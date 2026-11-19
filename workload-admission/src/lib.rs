#![forbid(unsafe_code)]

mod image;
mod launch;
mod records;

use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use openssl::cms::{CMSOptions, CmsContentInfo};
use openssl::hash::{Hasher, MessageDigest};
use openssl::sha::sha256;
use openssl::stack::Stack;
use openssl::x509::X509;

pub use image::{Image, Region};
use records::{Authorization, Blob, Deployment, Derivation};
pub use records::{IdMap, Launch, Limits, Scope};

const RECORD_LIMIT: u64 = 4 * 1024 * 1024;
const SIGNATURE_LIMIT: u64 = 16 * 1024;
const ARTIFACT_LIMIT: u64 = 660 * 1024 * 1024;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub struct Trust {
    scope: Scope,
    deployment: X509,
    workload: X509,
}

impl Trust {
    /// The caller provides the policy and direct signer pins from verified Guest configuration.
    pub fn new(scope: Scope, deployment: X509, workload: X509) -> Result<Self> {
        if !name(&scope.guest)
            || !name(&scope.service)
            || !is_digest(&scope.source_policy)
            || !(1..=i64::MAX as u64).contains(&scope.minimum_epoch)
            || !scope.revoked.iter().all(|id| revocation_id(id))
        {
            return Err(invalid("invalid trusted workload policy"));
        }
        let workload_key = workload.public_key()?;
        if deployment.public_key()?.public_eq(&workload_key) {
            return Err(invalid(
                "deployment and workload authorization share a signer key",
            ));
        }
        Ok(Self {
            scope,
            deployment,
            workload,
        })
    }
}

pub struct VerifiedWorkload {
    deployment: Deployment,
    launch: Launch,
    authorization: Authorization,
    artifact: File,
    image: Image,
}

impl VerifiedWorkload {
    pub fn service(&self) -> &str {
        &self.deployment.service
    }

    pub fn digest(&self) -> &str {
        &self.authorization.artifact.digest
    }

    pub fn verity_root_hash(&self) -> &str {
        &self.authorization.verity_root_hash
    }

    pub fn launch(&self) -> &Launch {
        &self.launch
    }

    pub fn limits(&self) -> &Limits {
        &self.deployment.limits
    }

    pub fn id_map(&self) -> &IdMap {
        &self.deployment.id_map
    }

    /// Continue with the file descriptor that was hashed, without reopening the path.
    pub fn into_artifact(self) -> (File, Image) {
        (self.artifact, self.image)
    }
}

fn invalid(reason: &str) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidData, reason).into()
}

fn name(value: &str) -> bool {
    let mut bytes = value.bytes();
    value.len() <= 64
        && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn root_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(lower_hex)
}

fn is_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(root_hash)
}

fn revocation_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => lower_hex(byte),
        })
}

fn digest(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in bytes {
        write!(value, "{byte:02x}").expect("writing into a String cannot fail");
    }
    value
}

fn open_regular(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o022 != 0 || metadata.nlink() != 1 {
        return Err(invalid("expected a private regular workload input"));
    }
    Ok(file)
}

pub fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut content = Vec::new();
    open_regular(path)?
        .take(limit + 1)
        .read_to_end(&mut content)?;
    if content.is_empty() || content.len() as u64 > limit {
        return Err(invalid("workload input is empty or exceeds its size limit"));
    }
    Ok(content)
}

fn verify_signature(content: &[u8], signature: &[u8], certificate: &X509) -> Result<()> {
    let mut cms = CmsContentInfo::from_der(signature)?;
    if cms.to_der()? != signature {
        return Err(invalid("workload signature is not canonical DER"));
    }
    let mut pins = Stack::new()?;
    pins.push(certificate.clone())?;
    let mut verified = Vec::new();
    // Trust only the explicitly pinned signer and verify the exact binary content.
    cms.verify(
        Some(&pins),
        None,
        Some(content),
        Some(&mut verified),
        CMSOptions::BINARY | CMSOptions::NOINTERN | CMSOptions::NO_SIGNER_CERT_VERIFY,
    )?;
    if verified != content {
        return Err(invalid("CMS verified different workload content"));
    }
    Ok(())
}

fn verified_record(directory: &Path, filename: &str, certificate: &X509) -> Result<Vec<u8>> {
    let content = read_bounded(&directory.join(format!("{filename}.json")), RECORD_LIMIT)?;
    let signature = read_bounded(&directory.join(format!("{filename}.p7s")), SIGNATURE_LIMIT)?;
    verify_signature(&content, &signature, certificate)?;
    Ok(content)
}

fn bound_record(directory: &Path, filename: &str, expected: &str) -> Result<Vec<u8>> {
    let content = read_bounded(&directory.join(filename), RECORD_LIMIT)?;
    if digest(&sha256(&content)) != expected {
        return Err(invalid(&format!(
            "{filename} does not match the signed workload digest"
        )));
    }
    Ok(content)
}

fn check_time(deployment: &Deployment) -> Result<()> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if !(deployment.valid_from..deployment.expires).contains(&now)
        || deployment.expires > i64::MAX as u64
    {
        return Err(invalid("deployment is outside its validity period"));
    }
    Ok(())
}

fn check_deployment(value: &Deployment, scope: &Scope) -> Result<()> {
    if value.schema != "fvca-workload-deployment-v1"
        || value.guest != scope.guest
        || value.service != scope.service
        || ![&value.source_index, &value.manifest, &value.launch]
            .iter()
            .all(|field| is_digest(field))
        || !revocation_id(&value.revocation_id)
        || !(scope.minimum_epoch..=i64::MAX as u64).contains(&value.security_epoch)
        || scope.revoked.contains(&value.revocation_id)
    {
        return Err(invalid(
            "deployment does not match the trusted scope or freshness policy",
        ));
    }
    let limits = &value.limits;
    let mapping = &value.id_map;
    if !(32 * 1024 * 1024..=64 * 1024 * 1024 * 1024).contains(&limits.memory_bytes)
        || !(1..=6400).contains(&limits.cpu_percent)
        || !(1..=4096).contains(&limits.pids)
        || mapping.size != 65536
        || ![mapping.uid_base, mapping.gid_base]
            .iter()
            .all(|base| (65536..u32::MAX - 65535).contains(base))
    {
        return Err(invalid(
            "deployment resource limits or subordinate identity map are invalid",
        ));
    }
    check_time(value)
}

fn check_derivation(
    value: &Derivation,
    approval: &Deployment,
    authorization: &Authorization,
    scope: &Scope,
) -> Result<()> {
    if value.schema != "fvca-workload-derivation-v1"
        || value.service != approval.service
        || value.source_policy != scope.source_policy
        || value.provenance != approval.provenance
        || !is_digest(&value.worker_image)
        || value.source.index != approval.source_index
        || value.source.repository.is_empty()
        || value.source.certificate_identity.is_empty()
        || value.source.certificate_issuer.is_empty()
        || value.platform.os != "linux"
        || value.platform.architecture != "amd64"
        || value.manifest.digest != approval.manifest
        || value.manifest.media_type != "application/vnd.oci.image.manifest.v1+json"
        || !(1..=RECORD_LIMIT).contains(&value.manifest.size)
        || value.launch != approval.launch
        || value.verity_root_hash != authorization.verity_root_hash
        || ![&value.root, &value.verity_tree]
            .into_iter()
            .all(|blob| is_digest(&blob.digest) && blob.size > 0 && blob.size.is_multiple_of(4096))
        || value.root.size.saturating_add(value.verity_tree.size) >= authorization.artifact.size
    {
        return Err(invalid(
            "derivation does not match the published source, launch, or image",
        ));
    }
    Ok(())
}

fn digest_stream(mut input: impl Read, size: u64) -> Result<String> {
    let mut hasher = Hasher::new(MessageDigest::sha256())?;
    let mut buffer = vec![0; 1024 * 1024];
    let mut remaining = size;
    while remaining > 0 {
        let count = remaining.min(buffer.len() as u64) as usize;
        input.read_exact(&mut buffer[..count])?;
        hasher.update(&buffer[..count])?;
        remaining -= count as u64;
    }
    Ok(digest(&hasher.finish()?))
}

fn verify_artifact(path: &Path, expected: &Blob) -> Result<File> {
    let mut artifact = open_regular(path)?;
    let before = artifact.metadata()?;
    if before.len() != expected.size || !(1..=ARTIFACT_LIMIT).contains(&expected.size) {
        return Err(invalid(
            "workload artifact size does not match the authorization",
        ));
    }
    let actual = digest_stream(&mut artifact, expected.size)?;
    let after = artifact.metadata()?;
    if before.len() != after.len()
        || before.modified()? != after.modified()?
        || (before.ctime(), before.ctime_nsec()) != (after.ctime(), after.ctime_nsec())
        || actual != expected.digest
    {
        return Err(invalid("workload artifact does not match the signed bytes"));
    }
    artifact.rewind()?;
    Ok(artifact)
}

/// Verify signed workload evidence and the exact image bytes before any image parser or mount.
/// The caller owns the staging directory and must prevent concurrent writers until activation.
pub fn verify(directory: &Path, trust: &Trust) -> Result<VerifiedWorkload> {
    let deployment_bytes = verified_record(directory, "deployment", &trust.deployment)?;
    let deployment = serde_json::from_slice(&deployment_bytes)?;
    check_deployment(&deployment, &trust.scope)?;

    let authorization_bytes = verified_record(directory, "authorization", &trust.workload)?;
    let authorization: Authorization = serde_json::from_slice(&authorization_bytes)?;
    if authorization.schema != "fvca-workload-authorization-v1"
        || authorization.deployment != digest(&sha256(&deployment_bytes))
        || authorization.deployment_certificate != digest(&sha256(&trust.deployment.to_der()?))
        || authorization.workload_certificate != digest(&sha256(&trust.workload.to_der()?))
        || !root_hash(&authorization.verity_root_hash)
        || !is_digest(&authorization.artifact.digest)
    {
        return Err(invalid(
            "workload authorization does not bind these signer pins and deployment",
        ));
    }

    let derivation = serde_json::from_slice(&bound_record(
        directory,
        "derivation.json",
        &authorization.derivation,
    )?)?;
    check_derivation(&derivation, &deployment, &authorization, &trust.scope)?;
    bound_record(
        directory,
        "publisher-proof.json",
        &authorization.publisher_proof,
    )?;
    let launch: Launch =
        serde_json::from_slice(&bound_record(directory, "launch.json", &deployment.launch)?)?;
    launch.validate()?;
    let mut artifact = verify_artifact(&directory.join("workload.raw"), &authorization.artifact)?;
    let image = image::verify_image(&mut artifact, &authorization, &derivation, &trust.workload)?;
    check_time(&deployment)?;
    Ok(VerifiedWorkload {
        deployment,
        launch,
        authorization,
        artifact,
        image,
    })
}
