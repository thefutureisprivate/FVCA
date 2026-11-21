//! Read exact, independently signed permit revocations on the selected Guest data pool.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use base64::{Engine, engine::general_purpose::STANDARD};
use openssl::sha::sha256;
use openssl::x509::X509;
use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags, mkdirat, openat, renameat_with, unlinkat};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};

use crate::{
    Result, SIGNATURE_LIMIT, Trust, digest, invalid, is_digest, revocation_id, verify_signature,
};

pub const NOTICE_LIMIT: u64 = 64 * 1024;
const STORE: &str = "workload-updates";
const NOTICES: &str = "permit-revocations";
const TEMPORARY: &str = ".channel-revocation.new";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PermitIdentity {
    pub(crate) guest: String,
    pub(crate) service: String,
    pub(crate) id: String,
    pub(crate) permit: String,
    pub(crate) authority: String,
    pub(crate) issued_at: u64,
    pub(crate) expires: u64,
}

impl PermitIdentity {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn expires(&self) -> u64 {
        self.expires
    }
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    BlockNewStarts,
    Stop,
}

impl Action {
    fn filename(self, permit: &str) -> String {
        let suffix = match self {
            Self::BlockNewStarts => "block",
            Self::Stop => "stop",
        };
        format!("{permit}.{suffix}.json")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    record: String,
    signature: String,
    authority: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revocation {
    schema: String,
    guest: String,
    service: String,
    permit_id: String,
    permit: String,
    action: Action,
    revoked_at: u64,
    reason: String,
}

pub(crate) struct Ledger {
    pool: File,
    device: u64,
}

impl Ledger {
    pub(crate) fn open(pool: &Path, device: u64) -> Result<Self> {
        let pool = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(pool)?;
        check_directory(&pool, device)?;
        Ok(Self { pool, device })
    }

    fn check(&self, permit: &PermitIdentity, trust: &Trust) -> Result<Option<Action>> {
        let Some(store) = self.directory(&self.pool, STORE)? else {
            return Ok(None);
        };
        let Some(directory) = self.directory(&store, NOTICES)? else {
            return Ok(None);
        };
        for action in [Action::Stop, Action::BlockNewStarts] {
            let filename = action.filename(
                permit
                    .permit
                    .strip_prefix("sha256:")
                    .expect("validated permit digest"),
            );
            let Some(bytes) = self.read_notice(&directory, &filename)? else {
                continue;
            };
            verify_envelope(&bytes, trust)?.check_permit(permit, action)?;
            return Ok(Some(action));
        }
        Ok(None)
    }

    fn read_notice(&self, directory: &File, name: &str) -> Result<Option<Vec<u8>>> {
        let Some(file) = open_member(directory, name, OFlags::NONBLOCK | OFlags::NOCTTY)? else {
            return Ok(None);
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.dev() != self.device
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o400
        {
            return Err(invalid(
                "permit revocation must be a root-owned 0400 file on the selected pool",
            ));
        }
        let mut bytes = Vec::new();
        file.take(NOTICE_LIMIT + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > NOTICE_LIMIT {
            return Err(invalid("permit revocation envelope exceeds its bound"));
        }
        Ok(Some(bytes))
    }

    fn retain(&self, filename: &str, bytes: &[u8]) -> Result<bool> {
        let store = self
            .directory(&self.pool, STORE)?
            .ok_or_else(|| invalid("the authenticated workload store is unavailable"))?;
        match mkdirat(&store, NOTICES, Mode::from_bits_truncate(0o700)) {
            Ok(()) | Err(Errno::EXIST) => store.sync_all()?,
            Err(error) => return Err(error.into()),
        }
        let directory = self
            .directory(&store, NOTICES)?
            .ok_or_else(|| invalid("the permit revocation directory disappeared"))?;
        // The channel caller holds the workload lifecycle lease for publication.
        remove_temporary(&directory)?;
        if let Some(existing) = self.read_notice(&directory, filename)? {
            if existing != bytes {
                return Err(invalid(
                    "conflicting content for an immutable permit revocation notice",
                ));
            }
            directory.sync_all()?;
            return Ok(false);
        }

        let result = (|| -> Result<()> {
            let descriptor = openat(
                &directory,
                TEMPORARY,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_bits_truncate(0o400),
            )?;
            let mut file = File::from(descriptor);
            file.write_all(bytes)?;
            file.sync_all()?;
            renameat_with(
                &directory,
                TEMPORARY,
                &directory,
                filename,
                RenameFlags::NOREPLACE,
            )?;
            directory.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            remove_temporary(&directory)?;
        }
        result.map(|()| true)
    }

    fn clear_partial(&self) -> Result<()> {
        if let Some(store) = self.directory(&self.pool, STORE)?
            && let Some(directory) = self.directory(&store, NOTICES)?
        {
            remove_temporary(&directory)?;
        }
        Ok(())
    }

    fn directory(&self, parent: &File, name: &str) -> Result<Option<File>> {
        let directory = open_member(parent, name, OFlags::DIRECTORY)?;
        if let Some(opened) = &directory {
            check_directory(opened, self.device)?;
        }
        Ok(directory)
    }
}

fn remove_temporary(directory: &File) -> io::Result<()> {
    match unlinkat(directory, TEMPORARY, AtFlags::empty()) {
        Ok(()) => directory.sync_all(),
        Err(Errno::NOENT) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn open_member(directory: &File, name: &str, flags: OFlags) -> io::Result<Option<File>> {
    match openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | flags,
        Mode::empty(),
    ) {
        Ok(file) => Ok(Some(File::from(file))),
        Err(Errno::NOENT) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn check_directory(file: &File, device: u64) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_dir()
        || metadata.dev() != device
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(invalid(
            "permit revocation directory is outside the private selected Guest pool",
        ));
    }
    Ok(())
}

fn decode(value: &str) -> Result<Vec<u8>> {
    let bytes = STANDARD.decode(value)?;
    if bytes.is_empty() || bytes.len() as u64 > SIGNATURE_LIMIT {
        return Err(invalid("permit revocation evidence is empty or oversized"));
    }
    Ok(bytes)
}

fn verify_envelope(bytes: &[u8], trust: &Trust) -> Result<Revocation> {
    if bytes.len() as u64 > NOTICE_LIMIT {
        return Err(invalid("permit revocation envelope exceeds its bound"));
    }
    let envelope: Envelope = serde_json::from_slice(bytes)?;
    let certificate = trust.permit_authority(&decode(&envelope.authority)?)?;
    let record = decode(&envelope.record)?;
    verify_signature(&record, &decode(&envelope.signature)?, &certificate)?;
    let record: Revocation = serde_json::from_slice(&record)?;
    if record.schema != "fvca-workload-permit-revocation-v1"
        || !trust.identifies(&record.guest, &record.service)
        || !revocation_id(&record.permit_id)
        || !is_digest(&record.permit)
        || !(1..=i64::MAX as u64).contains(&record.revoked_at)
        || record.reason.is_empty()
        || record.reason.chars().count() > 512
        || record.reason.trim() != record.reason
        || record.reason.chars().any(char::is_control)
    {
        return Err(invalid(
            "signed revocation does not bind the enrolled Guest and service",
        ));
    }
    Ok(record)
}

impl Revocation {
    fn check_permit(&self, permit: &PermitIdentity, action: Action) -> Result<()> {
        if self.permit_id != permit.id
            || self.permit != permit.permit
            || self.action != action
            || self.revoked_at < permit.issued_at
        {
            return Err(invalid(
                "signed revocation does not bind the enrolled permit and requested action",
            ));
        }
        Ok(())
    }
}

impl Trust {
    pub fn accepts_permit_notices(&self) -> bool {
        self.scope.unsigned_permit_authority.is_some()
    }

    /// Clear an interrupted publication while holding the workload lifecycle lease.
    pub fn clear_partial_permit_notice(&self) -> Result<()> {
        if let Some(ledger) = &self.revocations {
            ledger.clear_partial()?;
        }
        Ok(())
    }

    pub fn verify_permit_notice(&self, filename: &str, bytes: &[u8]) -> Result<()> {
        let record = verify_envelope(bytes, self)?;
        let permit = record
            .permit
            .strip_prefix("sha256:")
            .expect("validated permit digest");
        if filename != record.action.filename(permit) {
            return Err(invalid(
                "revocation target name differs from its signed permit and action",
            ));
        }
        Ok(())
    }

    /// Publish authenticated bytes after acquiring the workload lifecycle lease.
    pub fn retain_permit_notice(&self, filename: &str, bytes: &[u8]) -> Result<bool> {
        self.verify_permit_notice(filename, bytes)?;
        self.revocations
            .as_ref()
            .ok_or_else(|| {
                invalid("permit revocation publication requires the selected Guest pool")
            })?
            .retain(filename, bytes)
    }

    /// Attach the authoritative local revocation store to verification on an appliance.
    pub fn with_permit_revocations(mut self, pool: &Path, device: u64) -> Result<Self> {
        if self.scope.unsigned_permit_authority.is_some() {
            self.revocations = Some(Ledger::open(pool, device)?);
        }
        Ok(self)
    }

    pub fn permit_revocation(&self, permit: &PermitIdentity) -> Result<Option<Action>> {
        if permit.guest != self.scope.guest
            || permit.service != self.scope.service
            || !revocation_id(&permit.id)
            || !is_digest(&permit.permit)
            || permit.issued_at == 0
            || permit.issued_at >= permit.expires
            || permit.expires > i64::MAX as u64
        {
            return Err(invalid(
                "permit identity differs from the authenticated Guest scope",
            ));
        }
        self.permit_authority(&decode(&permit.authority)?)?;
        if let Some(ledger) = &self.revocations
            && let Some(action) = ledger.check(permit, self)?
        {
            return Ok(Some(action));
        }
        Ok(self
            .scope
            .revoked
            .contains(&permit.id)
            .then_some(Action::BlockNewStarts))
    }

    pub(crate) fn permit_authority(&self, der: &[u8]) -> Result<X509> {
        let certificate = X509::from_der(der)?;
        let key = certificate.public_key()?;
        if self.scope.unsigned_permit_authority.as_deref() != Some(digest(&sha256(der)).as_str())
            || certificate.to_der()? != der
            || self.deployment.public_key()?.public_eq(&key)
            || self.workload.public_key()?.public_eq(&key)
        {
            return Err(invalid(
                "unsigned permit requires a distinct authority key matching the Guest enrollment",
            ));
        }
        Ok(certificate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        bn::{BigNum, MsbOption},
        cms::{CMSOptions, CmsContentInfo},
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::{PKey, Private},
        x509::X509Name,
    };
    use serde_json::{Value, json};

    fn signer() -> Result<(X509, PKey<Private>)> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let mut subject = X509Name::builder()?;
        subject.append_entry_by_text("CN", "FVCA revocation test")?;
        let subject = subject.build();
        let mut certificate = X509::builder()?;
        certificate.set_version(2)?;
        let mut serial = BigNum::new()?;
        serial.rand(128, MsbOption::ONE, false)?;
        let serial = serial.to_asn1_integer()?;
        certificate.set_serial_number(&serial)?;
        certificate.set_subject_name(&subject)?;
        certificate.set_issuer_name(&subject)?;
        certificate.set_pubkey(&key)?;
        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(1)?;
        certificate.set_not_before(&not_before)?;
        certificate.set_not_after(&not_after)?;
        certificate.sign(&key, MessageDigest::sha256())?;
        Ok((certificate.build(), key))
    }

    fn envelope(value: &Value, certificate: &X509, key: &PKey<Private>) -> Result<Vec<u8>> {
        let record = serde_json::to_vec(value)?;
        let signature = CmsContentInfo::sign(
            Some(certificate),
            Some(key),
            None,
            Some(&record),
            CMSOptions::BINARY
                | CMSOptions::DETACHED
                | CMSOptions::NOATTR
                | CMSOptions::CMS_NOCERTS,
        )?
        .to_der()?;
        Ok(serde_json::to_vec(
            &json!({"record": STANDARD.encode(record), "signature": STANDARD.encode(signature),
                    "authority": STANDARD.encode(certificate.to_der()?)}),
        )?)
    }

    #[test]
    fn authenticates_stop_and_binds_the_precise_action_and_permit() -> Result<()> {
        let (certificate, key) = signer()?;
        let permit = PermitIdentity {
            guest: "guest-one".to_owned(),
            service: "mail".to_owned(),
            id: "0098e4f4-bcf2-4140-b0e5-232351be4e76".to_owned(),
            permit: digest(&sha256(b"test permit")),
            authority: STANDARD.encode(certificate.to_der()?),
            issued_at: 30,
            expires: 40,
        };
        let statement = json!({"schema":"fvca-workload-permit-revocation-v1", "guest":permit.guest, "service":permit.service,
            "permit_id": permit.id, "permit":permit.permit, "action":"stop", "revoked_at":90, "reason":"Fixture stop notice"});
        let trust = Trust::new(
            crate::Scope {
                guest: permit.guest.clone(),
                service: permit.service.clone(),
                source_policy: digest(&sha256(b"scope")),
                minimum_epoch: 1,
                revoked: vec![],
                unsigned_permit_authority: Some(digest(&sha256(&certificate.to_der()?))),
            },
            signer()?.0,
            signer()?.0,
        )?;
        let exact = envelope(&statement, &certificate, &key)?;
        verify_envelope(&exact, &trust)?.check_permit(&permit, Action::Stop)?;
        assert!(
            verify_envelope(&exact, &trust)?
                .check_permit(&permit, Action::BlockNewStarts)
                .is_err()
        );
        let (other, other_key) = signer()?;
        assert!(verify_envelope(&envelope(&statement, &other, &other_key)?, &trust).is_err());
        for (field, value) in [
            ("guest", json!("guest-two")),
            ("permit", json!(digest(&sha256(b"other permit")))),
            ("permit_id", json!("33d43135-a656-406c-aecb-e429c234ec86")),
            ("revoked_at", json!(29)),
        ] {
            let mut changed = statement.clone();
            changed[field] = value;
            let signed = envelope(&changed, &certificate, &key)?;
            assert!(
                verify_envelope(&signed, &trust)
                    .and_then(|receipt| receipt.check_permit(&permit, Action::Stop))
                    .is_err(),
                "{field}"
            );
        }
        Ok(())
    }
}
