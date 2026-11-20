//! Collect a fixed Hypervisor boot quote and appraise it against a trusted reference.

use std::ffi::c_char;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::{
    rand,
    signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey},
};
use fvca_trial_authorization::guest::SERVICE_GUEST_UUID;
use rustix::fs::OFlags;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Result, invalid, state, tpm, valid_digest, valid_uuid};

// TPM SHA-256 PCR 0, 2, 4, 7, 9, 11, 12 and 13, in ascending order.
const PCRS: [u8; 3] = [0x95, 0x3a, 0];
// Offsets of the Secure Boot and UKI measurements in the reference array.
const REQUIRED_MEASUREMENTS: [usize; 2] = [3, 5];
const QUOTE_BYTES: usize = 256;
const CHALLENGE_SECONDS: u64 = 120;
const REFERENCE_SCHEMA: &str = "fvca-hypervisor-boot-reference-v1";
const EVIDENCE_SCHEMA: &str = "fvca-hypervisor-boot-quote-v1";

unsafe extern "C" {
    fn fvca_boot_quote(
        transport: *const c_char,
        nonce: *const u8,
        pcrs: *const u8,
        attest: *mut u8,
        capacity: usize,
        size: *mut usize,
        signature: *mut u8,
    ) -> u32;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    schema: String,
    host: String,
    release_manifest_sha256: String,
    ak_public: String,
    ak_qualified_name: String,
    sha256_pcrs: [String; 8],
}

impl Reference {
    fn load(path: &Path) -> Result<(Self, String)> {
        let data = state::read(path, 4096)?;
        let reference: Self = serde_json::from_slice(&data)?;
        if reference.schema != REFERENCE_SCHEMA
            || !valid_uuid(&reference.host)
            || reference.host.as_bytes() == SERVICE_GUEST_UUID.to_bytes()
            || !valid_digest(&reference.release_manifest_sha256)
            || decode::<65>(&reference.ak_public)?[0] != 4
            || decode::<34>(&reference.ak_qualified_name)?[..2] != [0, 0x0b]
            || !reference
                .sha256_pcrs
                .iter()
                .all(|value| valid_digest(value))
            || REQUIRED_MEASUREMENTS.iter().any(|&index| {
                reference.sha256_pcrs[index]
                    .bytes()
                    .all(|byte| byte == b'0')
            })
        {
            return Err(invalid("invalid trusted Hypervisor boot reference").into());
        }
        Ok((reference, hex::encode(Sha256::digest(data))))
    }

    fn verify(&self, challenge: &Challenge, evidence: Evidence) -> Result<()> {
        if evidence.schema != EVIDENCE_SCHEMA || evidence.quote.len() > QUOTE_BYTES * 2 {
            return Err(invalid("invalid Hypervisor boot evidence").into());
        }
        let signed = hex::decode(evidence.quote)?;
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, decode::<65>(&self.ak_public)?)
            .verify(&signed, &decode::<64>(&evidence.signature)?)
            .map_err(|_| invalid("boot quote signature does not match the enrolled AK"))?;
        let mut wire = signed.as_slice();
        if read::<6>(&mut wire)? != [0xff, 0x54, 0x43, 0x47, 0x80, 0x18] {
            return Err(invalid("expected TPM-generated quote evidence").into());
        }
        if read_tpm2b::<34>(&mut wire)? != decode::<34>(&self.ak_qualified_name)? {
            return Err(invalid("boot quote signer name differs from enrollment").into());
        }
        if read_tpm2b::<32>(&mut wire)? != decode::<32>(&challenge.nonce)? {
            return Err(invalid("boot quote does not answer the verifier's challenge").into());
        }
        // TPM clock information and firmwareVersion are signed metadata. Freshness
        // comes from the verifier's challenge and clock, without trusting either field.
        read::<25>(&mut wire)?;
        if read::<7>(&mut wire)? != [0, 0, 0, 1, 0, 0x0b, 3] || read::<3>(&mut wire)? != PCRS {
            return Err(invalid("unexpected boot quote PCR bank or selection").into());
        }
        let composite = read_tpm2b::<32>(&mut wire)?;
        let mut expected = Sha256::new();
        for value in &self.sha256_pcrs {
            expected.update(decode::<32>(value)?);
        }
        let expected: [u8; 32] = expected.finalize().into();
        if composite != expected || !wire.is_empty() {
            return Err(invalid("boot quote does not match the approved PCR measurements").into());
        }
        Ok(())
    }
}

fn read<const N: usize>(wire: &mut impl Read) -> io::Result<[u8; N]> {
    let mut value = [0; N];
    wire.read_exact(&mut value)?;
    Ok(value)
}

fn read_tpm2b<const N: usize>(wire: &mut &[u8]) -> io::Result<[u8; N]> {
    if usize::from(u16::from_be_bytes(read(wire)?)) != N {
        return Err(invalid("unexpected field width in the TPM quote"));
    }
    read(wire)
}

fn decode<const N: usize>(value: &str) -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes)
        .map_err(|_| invalid("invalid attestation hex field"))?;
    Ok(bytes)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    nonce: String,
    reference_sha256: String,
    issued: u64,
}

impl Challenge {
    fn require_current(&self) -> Result<()> {
        let now = unix_seconds()?;
        if now < self.issued || now - self.issued >= CHALLENGE_SECONDS {
            return Err(invalid("boot challenge is outside its validity interval").into());
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    schema: String,
    quote: String,
    signature: String,
}

fn unix_seconds() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn state_parent(path: &Path) -> io::Result<&Path> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    state::directory(parent)?;
    Ok(parent)
}

pub fn issue(reference: &Path, destination: &Path) -> Result<()> {
    let (_, reference_sha256) = Reference::load(reference)?;
    let parent = state_parent(destination)?;
    let mut nonce = [0; 32];
    rand::fill(&mut nonce).map_err(|_| io::Error::other("could not generate a boot challenge"))?;
    let challenge = Challenge {
        nonce: hex::encode(nonce),
        reference_sha256,
        issued: unix_seconds()?,
    };
    let mut record = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(&mut record, &challenge)?;
    record.as_file().sync_all()?;
    record.persist_noclobber(destination)?;
    File::open(parent)?.sync_all()?;
    println!("{}", challenge.nonce);
    Ok(())
}

pub fn collect(nonce: &str) -> Result<()> {
    let nonce = decode::<32>(nonce)?;
    let mut quote = [0; QUOTE_BYTES];
    let mut size = 0;
    let mut signature = [0; 64];
    // All buffers stay live for the call. The bridge receives the capacity and
    // only writes the used length and the fixed-width ECDSA signature on success.
    let status = tpm::with_transport(|transport| unsafe {
        fvca_boot_quote(
            transport.as_ptr(),
            nonce.as_ptr(),
            PCRS.as_ptr(),
            quote.as_mut_ptr(),
            quote.len(),
            &mut size,
            signature.as_mut_ptr(),
        )
    })?;
    if status != 0 || !(1..=QUOTE_BYTES).contains(&size) {
        return Err(io::Error::other(format!(
            "TPM could not collect a boot quote (0x{status:08x})"
        ))
        .into());
    }
    println!(
        "{}",
        serde_json::to_string(&Evidence {
            schema: EVIDENCE_SCHEMA.into(),
            quote: hex::encode(&quote[..size]),
            signature: hex::encode(signature)
        })?
    );
    Ok(())
}

pub fn collect_from_stdin() -> Result<()> {
    let mut input = io::stdin().lock();
    let nonce = read::<64>(&mut input)?;
    if read::<1>(&mut input)? != *b"\n" {
        return Err(invalid("expected one newline-terminated boot challenge").into());
    }
    collect(std::str::from_utf8(&nonce)?)
}

pub fn appraise(reference: &Path, pending: &Path, evidence: &Path) -> Result<()> {
    let (reference, reference_sha256) = Reference::load(reference)?;
    state_parent(pending)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY).bits() as i32)
        .open(pending)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(invalid("expected private verifier challenge state").into());
    }
    file.try_lock().map_err(io::Error::other)?;
    let mut data = Vec::new();
    (&mut file).take(1025).read_to_end(&mut data)?;
    if data.is_empty() || data.len() > 1024 {
        return Err(invalid("boot challenge was already consumed or its record is invalid").into());
    }
    let challenge: Challenge = serde_json::from_slice(&data)?;
    if challenge.reference_sha256 != reference_sha256 {
        return Err(invalid("boot challenge was issued for a different trusted reference").into());
    }
    challenge.require_current()?;
    reference.verify(
        &challenge,
        serde_json::from_slice(&state::read(evidence, 2048)?)?,
    )?;
    challenge.require_current()?;
    // Keep the inode and remove its authority under the exclusive lock. Emit
    // the verdict only after the one-use challenge is durably consumed.
    file.set_len(0)?;
    file.sync_all()?;
    println!(
        "{}",
        serde_json::json!({
            "result": "measured-boot-matches-reference", "role": "hypervisor", "host": reference.host,
            "release_manifest_sha256": reference.release_manifest_sha256,
        })
    );
    Ok(())
}
