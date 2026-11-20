//! Report boot-selected settings and verify separately authorized changes.

use std::io::{self, Read, Write};
use std::path::Path;

use fvca_trial_authorization::{
    guest,
    guest_config::{self, ACTIVE, Binding, Change, Configuration, LIMIT, Policy, Resources},
};
use serde::Serialize;

use crate::{Result, channel::digest, handoff, invalid, state};

fn accept(binding: Option<&Binding>, payload: Option<&[u8]>) -> Result<Resources> {
    match (binding, payload) {
        (None, None) => Ok(Resources::DEFAULT),
        (Some(binding), Some(payload)) => {
            let configuration = Configuration::parse(std::str::from_utf8(payload)?)?;
            configuration.require_binding(binding, &digest(payload))?;
            Ok(configuration.resources)
        }
        _ => Err(invalid("the Host lacks a matching boot-selected Guest configuration").into()),
    }
}

pub(super) fn running() -> Result<(Policy, Resources)> {
    let launch = state::read(Path::new(guest::SELECTION), guest::ENVELOPE_LIMIT as u64)?;
    guest::parse(std::str::from_utf8(&launch)?)?;
    let cmdline = state::read(Path::new("/proc/cmdline"), 32 * 1024)?;
    let policy = Policy::parse(std::str::from_utf8(&cmdline)?)?;
    let payload = match state::open_regular(Path::new(ACTIVE)) {
        Ok(file) => {
            handoff::private_file(&file)?;
            let mut data = Vec::new();
            file.take((LIMIT + 1) as u64).read_to_end(&mut data)?;
            Some(data)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let resources = accept(policy.binding.as_ref(), payload.as_deref())?;
    Ok((policy, resources))
}

pub(crate) struct Grant {
    pub authority: [u8; 32],
    pub change: Change,
    pub packet: Vec<u8>,
}

pub(super) fn authorize(packet: Vec<u8>, trial: &[u8], authority: [u8; 32]) -> Result<Grant> {
    let (signature, body) = guest_config::signed_change(&packet)?;
    crate::channel::verify(
        &authority,
        body,
        signature,
        "invalid independent Guest configuration signature",
    )?;
    let change = Change::parse(body)?;
    change.require_trial(&digest(trial))?;
    Ok(Grant {
        authority,
        change,
        packet,
    })
}

#[derive(Serialize)]
struct Status<'a> {
    schema: &'static str,
    guest: &'static str,
    boot_configuration_revision: Option<u64>,
    boot_configuration_sha256: Option<&'a str>,
    vcpus: u32,
    memory_mib: u32,
}

pub(super) fn report() -> Result<()> {
    let (Policy { binding, .. }, resources) = running()?;
    let mut output = io::stdout().lock();
    serde_json::to_writer(
        &mut output,
        &Status {
            schema: "fvca-guest-configuration-status-v1",
            guest: guest::SERVICE_GUEST_UUID.to_str()?,
            boot_configuration_revision: binding.as_ref().map(|value| value.revision),
            boot_configuration_sha256: binding.as_ref().map(|value| value.sha256.as_str()),
            vcpus: resources.vcpus,
            memory_mib: resources.memory_mib,
        },
    )?;
    writeln!(output)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };

    #[test]
    fn configuration_approval_authenticates_the_exact_trial_and_next_revision() -> Result<()> {
        let key = || -> Result<Ed25519KeyPair> {
            let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())?;
            Ok(Ed25519KeyPair::from_pkcs8(document.as_ref())?)
        };
        let signer = key()?;
        let expected = signer.public_key().as_ref().try_into()?;
        let wrong = key()?.public_key().as_ref().try_into()?;
        let trial = b"exact signed standing trial";
        let body = format!(
            "FVCA-GUEST-CONFIGURATION-CHANGE-1\nguest={}\ntrial_sha256={}\nprevious=default\nnext=1,{}\n",
            guest::SERVICE_GUEST_UUID.to_str()?,
            digest(trial),
            "9".repeat(64)
        );
        let mut packet = signer.sign(body.as_bytes()).as_ref().to_vec();
        packet.extend_from_slice(body.as_bytes());
        let grant = authorize(packet.clone(), trial, expected)?;
        assert_eq!(grant.change.previous, None);
        assert_eq!(grant.change.next.revision, 1);
        assert!(authorize(packet.clone(), trial, wrong).is_err());
        assert!(authorize(packet.clone(), b"different standing trial", expected).is_err());
        let last = packet.len() - 2;
        packet[last] = b'8';
        assert!(authorize(packet, trial, expected).is_err());
        Ok(())
    }

    #[test]
    fn running_configuration_requires_the_initramfs_record_and_signed_binding() -> Result<()> {
        let record = concat!(
            "FVCA-SERVICE-GUEST-VM-2\n",
            "guest=e629aa43-af11-47c6-aedc-a2dc47f1cc3a\n",
            "revision=6\nvcpus=3\nmemory_mib=2560\n",
        );
        let binding = Binding {
            revision: 6,
            sha256: digest(record.as_bytes()),
        };
        assert_eq!(accept(Some(&binding), Some(record.as_bytes()))?.vcpus, 3);
        assert_eq!(accept(None, None)?, Resources::DEFAULT);
        assert!(accept(Some(&binding), None).is_err());
        assert!(accept(None, Some(record.as_bytes())).is_err());
        let changed = record.replace("vcpus=3", "vcpus=4");
        assert!(accept(Some(&binding), Some(changed.as_bytes())).is_err());
        Ok(())
    }
}
