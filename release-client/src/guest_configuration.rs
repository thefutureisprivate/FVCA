//! Read the Host's boot-selected configuration independently of release state.

use std::io::{self, Read, Write};
use std::path::Path;

use fvca_trial_authorization::{
    guest,
    guest_config::{self, ACTIVE, Binding, Configuration, LIMIT, Resources},
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

pub(super) fn running() -> Result<(Option<Binding>, Resources)> {
    let launch = state::read(Path::new(guest::SELECTION), guest::ENVELOPE_LIMIT as u64)?;
    guest::parse(std::str::from_utf8(&launch)?)?;
    let cmdline = state::read(Path::new("/proc/cmdline"), 32 * 1024)?;
    let binding = guest_config::binding(std::str::from_utf8(&cmdline)?)?;
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
    let resources = accept(binding.as_ref(), payload.as_deref())?;
    Ok((binding, resources))
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
    let (binding, resources) = running()?;
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
