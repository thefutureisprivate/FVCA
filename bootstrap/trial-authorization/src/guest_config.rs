//! The Host-owned Guest configuration record and its signed UKI binding.

use std::io;

use super::{digest, guest::SERVICE_GUEST_UUID, invalid, number};

pub const ARGUMENT: &str = "fvca.guest_config";
pub const ACTIVE: &str = "/run/fvca/guest-vm-settings";
pub const LIMIT: usize = 192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Resources {
    pub vcpus: u32,
    pub memory_mib: u32,
}

impl Resources {
    pub const DEFAULT: Self = Self {
        vcpus: 2,
        memory_mib: 2048,
    };
}

#[derive(Debug, Eq, PartialEq)]
pub struct Configuration {
    pub revision: u64,
    pub resources: Resources,
}

impl Configuration {
    pub fn parse(data: &str) -> io::Result<Self> {
        if data.len() > LIMIT {
            return Err(invalid(
                "Service Guest resource record exceeds its size bound",
            ));
        }
        let mut fields = data.split('\n');
        if fields.next() != Some("FVCA-SERVICE-GUEST-VM-2")
            || fields
                .next()
                .and_then(|field| field.strip_prefix("guest="))
                .map(str::as_bytes)
                != Some(SERVICE_GUEST_UUID.to_bytes())
        {
            return Err(invalid(
                "invalid Service Guest configuration schema or identity",
            ));
        }
        let field = |value: Option<&str>, prefix| number(value.unwrap_or_default(), prefix);
        let revision = field(fields.next(), "revision=")?;
        let vcpus = field(fields.next(), "vcpus=")?;
        let memory_mib = field(fields.next(), "memory_mib=")?;
        if fields.next() != Some("")
            || fields.next().is_some()
            || !(1..=4).contains(&vcpus)
            || !(1024..=4096).contains(&memory_mib)
            || !memory_mib.is_multiple_of(256)
        {
            return Err(invalid(
                "Service Guest resources exceed the approved machine profile",
            ));
        }
        Ok(Self {
            revision,
            resources: Resources {
                vcpus: vcpus as u32,
                memory_mib: memory_mib as u32,
            },
        })
    }

    pub fn require_binding(&self, binding: &Binding, sha256: &str) -> io::Result<()> {
        if self.revision != binding.revision || sha256 != binding.sha256 {
            return Err(invalid(
                "Service Guest configuration differs from its signed UKI binding",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Binding {
    pub revision: u64,
    pub sha256: String,
}

pub fn binding(cmdline: &str) -> io::Result<Option<Binding>> {
    let mut args = cmdline
        .split_ascii_whitespace()
        .filter(|arg| arg.split('=').next() == Some(ARGUMENT));
    let Some(arg) = args.next() else {
        return Ok(None);
    };
    let (revision, sha256) = arg
        .split_once('=')
        .and_then(|(_, value)| value.split_once(','))
        .filter(|_| args.next().is_none())
        .ok_or_else(|| invalid("invalid or duplicate Guest configuration UKI binding"))?;
    Ok(Some(Binding {
        revision: number(revision, "")?,
        sha256: digest(sha256, "")?.to_owned(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_the_exact_configuration_revision_and_digest() -> io::Result<()> {
        let sha256 = "a".repeat(64);
        let setting = format!("{ARGUMENT}=7,{sha256}");
        let selected = binding(&format!("ro {setting} quiet"))?.unwrap();
        let record = concat!(
            "FVCA-SERVICE-GUEST-VM-2\n",
            "guest=e629aa43-af11-47c6-aedc-a2dc47f1cc3a\n",
            "revision=7\nvcpus=3\nmemory_mib=2560\n",
        );
        let configuration = Configuration::parse(record)?;
        assert_eq!(configuration.resources.vcpus, 3);
        configuration.require_binding(&selected, &sha256)?;
        assert!(
            configuration
                .require_binding(&selected, &"b".repeat(64))
                .is_err()
        );
        assert!(
            Configuration::parse(&record.replace("revision=7", "revision=6"))?
                .require_binding(&selected, &sha256)
                .is_err()
        );
        for invalid in [
            format!("{setting} {setting}"),
            format!("{ARGUMENT}=0,{sha256}"),
            format!("{ARGUMENT}=07,{sha256}"),
            format!("{ARGUMENT}=7,{}", "A".repeat(64)),
            ARGUMENT.to_owned(),
        ] {
            assert!(binding(&invalid).is_err());
        }
        assert_eq!(binding("ro quiet")?, None);
        for (original, replacement) in [
            ("revision=7", "revision=0"),
            ("e629aa43", "00000000"),
            ("vcpus=3", "vcpus=5"),
            ("vcpus=3", "vcpus=03"),
            ("memory_mib=2560", "memory_mib=2561"),
            ("memory_mib=2560", "memory_mib=768"),
            ("memory_mib=2560", "memory_mib=4352"),
            ("memory_mib=2560", "memory_mib=2048\nnetwork=bridge"),
        ] {
            assert!(Configuration::parse(&record.replace(original, replacement)).is_err());
        }
        Ok(())
    }
}
