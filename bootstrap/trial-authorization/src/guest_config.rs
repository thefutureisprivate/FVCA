//! The Host-owned Guest configuration record and its signed UKI binding.

use std::io;

use super::{digest, guest::SERVICE_GUEST_UUID, invalid, number};

pub const ARGUMENT: &str = "fvca.guest_config";
pub const AUTHORITY_ARGUMENT: &str = "fvca.guest_config_key";
pub const AUTHORITY_FILE: &str = "/usr/lib/fvca/guest-configuration-key";
pub const CHANGE_SUFFIX: &str = ".guest-configuration-change";
pub const ACTIVE: &str = "/run/fvca/guest-vm-settings";
pub const LIMIT: usize = 192;
pub const CHANGE_LIMIT: usize = 512;

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

    fn permits(vcpus: u64, memory_mib: u64) -> bool {
        (1..=4).contains(&vcpus)
            && (1024..=4096).contains(&memory_mib)
            && memory_mib.is_multiple_of(256)
    }

    pub fn require_capacity(self, cpus: usize, memory_kib: u64) -> io::Result<()> {
        const HOST_RESERVE_MIB: u64 = 1024;
        const QEMU_RESERVE_MIB: u64 = 512;
        let required = (u64::from(self.memory_mib) + HOST_RESERVE_MIB + QEMU_RESERVE_MIB) * 1024;
        if cpus < self.vcpus as usize || memory_kib < required {
            return Err(invalid(
                "insufficient Host CPU or memory headroom for the Service Guest",
            ));
        }
        Ok(())
    }
}

pub fn host_memory_kib(meminfo: &str, field: &str) -> io::Result<u64> {
    meminfo
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .and_then(|value| value.trim_ascii().strip_suffix(" kB"))
        .map(str::trim_ascii)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| invalid("Host memory capacity is unavailable"))
}

#[derive(Debug, Eq, PartialEq)]
pub struct Configuration {
    pub revision: u64,
    pub resources: Resources,
}

impl Configuration {
    pub fn from_resources(revision: u64, resources: Resources) -> io::Result<Self> {
        if revision == 0 || !Resources::permits(resources.vcpus.into(), resources.memory_mib.into())
        {
            return Err(invalid(
                "invalid Guest configuration revision or machine resources",
            ));
        }
        Ok(Self {
            revision,
            resources,
        })
    }

    pub fn record(&self) -> io::Result<String> {
        Ok(format!(
            "FVCA-SERVICE-GUEST-VM-2\nguest={}\nrevision={}\nvcpus={}\nmemory_mib={}\n",
            SERVICE_GUEST_UUID.to_str().map_err(io::Error::other)?,
            self.revision,
            self.resources.vcpus,
            self.resources.memory_mib,
        ))
    }

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
            || !Resources::permits(vcpus, memory_mib)
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Binding {
    pub revision: u64,
    pub sha256: String,
}

pub fn binding(cmdline: &str) -> io::Result<Option<Binding>> {
    argument(cmdline, ARGUMENT)?.map(parse_binding).transpose()
}

fn argument<'a>(cmdline: &'a str, name: &str) -> io::Result<Option<&'a str>> {
    let mut args = cmdline
        .split_ascii_whitespace()
        .filter(|arg| arg.split('=').next() == Some(name));
    let Some(arg) = args.next() else {
        return Ok(None);
    };
    arg.strip_prefix(name)
        .and_then(|arg| arg.strip_prefix('='))
        .filter(|_| args.next().is_none())
        .map(Some)
        .ok_or_else(|| invalid("invalid or duplicate Guest configuration UKI argument"))
}

fn parse_binding(value: &str) -> io::Result<Binding> {
    let (revision, sha256) = value
        .split_once(',')
        .ok_or_else(|| invalid("Guest configuration requires a revision and digest"))?;
    Ok(Binding {
        revision: number(revision, "")?,
        sha256: digest(sha256, "")?.to_owned(),
    })
}

pub fn authority(cmdline: &str) -> io::Result<Option<[u8; 32]>> {
    let Some(value) = argument(cmdline, AUTHORITY_ARGUMENT)? else {
        return Ok(None);
    };
    let key = digest(value, "")?;
    let mut raw = [0; 32];
    for (index, output) in raw.iter_mut().enumerate() {
        *output =
            u8::from_str_radix(&key[index * 2..index * 2 + 2], 16).map_err(io::Error::other)?;
    }
    if raw == [0; 32] {
        return Err(invalid("Guest configuration authority cannot be empty"));
    }
    Ok(Some(raw))
}

#[derive(PartialEq, Eq)]
pub struct Policy {
    pub binding: Option<Binding>,
    pub authority: Option<[u8; 32]>,
}

impl Policy {
    pub fn parse(cmdline: &str) -> io::Result<Self> {
        Ok(Self {
            binding: binding(cmdline)?,
            authority: authority(cmdline)?,
        })
    }
}

pub struct Change {
    pub trial_sha256: String,
    pub previous: Option<Binding>,
    pub next: Binding,
}

pub fn signed_change(packet: &[u8]) -> io::Result<(&[u8; 64], &[u8])> {
    packet
        .split_first_chunk::<64>()
        .filter(|(_, body)| !body.is_empty() && packet.len() <= CHANGE_LIMIT)
        .ok_or_else(|| invalid("invalid signed Guest configuration change size"))
}

impl Change {
    pub fn parse(body: &[u8]) -> io::Result<Self> {
        if body.len() > CHANGE_LIMIT - 64 {
            return Err(invalid("Guest configuration change exceeds its size bound"));
        }
        let text = std::str::from_utf8(body).map_err(io::Error::other)?;
        let fields: Vec<_> = text.split('\n').collect();
        let [
            "FVCA-GUEST-CONFIGURATION-CHANGE-1",
            guest,
            trial,
            previous,
            next,
            "",
        ] = fields.as_slice()
        else {
            return Err(invalid("invalid Guest configuration change"));
        };
        if guest.strip_prefix("guest=").map(str::as_bytes) != Some(SERVICE_GUEST_UUID.to_bytes()) {
            return Err(invalid("configuration change targets a different Guest"));
        }
        let previous = match previous.strip_prefix("previous=") {
            Some("default") => None,
            Some(value) => Some(parse_binding(value)?),
            None => return Err(invalid("configuration change lacks its previous revision")),
        };
        let next = parse_binding(
            next.strip_prefix("next=")
                .ok_or_else(|| invalid("configuration change lacks its next revision"))?,
        )?;
        if previous
            .as_ref()
            .map_or(0, |value| value.revision)
            .checked_add(1)
            != Some(next.revision)
        {
            return Err(invalid(
                "Guest configuration change must advance exactly one revision",
            ));
        }
        Ok(Self {
            trial_sha256: digest(trial, "trial_sha256=")?.to_owned(),
            previous,
            next,
        })
    }

    pub fn require_trial(&self, trial_sha256: &str) -> io::Result<()> {
        if self.trial_sha256 != trial_sha256 {
            return Err(invalid(
                "Guest configuration change does not authorize this Host trial",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restricts_changes_to_the_registered_guest_and_consecutive_revisions() -> io::Result<()> {
        let from = "a".repeat(64);
        let to = "b".repeat(64);
        let trial = "c".repeat(64);
        let body = format!(
            "FVCA-GUEST-CONFIGURATION-CHANGE-1\nguest={}\ntrial_sha256={trial}\nprevious=4,{from}\nnext=5,{to}\n",
            SERVICE_GUEST_UUID.to_str().map_err(io::Error::other)?
        );
        let accepted = Change::parse(body.as_bytes())?;
        assert_eq!(accepted.previous.unwrap().sha256, from);
        assert_eq!(accepted.next.revision, 5);
        for changed in [
            body.replace("next=5", "next=4"),
            body.replace("next=5", "next=6"),
            body.replace(&format!("4,{from}"), "default"),
            body.replace("e629aa43", "00000000"),
            format!("{body}\n"),
        ] {
            assert!(Change::parse(changed.as_bytes()).is_err());
        }
        assert!(signed_change(&[0; CHANGE_LIMIT + 1]).is_err());
        let selection = format!("ro {AUTHORITY_ARGUMENT}={to}");
        assert_eq!(Policy::parse(&selection)?.authority, Some([0xbb; 32]));
        assert!(Policy::parse(&format!("{selection} {selection}")).is_err());
        assert!(Policy::parse(&format!("{AUTHORITY_ARGUMENT}={}", "0".repeat(64))).is_err());
        Ok(())
    }

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
