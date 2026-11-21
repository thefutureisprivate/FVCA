//! Boot authorization and durable binding for the registered Service Guest.

use std::io;

use crate::{
    digest,
    guest::SERVICE_GUEST_UUID,
    guest_config::{Binding, Configuration, Resources},
    invalid, number, uuid,
};

pub const SELECTION: &str = "/run/fvca/guest-commissioning";
pub const OFFER: &str = "/run/fvca/guest-provisioning-offer";
pub const QUEUE: &str = "/run/fvca/host-data/guest-provisioning";
pub const REQUEST: &str = "request";
pub const JOURNAL: &str = "/run/fvca/host-data/guest-commissioning";
pub const GUEST_READY: &str = "guest-ready";
pub const LIMIT: usize = 512;
const SCHEMA: &str = "FVCA-GUEST-PROVISIONING-1";

pub struct Seed<'a> {
    pub bundle: &'a str,
    pub bytes: u64,
    pub digest: &'a str,
}

impl<'a> Seed<'a> {
    pub fn parse(text: &'a str) -> io::Result<Self> {
        let mut fields = text.split_terminator('\n');
        if !text.ends_with('\n')
            || fields.next() != Some("FVCA-GUEST-COMMISSIONING-1")
            || fields
                .next()
                .and_then(|line| line.strip_prefix("guest="))
                .map(str::as_bytes)
                != Some(SERVICE_GUEST_UUID.to_bytes())
        {
            return Err(invalid("invalid signed Service Guest commissioning record"));
        }
        let bundle = digest(fields.next().unwrap_or_default(), "bundle=")?;
        let bytes = number(fields.next().unwrap_or_default(), "bytes=")?;
        let digest = digest(fields.next().unwrap_or_default(), "seed_sha256=")?;
        if fields.next().is_some()
            || bytes == 0
            || bytes > i64::MAX as u64
            || !bytes.is_multiple_of(512)
        {
            return Err(invalid("invalid signed Guest seed length or fields"));
        }
        Ok(Self {
            bundle,
            bytes,
            digest,
        })
    }
}

pub struct Offer<'a> {
    pub host: &'a str,
    pub configuration: Option<Binding>,
    pub resources: Resources,
    pub seed: Seed<'a>,
}

fn resources(vcpus: u64, memory_mib: u64) -> io::Result<Resources> {
    let resources = Resources {
        vcpus: u32::try_from(vcpus).map_err(io::Error::other)?,
        memory_mib: u32::try_from(memory_mib).map_err(io::Error::other)?,
    };
    Ok(Configuration::from_resources(1, resources)?.resources)
}

fn host(value: &str) -> io::Result<&str> {
    if value == "00000000-0000-0000-0000-000000000000"
        || value.as_bytes() == SERVICE_GUEST_UUID.to_bytes()
    {
        return Err(invalid("commissioning requires a distinct Host identity"));
    }
    uuid(value)
}

impl<'a> Offer<'a> {
    pub fn record(
        host_id: &str,
        binding: Option<&Binding>,
        selected: Resources,
        seed: &str,
    ) -> io::Result<String> {
        let binding = binding.map_or_else(
            || "default".to_owned(),
            |value| format!("{},{}", value.revision, value.sha256),
        );
        let text = format!(
            "{SCHEMA}\nhost={}\nconfiguration={binding}\nvcpus={}\nmemory_mib={}\n{seed}",
            host(host_id)?,
            selected.vcpus,
            selected.memory_mib,
        );
        Offer::parse(&text)?;
        Ok(text)
    }

    pub fn parse(text: &'a str) -> io::Result<Self> {
        if text.len() > LIMIT {
            return Err(invalid("Guest provisioning record exceeds its size bound"));
        }
        let mut fields = text.splitn(6, '\n');
        let [
            Some(SCHEMA),
            Some(identity),
            Some(binding),
            Some(cpus),
            Some(memory),
            Some(seed),
        ] = std::array::from_fn(|_| fields.next())
        else {
            return Err(invalid("invalid Guest provisioning record"));
        };
        let host = host(identity.strip_prefix("host=").unwrap_or_default())?;
        let resources = resources(number(cpus, "vcpus=")?, number(memory, "memory_mib=")?)?;
        let configuration = match binding.strip_prefix("configuration=") {
            Some("default") if resources == Resources::DEFAULT => None,
            Some(binding) => {
                let (revision, sha256) = binding
                    .split_once(',')
                    .ok_or_else(|| invalid("invalid provisioning configuration binding"))?;
                let revision = number(revision, "")?;
                Configuration::from_resources(revision, resources)?;
                Some(Binding {
                    revision,
                    sha256: digest(sha256, "")?.to_owned(),
                })
            }
            None => return Err(invalid("missing provisioning configuration binding")),
        };
        Ok(Self {
            host,
            configuration,
            resources,
            seed: Seed::parse(seed)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_canonical_host_and_exact_seed() -> io::Result<()> {
        let host = "367f5cbc-c46a-437d-af72-5d96d805d234";
        let bundle = "a".repeat(64);
        let hash = "b".repeat(64);
        let seed = format!(
            "FVCA-GUEST-COMMISSIONING-1\nguest=e629aa43-af11-47c6-aedc-a2dc47f1cc3a\nbundle={bundle}\nbytes=67108864\nseed_sha256={hash}\n"
        );
        let record = Offer::record(host, None, Resources::DEFAULT, &seed)?;
        let offer = Offer::parse(&record)?;
        assert_eq!(offer.host, host);
        assert_eq!(offer.configuration, None);
        assert_eq!(offer.seed.bundle, bundle);
        assert_eq!(offer.seed.digest, hash);
        assert_eq!(offer.seed.bytes, 67_108_864);
        for (original, replacement) in [
            (host, "e629aa43-af11-47c6-aedc-a2dc47f1cc3a"),
            ("vcpus=2", "vcpus=3"),
            ("bytes=67108864", "bytes=067108864"),
            ("bytes=67108864", "bytes=67108865"),
            ("seed_sha256=", "path=/tmp\nseed_sha256="),
        ] {
            assert!(Offer::parse(&record.replace(original, replacement)).is_err());
        }
        assert!(Offer::parse(record.trim_end_matches('\n')).is_err());
        assert!(Offer::parse(&format!("{record}\n")).is_err());
        Ok(())
    }
}
