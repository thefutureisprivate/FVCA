//! Capture manifests shared by the lifecycle coordinator and Host inventory.

use std::io;

use crate::{digest, guest, invalid, uuid};

pub const RECORD_BYTES: u64 = 8192;

#[derive(Clone, Copy)]
pub enum Consistency {
    CleanStopped,
    Filesystem,
}

impl Consistency {
    pub fn header(self) -> &'static str {
        match self {
            Self::CleanStopped => "FVCA-STOPPED-CAPTURE-1",
            Self::Filesystem => "FVCA-LIVE-CAPTURE-1",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::CleanStopped => "clean-stopped",
            Self::Filesystem => "filesystem-consistent",
        }
    }
}

pub struct Plan<'a> {
    pub source: &'a str,
    pub source_id: u64,
    pub bytes: u64,
    pub captured: u64,
    pub launch: &'a str,
}

pub fn parse_plan_fields<'a>(
    text: &'a str,
    id: &str,
    consistency: Consistency,
    filesystem: Option<&str>,
) -> io::Result<Plan<'a>> {
    let launch_header = "FVCA-GUEST-LAUNCH-1\n";
    let start = text
        .find(launch_header)
        .ok_or_else(|| invalid("capture record lacks its authorized launch selection"))?;
    let (prefix, launch) = text.split_at(start);
    guest::parse(launch)?;
    let mut lines = prefix.lines();
    let name = consistency.name();
    for expected in [
        consistency.header().to_owned(),
        format!("capture_id={id}"),
        format!("vm_uuid={}", guest::SERVICE_GUEST_UUID.to_str().unwrap()),
        format!("requested_consistency={name}"),
        format!("achieved_consistency={name}"),
    ] {
        if lines.next() != Some(expected.as_str()) {
            return Err(invalid("unexpected capture fields"));
        }
    }
    let fsid = uuid(
        lines
            .next()
            .and_then(|line| line.strip_prefix("filesystem_uuid="))
            .ok_or_else(|| invalid("missing capture filesystem UUID"))?,
    )?;
    if filesystem.is_some_and(|expected| expected != fsid) {
        return Err(invalid("capture belongs to a different Btrfs filesystem"));
    }
    for expected in [
        "identity_policy=single-instance",
        "persistent_firmware=none",
        "persistent_vtpm=none",
        "external_storage=none",
        "workload_state=contained-in-data.raw",
        "member=data.raw,raw,vdc",
    ] {
        if lines.next() != Some(expected) {
            return Err(invalid("unsupported Guest recovery profile"));
        }
    }
    let mut take = |key| {
        lines
            .next()
            .and_then(|line| line.strip_prefix(key))
            .ok_or_else(|| invalid("incomplete capture metadata"))
    };
    let source = uuid(take("source_uuid=")?)?;
    let number = |value: &str| value.parse::<u64>().map_err(io::Error::other);
    let root_id = number(take("source_id=")?)?;
    let time = number(take("capture_unix_seconds=")?)?;
    let bytes = number(take("disk_bytes=")?)?;
    if root_id < 256
        || time == 0
        || bytes == 0
        || !bytes.is_multiple_of(512)
        || lines.next().is_some()
    {
        return Err(invalid("invalid capture metadata"));
    }
    Ok(Plan {
        source,
        source_id: root_id,
        bytes,
        captured: time,
        launch,
    })
}

pub struct Manifest<'a> {
    pub consistency: Consistency,
    pub plan: Plan<'a>,
    pub volume: &'a str,
    pub sequence: u64,
    pub digest: &'a str,
    plan_text: &'a str,
}

impl<'a> Manifest<'a> {
    pub fn parse(manifest: &'a str, id: &str, filesystem: Option<&str>) -> io::Result<Self> {
        let mut lines = manifest.splitn(5, '\n');
        if lines.next() != Some("CAPTURE_COMPLETE") || manifest.len() as u64 > RECORD_BYTES {
            return Err(invalid("unexpected finalized capture manifest"));
        }
        let mut take = |field| {
            lines
                .next()
                .and_then(|line| line.strip_prefix(field))
                .ok_or_else(|| invalid("incomplete finalized capture manifest"))
        };
        let volume = uuid(take("snapshot_uuid=")?)?;
        let sequence = take("snapshot_id=")?
            .parse::<u64>()
            .map_err(io::Error::other)?;
        let digest = digest(take("disk_sha256=")?, "")?;
        let plan_text = lines
            .next()
            .ok_or_else(|| invalid("the capture has no embedded plan"))?;
        let consistency = if plan_text.starts_with(Consistency::Filesystem.header()) {
            Consistency::Filesystem
        } else {
            Consistency::CleanStopped
        };
        let plan = parse_plan_fields(plan_text, id, consistency, filesystem)?;
        if sequence < 256 || sequence == plan.source_id || volume == plan.source {
            return Err(invalid(
                "capture inventory has inconsistent snapshot topology",
            ));
        }
        Ok(Self {
            consistency,
            plan,
            volume,
            sequence,
            digest,
            plan_text,
        })
    }

    pub fn verify_sidecars(
        &self,
        mut read: impl FnMut(&str) -> io::Result<String>,
    ) -> io::Result<()> {
        let sealed = format!(
            "CAPTURE_SEALED_PENDING_VALIDATION\nsnapshot_uuid={}\nsnapshot_id={}\n{}",
            self.volume, self.sequence, self.plan_text
        );
        if read("plan")? != self.plan_text
            || read("sealed")? != sealed
            || (matches!(self.consistency, Consistency::Filesystem)
                && read("live-seal-verified")? != "1\n")
        {
            return Err(invalid(
                "the capture inventory disagrees with its sealed record",
            ));
        }
        Ok(())
    }
}

pub fn expiry_record(id: &str, volume: &str, sequence: u64, digest: &str) -> String {
    format!(
        "FVCA-LOCAL-CAPTURE-EXPIRED-1\ncapture={id}\nsnapshot_uuid={volume}\nsnapshot_id={sequence}\ndisk_sha256={digest}\n"
    )
}
