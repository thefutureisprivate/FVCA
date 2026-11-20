//! Wire format shared by the boot verifier and the release handoff.

#![forbid(unsafe_code)]

use std::io;

pub const APPROVAL_LIMIT: usize = 2048;
pub const PENDING: &str = "pending-trial";
pub const KEY_ARGUMENT: &str = "fvca.trial_key";

pub fn key_marker(key: &[u8]) -> String {
    let mut value = String::with_capacity(KEY_ARGUMENT.len() + 65);
    value.push_str(KEY_ARGUMENT);
    value.push('=');
    for byte in key {
        use std::fmt::Write as _;
        write!(value, "{byte:02x}").expect("formatting into a string cannot fail");
    }
    value
}

#[derive(PartialEq, Eq)]
pub struct Entry<'a> {
    pub id: u16,
    pub esp: &'a str,
}

#[derive(PartialEq, Eq)]
pub struct Trial<'a> {
    pub transaction: &'a str,
    pub stable: Entry<'a>,
    pub candidate: Entry<'a>,
}

pub struct Authorization<'a> {
    pub trial: Trial<'a>,
    pub digest: &'a str,
    pub bytes: u64,
    pub core: &'a str,
    pub runtime: &'a str,
    pub guest: &'a str,
}

pub struct Standing<'a> {
    pub attempt: &'a str,
    pub authorization: Authorization<'a>,
    pub stable_roots: [&'a str; 3],
    pub stable_epoch: u64,
    pub candidate_epoch: u64,
    pub epoch_policy: &'a str,
    not_before: u64,
    expires: u64,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn uuid(value: &str) -> io::Result<&str> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(i, byte)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                hex(byte)
            }
        })
    {
        return Err(invalid("invalid trial UUID"));
    }
    Ok(value)
}

fn digest<'a>(line: &'a str, field: &str) -> io::Result<&'a str> {
    line.strip_prefix(field)
        .filter(|value| value.len() == 64 && value.bytes().all(hex))
        .ok_or_else(|| invalid("invalid trial digest"))
}

fn number(field: &str, prefix: &str) -> io::Result<u64> {
    field
        .strip_prefix(prefix)
        .filter(|value| !value.starts_with('0') && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| invalid("invalid trial number"))
}

fn entry<'a>(line: &'a str, field: &str) -> io::Result<Entry<'a>> {
    let (id, esp) = line
        .strip_prefix(field)
        .and_then(|value| value.split_once(','))
        .filter(|(id, _)| id.len() == 4 && id.bytes().all(hex))
        .ok_or_else(|| invalid("invalid trial boot entry"))?;
    Ok(Entry {
        id: u16::from_str_radix(id, 16).map_err(io::Error::other)?,
        esp: uuid(esp)?,
    })
}

pub fn trial<'a>(
    transaction: &'a str,
    stable: &'a str,
    candidate: &'a str,
) -> io::Result<Trial<'a>> {
    let transaction = uuid(
        transaction
            .strip_prefix("transaction=")
            .ok_or_else(|| invalid("missing trial transaction"))?,
    )?;
    let stable = entry(stable, "stable=")?;
    let candidate = entry(candidate, "candidate=")?;
    if stable.id == candidate.id || stable.esp == candidate.esp {
        return Err(invalid(
            "stable and candidate boot entries must be distinct",
        ));
    }
    Ok(Trial {
        transaction,
        stable,
        candidate,
    })
}

pub fn authorization(text: &str) -> io::Result<Authorization<'_>> {
    let fields: Vec<_> = text.split('\n').collect();
    let [
        "FVCA-HYPERVISOR-TRIAL-2",
        tx,
        stable,
        candidate,
        esp,
        bytes,
        core,
        runtime,
        guest,
        "",
    ] = fields.as_slice()
    else {
        return Err(invalid("invalid Hypervisor trial authorization"));
    };
    let bytes = number(bytes, "candidate_esp_bytes=")?;
    if !(4096..=4 * 1024 * 1024 * 1024).contains(&bytes) || !bytes.is_multiple_of(4096) {
        return Err(invalid("invalid candidate ESP size"));
    }
    Ok(Authorization {
        trial: trial(tx, stable, candidate)?,
        digest: digest(esp, "candidate_esp_sha256=")?,
        bytes,
        core: digest(core, "candidate_core=")?,
        runtime: digest(runtime, "candidate_runtime=")?,
        guest: digest(guest, "guest_bundle=")?,
    })
}

impl Standing<'_> {
    pub fn parse(body: &str) -> io::Result<Standing<'_>> {
        if body.len() + 64 > APPROVAL_LIMIT {
            return Err(invalid("standing trial approval exceeds its bound"));
        }
        let (header, attempt) = body.split_at(
            body.find("FVCA-HYPERVISOR-TRIAL-2\n")
                .ok_or_else(|| invalid("standing trial lacks its candidate authorization"))?,
        );
        let fields: Vec<_> = header.split('\n').collect();
        let [
            "FVCA-HYPERVISOR-STANDING-TRIAL-1",
            from,
            until,
            stable_epoch,
            candidate_epoch,
            epoch_policy,
            core,
            runtime,
            guest,
            "",
        ] = fields.as_slice()
        else {
            return Err(invalid("invalid standing trial approval"));
        };
        let not_before = number(from, "not_before=")?;
        let expires = number(until, "expires=")?;
        let stable_epoch = number(stable_epoch, "stable_epoch=")?;
        let candidate_epoch = number(candidate_epoch, "candidate_epoch=")?;
        if !expires
            .checked_sub(not_before)
            .is_some_and(|length| (1..=86_400).contains(&length))
            || candidate_epoch < stable_epoch
        {
            return Err(invalid(
                "standing trial exceeds its validity or epoch bounds",
            ));
        }
        Ok(Standing {
            attempt,
            authorization: authorization(attempt)?,
            stable_roots: [
                digest(core, "stable_core=")?,
                digest(runtime, "stable_runtime=")?,
                digest(guest, "stable_guest_bundle=")?,
            ],
            stable_epoch,
            candidate_epoch,
            epoch_policy: digest(epoch_policy, "epoch_policy_sha256=")?,
            not_before,
            expires,
        })
    }

    pub fn require_fresh(&self, now: u64) -> io::Result<()> {
        if !(self.not_before..self.expires).contains(&now) {
            return Err(invalid(
                "standing trial is outside its signed validity interval",
            ));
        }
        Ok(())
    }
}
