//! Wire format shared by the boot verifier and the release handoff.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::io;
use std::net::{IpAddr, SocketAddr};

pub mod efi;
pub mod firmware;
pub mod guest;
pub mod guest_config;
pub mod host_network;

pub const APPROVAL_LIMIT: usize = 2048;
pub const PENDING: &str = "pending-trial";
pub const KEY_ARGUMENT: &str = "fvca.trial_key";
pub const RUNNING_CONTEXT: &str = "/run/fvca/running-trial-context";
pub const GUEST_CAPTURE_LOCK: &str = "/run/fvca/guest-capture.lock";
pub const GUEST_OPERATION_LOCK: &str = "/run/fvca/guest-operation.lock";
pub const PEER_PARTITIONS: usize = 7;
pub const PEER_ENROLLMENT: &str = "os-update-peer";
pub const PEER_BYTES: usize = PEER_PARTITIONS * 37;
pub const PROMOTION_ENROLLMENT: &str = "/run/fvca/os-update-promotion-key";
pub const PROMOTED_RELEASE: &str = "/run/fvca/promoted-os-release";
pub const STANDING_TRIAL: &str = "FVCA-HYPERVISOR-STANDING-TRIAL-2";
pub const STANDING_PROMOTION: &str = "FVCA-HYPERVISOR-STANDING-PROMOTION-2";
pub const WATCHDOG_ARGUMENT: &str = "fvca.trial_watchdog_seconds";
pub const MANAGEMENT_ARGUMENT: &str = "fvca.management";
pub const MANAGEMENT_ADDRESS_ARGUMENT: &str = "fvca.management_address";
pub const MANAGEMENT_POLICY: &str = "/run/fvca/management.json";
pub const MANAGEMENT_INTENTS: &str = "/run/fvca/host-data/os-update/management-intents";
pub const MANAGEMENT_POLICY_BYTES: usize = 4096;
pub const MANAGEMENT_UID: u32 = 62000;

fn signed_argument<'a>(cmdline: &'a str, argument: &str) -> io::Result<Option<&'a str>> {
    let mut markers = cmdline
        .split_ascii_whitespace()
        .filter(|arg| arg.split('=').next() == Some(argument));
    let Some(marker) = markers.next() else {
        return Ok(None);
    };
    if markers.next().is_some() {
        return Err(invalid("duplicate signed command-line binding"));
    }
    marker
        .split_once('=')
        .map(|(_, value)| Some(value))
        .ok_or_else(|| invalid("invalid signed command-line binding"))
}

pub fn private_management_address(address: SocketAddr) -> bool {
    let private = match address.ip() {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_loopback(),
    };
    private
        && address.port() >= 1024
        && !matches!(address, SocketAddr::V6(value) if value.scope_id() != 0 || value.flowinfo() != 0)
}

pub fn management_binding(cmdline: &str) -> io::Result<Option<(&str, SocketAddr)>> {
    let digest_value = signed_argument(cmdline, MANAGEMENT_ARGUMENT)?;
    let address = signed_argument(cmdline, MANAGEMENT_ADDRESS_ARGUMENT)?;
    match (digest_value, address) {
        (None, None) => Ok(None),
        (Some(value), Some(address)) => {
            let address = address.parse().map_err(io::Error::other)?;
            if !private_management_address(address) {
                return Err(invalid("management requires an enrolled private listener"));
            }
            Ok(Some((digest(value, "")?, address)))
        }
        _ => Err(invalid(
            "management requires both enrollment digest and private address",
        )),
    }
}

pub struct Promotion<'a> {
    pub trial_body: &'a str,
    pub trial: Standing<'a>,
    pub stable_slot: &'a str,
    pub stable_sequence: u64,
    pub candidate_sequence: u64,
    pub stable_manifest: &'a str,
    pub candidate_manifest: &'a str,
}

impl Promotion<'_> {
    pub fn parse(body: &str) -> io::Result<Promotion<'_>> {
        if body.len() + 64 > APPROVAL_LIMIT {
            return Err(invalid("standing promotion exceeds its size bound"));
        }
        let (header, trial_body) = body.split_at(
            body.find(STANDING_TRIAL)
                .ok_or_else(|| invalid("standing promotion is missing its trial"))?,
        );
        let fields: Vec<_> = header.split('\n').collect();
        let [
            STANDING_PROMOTION,
            stable_slot,
            stable_sequence,
            candidate_sequence,
            stable_manifest,
            candidate_manifest,
            "",
        ] = fields.as_slice()
        else {
            return Err(invalid("invalid standing promotion"));
        };
        let stable_slot = stable_slot
            .strip_prefix("stable_slot=")
            .filter(|slot| matches!(*slot, "a" | "b"))
            .ok_or_else(|| invalid("invalid standing promotion stable slot"))?;
        let stable_sequence = number(stable_sequence, "stable_sequence=")?;
        let candidate_sequence = number(candidate_sequence, "candidate_sequence=")?;
        let stable_manifest = digest(stable_manifest, "stable_manifest_sha256=")?;
        let candidate_manifest = digest(candidate_manifest, "candidate_manifest_sha256=")?;
        if stable_sequence >= candidate_sequence || stable_manifest == candidate_manifest {
            return Err(invalid(
                "standing promotion must advance the active release",
            ));
        }
        Ok(Promotion {
            trial_body,
            trial: Standing::parse(trial_body)?,
            stable_slot,
            stable_sequence,
            candidate_sequence,
            stable_manifest,
            candidate_manifest,
        })
    }

    pub fn matches_trial(&self, envelope: &[u8]) -> io::Result<()> {
        if envelope.get(64..) != Some(self.trial_body.as_bytes()) {
            return Err(invalid(
                "standing promotion does not authorize the exact trial",
            ));
        }
        Ok(())
    }
}

pub fn peer_partitions(record: &str) -> io::Result<[&str; PEER_PARTITIONS]> {
    let text = record
        .strip_suffix('\n')
        .ok_or_else(|| invalid("missing signed peer partition terminator"))?;
    let mut fields = text.split('\n');
    let mut partitions = [""; PEER_PARTITIONS];
    for index in 0..partitions.len() {
        let part = uuid(
            fields
                .next()
                .ok_or_else(|| invalid("incomplete signed peer slot"))?,
        )?;
        if part == "00000000-0000-0000-0000-000000000000" || partitions[..index].contains(&part) {
            return Err(invalid(
                "signed peer slot partition identities must be distinct and nonzero",
            ));
        }
        partitions[index] = part;
    }
    if fields.next().is_some() {
        return Err(invalid("extra signed peer partition identities"));
    }
    Ok(partitions)
}

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
    pub candidate_uki: &'a str,
    pub candidate_uki_bytes: u64,
    pub payloads: [[&'a str; 2]; 3],
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

pub fn watchdog_seconds(value: &str) -> io::Result<i32> {
    number(value, "")
        .ok()
        .filter(|value| (10..=300).contains(value))
        .map(|value| value as i32)
        .ok_or_else(|| invalid("trial watchdog deadline must be between 10 and 300 seconds"))
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
    pub fn require_running_context(&self, key: &[u8], context: &[u8]) -> io::Result<()> {
        let (running_key, running) = context
            .split_first_chunk::<32>()
            .ok_or_else(|| invalid("missing verified running trial context"))?;
        let [core, runtime, guest] = self.stable_roots;
        let expected = format!(
            "{}\n{core}\n{runtime}\n{guest}\nfvca.hypervisor_epoch={},{}\n",
            self.authorization.trial.stable.esp, self.stable_epoch, self.epoch_policy,
        );
        if running_key != key || running != expected.as_bytes() {
            return Err(invalid(
                "trial does not authorize the running stable composition",
            ));
        }
        Ok(())
    }

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
            STANDING_TRIAL,
            from,
            until,
            stable_epoch,
            candidate_epoch,
            epoch_policy,
            core,
            runtime,
            guest,
            uki,
            uki_bytes,
            core_devices,
            runtime_devices,
            guest_devices,
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
        let authorization = authorization(attempt)?;
        let candidate_uki_bytes = number(uki_bytes, "candidate_uki_bytes=")?;
        if candidate_uki_bytes > authorization.bytes.min(256 * 1024 * 1024) {
            return Err(invalid(
                "standing trial candidate UKI exceeds its size bound",
            ));
        }
        let mut used = BTreeSet::from([
            authorization.trial.candidate.esp,
            "00000000-0000-0000-0000-000000000000",
        ]);
        let mut payloads = [[""; 2]; 3];
        for (pair, (line, field)) in payloads.iter_mut().zip([
            (core_devices, "candidate_core_devices="),
            (runtime_devices, "candidate_runtime_devices="),
            (guest_devices, "candidate_guest_devices="),
        ]) {
            let (data, tree) = line
                .strip_prefix(field)
                .and_then(|value| value.split_once(','))
                .ok_or_else(|| invalid("standing trial is missing candidate partition IDs"))?;
            *pair = [uuid(data)?, uuid(tree)?];
            if !used.insert(pair[0]) || !used.insert(pair[1]) {
                return Err(invalid(
                    "standing trial requires distinct nonzero candidate partition IDs",
                ));
            }
        }
        Ok(Standing {
            attempt,
            authorization,
            stable_roots: [
                digest(core, "stable_core=")?,
                digest(runtime, "stable_runtime=")?,
                digest(guest, "stable_guest_bundle=")?,
            ],
            stable_epoch,
            candidate_epoch,
            epoch_policy: digest(epoch_policy, "epoch_policy_sha256=")?,
            candidate_uki: digest(uki, "candidate_uki_sha256=")?,
            candidate_uki_bytes,
            payloads,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn management_listener_requires_a_unique_private_binding() -> io::Result<()> {
        let digest = "a".repeat(64);
        let binding = format!("{MANAGEMENT_ARGUMENT}={digest}");
        assert_eq!(management_binding("quiet")?, None);
        for listener in ["192.168.1.12:9443", "[fd12::1]:9443", "[::1]:9443"] {
            let cmdline = format!("quiet {binding} {MANAGEMENT_ADDRESS_ARGUMENT}={listener}");
            assert_eq!(
                management_binding(&cmdline)?,
                Some((digest.as_str(), listener.parse().unwrap()))
            );
            assert!(management_binding(&format!("{cmdline} {binding}")).is_err());
            assert!(
                management_binding(&format!(
                    "{cmdline} {MANAGEMENT_ADDRESS_ARGUMENT}={listener}"
                ))
                .is_err()
            );
        }
        assert!(management_binding(&binding).is_err());
        for listener in [
            "0.0.0.0:9443",
            "192.168.1.12:443",
            "8.8.8.8:9443",
            "[fe80::1%3]:9443",
        ] {
            assert!(
                management_binding(&format!(
                    "{binding} {MANAGEMENT_ADDRESS_ARGUMENT}={listener}"
                ))
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn standing_promotion_binds_exact_trial_and_advances_sequence() -> io::Result<()> {
        let prior = "a".repeat(64);
        let candidate = "b".repeat(64);
        let first = "11111111-1111-4111-8111-111111111111";
        let other = "22222222-2222-4222-8222-222222222222";
        let trial = format!(
            concat!(
                "FVCA-HYPERVISOR-STANDING-TRIAL-2\nnot_before=10\nexpires=300\n",
                "stable_epoch=1\ncandidate_epoch=2\nepoch_policy_sha256={0}\n",
                "stable_core={0}\nstable_runtime={0}\nstable_guest_bundle={0}\n",
                "candidate_uki_sha256={3}\ncandidate_uki_bytes=2048\n",
                "candidate_core_devices=11111111-1111-4111-8111-111111111112,11111111-1111-4111-8111-111111111113\n",
                "candidate_runtime_devices=11111111-1111-4111-8111-111111111114,11111111-1111-4111-8111-111111111115\n",
                "candidate_guest_devices=11111111-1111-4111-8111-111111111116,11111111-1111-4111-8111-111111111117\n",
                "FVCA-HYPERVISOR-TRIAL-2\ntransaction=33333333-3333-4333-8333-333333333333\n",
                "stable=000a,{1}\ncandidate=000b,{2}\ncandidate_esp_sha256={3}\n",
                "candidate_esp_bytes=4096\ncandidate_core={3}\ncandidate_runtime={3}\nguest_bundle={3}\n",
            ),
            prior, first, other, candidate,
        );
        let body = format!(
            "{STANDING_PROMOTION}\nstable_slot=a\nstable_sequence=3\ncandidate_sequence=4\n\
             stable_manifest_sha256={prior}\ncandidate_manifest_sha256={candidate}\n{trial}",
        );
        let approval = Promotion::parse(&body)?;
        assert_eq!(approval.candidate_manifest, candidate);
        assert_eq!(approval.candidate_sequence, 4);
        assert_eq!(approval.trial.candidate_uki, candidate);
        assert_eq!(approval.trial.candidate_uki_bytes, 2048);
        assert!(
            Standing::parse(&trial.replace("candidate_uki_bytes=2048", "candidate_uki_bytes=8192"))
                .is_err()
        );
        assert!(
            Standing::parse(&trial.replace(
                "11111111-1111-4111-8111-111111111117",
                "11111111-1111-4111-8111-111111111112"
            ))
            .is_err()
        );
        let mut envelope = vec![0; 64];
        envelope.extend_from_slice(trial.as_bytes());
        approval.matches_trial(&envelope)?;
        envelope[64] ^= 1;
        assert!(approval.matches_trial(&envelope).is_err());
        assert!(
            Promotion::parse(&body.replace("candidate_sequence=4", "candidate_sequence=3"))
                .is_err()
        );
        Ok(())
    }
}
