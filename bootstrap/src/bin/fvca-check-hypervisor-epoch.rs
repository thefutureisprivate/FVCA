#![forbid(unsafe_code)]

use std::alloc::System;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use fvca_initrd_bootstrap::{HYPERVISOR_EPOCH_ARGUMENT, invalid};

#[global_allocator]
static ALLOCATOR: System = System;

const POLICY: &str = "/usr/lib/fvca/hypervisor-epoch";
const DEVICE: &str = "/dev/tpmrm0";
const INDEX: u32 = 0x0150_4656;
const SHA256: u16 = 0x000b;
// AUTHREAD | POLICYWRITE | COUNTER | NO_DA | WRITTEN. The counter is
// initialized and persistent, and only a TPM policy session can advance it.
const ATTRIBUTES: u32 = 0x2204_0018;
const NO_SESSIONS: u16 = 0x8001;
const SESSIONS: u16 = 0x8002;
const NV_READ_PUBLIC: u32 = 0x0000_0169;
const NV_READ: u32 = 0x0000_014e;
const PCR_READ: u32 = 0x0000_017e;
const PASSWORD: u32 = 0x4000_0009;
// One SHA-256 bank with PCR 7 selected.
const PCR7_SELECTION: [u8; 10] = [0, 0, 0, 1, 0, 11, 3, 0x80, 0, 0];

struct Selection {
    epoch: u64,
    policy: [u8; 32],
}

fn selection(command_line: &str) -> io::Result<Selection> {
    let mut data = String::new();
    File::open(POLICY)?.take(257).read_to_string(&mut data)?;
    let fields: Vec<_> = data.split('\n').collect();
    let ["FVCA-HYPERVISOR-EPOCH-1", epoch, policy, ""] = fields.as_slice() else {
        return Err(invalid("malformed signed Hypervisor epoch policy"));
    };
    let epoch = epoch
        .strip_prefix("epoch=")
        .ok_or_else(|| invalid("missing Hypervisor release epoch"))?;
    let number = epoch.parse::<u64>().map_err(io::Error::other)?;
    if number == 0 || number.to_string() != epoch {
        return Err(invalid("invalid Hypervisor release epoch"));
    }
    let policy = policy
        .strip_prefix("policy_sha256=")
        .ok_or_else(|| invalid("missing TPM counter policy digest"))?;
    if policy.len() != 64
        || !policy
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("invalid TPM counter policy digest"));
    }
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&policy[start..start + 2], 16).map_err(io::Error::other)?;
    }
    if digest == [0; 32] {
        return Err(invalid("TPM counter policy digest must be nonzero"));
    }
    if command_line != format!("{HYPERVISOR_EPOCH_ARGUMENT}={epoch},{policy}") {
        return Err(invalid(
            "command-line epoch or TPM policy differs from the signed initramfs",
        ));
    }
    Ok(Selection {
        epoch: number,
        policy: digest,
    })
}

fn exchange(device: &mut File, tag: u16, command: u32, body: &[u8]) -> io::Result<Vec<u8>> {
    let mut packet = tag.to_be_bytes().to_vec();
    packet.extend(((10 + body.len()) as u32).to_be_bytes());
    packet.extend(command.to_be_bytes());
    packet.extend(body);
    let mut response = [0; 128];
    for attempt in 0..5 {
        if device.write(&packet)? != packet.len() {
            return Err(invalid("incomplete TPM read command"));
        }
        let received = device.read(&mut response)?;
        let Some(([wire_tag_a, wire_tag_b, a, b, c, d, e, f, g, h], payload)) =
            response[..received].split_first_chunk::<10>()
        else {
            return Err(invalid("truncated TPM read response"));
        };
        let wire_tag = u16::from_be_bytes([*wire_tag_a, *wire_tag_b]);
        if u32::from_be_bytes([*a, *b, *c, *d]) as usize != received {
            return Err(invalid("invalid TPM read response size"));
        }
        let code = u32::from_be_bytes([*e, *f, *g, *h]);
        if code == 0 && wire_tag == tag {
            return Ok(payload.to_vec());
        }
        // The TPM may ask a caller to retry while it is busy with self-tests
        // or another connection. This helper only sends read commands.
        if !matches!(code, 0x908 | 0x90a | 0x922)
            || wire_tag != NO_SESSIONS
            || !payload.is_empty()
            || attempt == 4
        {
            return Err(invalid(&format!(
                "TPM refused read command 0x{command:08x} (0x{code:08x})"
            )));
        }
        thread::sleep(Duration::from_millis(50));
    }
    unreachable!("retry count checked")
}

fn require_policy(device: &mut File, selected: &Selection) -> io::Result<()> {
    let response = exchange(device, NO_SESSIONS, NV_READ_PUBLIC, &INDEX.to_be_bytes())?;
    let mut expected = 46u16.to_be_bytes().to_vec();
    expected.extend(INDEX.to_be_bytes());
    expected.extend(SHA256.to_be_bytes());
    expected.extend(ATTRIBUTES.to_be_bytes());
    expected.extend(32u16.to_be_bytes());
    expected.extend(selected.policy);
    expected.extend(8u16.to_be_bytes());
    let name = response
        .strip_prefix(expected.as_slice())
        .and_then(|trailer| trailer.strip_prefix(&[0, 34, 0, 11]));
    if name.is_none_or(|digest| digest.len() != 32) {
        return Err(invalid(
            "TPM release counter attributes or policy differ from the signed enrollment",
        ));
    }
    Ok(())
}

fn counter(device: &mut File) -> io::Result<u64> {
    let mut body = INDEX.to_be_bytes().to_vec();
    body.extend(INDEX.to_be_bytes());
    body.extend(9u32.to_be_bytes());
    body.extend(PASSWORD.to_be_bytes());
    body.extend([0, 0, 0, 0, 0]); // Empty nonce, session attributes and password.
    body.extend([0, 8, 0, 0]); // Eight bytes at offset zero.
    let response = exchange(device, SESSIONS, NV_READ, &body)?;
    let Some(value) = response
        .strip_prefix(&[0, 0, 0, 10, 0, 8])
        .and_then(|data| data.strip_suffix(&[0, 0, 1, 0, 0]))
        .and_then(|data| <[u8; 8]>::try_from(data).ok())
    else {
        return Err(invalid("invalid TPM release counter readout"));
    };
    let floor = u64::from_be_bytes(value);
    if floor == 0 {
        return Err(invalid("TPM release counter is uninitialized"));
    }
    Ok(floor)
}

fn pcr7_digest(response: &[u8]) -> io::Result<[u8; 32]> {
    let digest = response
        .get(4..) // pcrUpdateCounter
        .and_then(|data| data.strip_prefix(&PCR7_SELECTION))
        .and_then(|data| data.strip_prefix(&[0, 0, 0, 1, 0, 32]))
        .and_then(|data| <[u8; 32]>::try_from(data).ok())
        .filter(|digest| *digest != [0; 32]);
    digest.ok_or_else(|| invalid("TPM did not report a measured SHA-256 PCR 7"))
}

fn check() -> io::Result<()> {
    fvca_allocator_binding::require_allocator()?;
    let mut args = env::args_os().skip(1);
    let command_line = args
        .next()
        .and_then(|arg| arg.into_string().ok())
        .ok_or_else(|| invalid("expected one Hypervisor epoch argument"))?;
    let firmware = match args.next().as_deref() {
        None => false,
        Some(option) if option == "--measure-firmware-tpm" && args.next().is_none() => true,
        _ => return Err(invalid("invalid Hypervisor epoch arguments")),
    };
    let selected = selection(&command_line)?;
    let mut device = OpenOptions::new()
        .read(true)
        .write(true)
        .open(DEVICE)
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("TPM resource manager device is required: {error}"),
            )
        })?;
    if !device.metadata()?.file_type().is_char_device() {
        return Err(invalid("TPM resource manager character device is required"));
    }
    require_policy(&mut device, &selected)?;
    let floor = counter(&mut device)?;
    if selected.epoch < floor {
        return Err(invalid(&format!(
            "signed Hypervisor epoch {} is below the TPM floor {floor}",
            selected.epoch
        )));
    }
    println!("FVCA_HYPERVISOR_EPOCH_ACCEPTED {} {floor}", selected.epoch);
    if firmware {
        let measurement = exchange(&mut device, NO_SESSIONS, PCR_READ, &PCR7_SELECTION)
            .and_then(|response| pcr7_digest(&response));
        match measurement {
            Ok(digest) => {
                let digest: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
                println!("FVCA_FIRMWARE_PCR7 {digest}");
            }
            Err(error) => eprintln!("FVCA_HOST_FIRMWARE_TPM_EVIDENCE_BLOCKED {error}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_one_measured_sha256_pcr7() -> io::Result<()> {
        let mut report = vec![0; 4];
        report.extend(PCR7_SELECTION);
        report.extend([0, 0, 0, 1, 0, 32]);
        report.extend([0xab; 32]);
        assert_eq!(pcr7_digest(&report)?, [0xab; 32]);
        report[11] = 0x40;
        assert!(pcr7_digest(&report).is_err());
        report[11] = 0x80;
        assert!(pcr7_digest(&report[..report.len() - 1]).is_err());
        report[20..].fill(0);
        assert!(pcr7_digest(&report).is_err());
        Ok(())
    }
}

fn main() -> ExitCode {
    if let Err(error) = check() {
        eprintln!("FVCA_HYPERVISOR_EPOCH_REFUSED {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
