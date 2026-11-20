//! Arm the qualified Intel timer without feeding it during a candidate trial.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::Command;

use super::{O_NOFOLLOW, publish, read, read_record};
use crate::{invalid, run};

const POLICY: &str = "/usr/lib/fvca/hypervisor-trial-watchdog";
const RECORD: &str = "/run/fvca/boot-trial-watchdog";
const DEVICE: &str = "/dev/watchdog0";
const SYSFS: &str = "/sys/class/watchdog/watchdog0";
const IDENTITY: &str = "i6300ESB timer\n";

pub fn policy() -> io::Result<Option<i32>> {
    match read(Path::new(POLICY), 80) {
        Ok(raw) => seconds(&raw).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn seconds(raw: &[u8]) -> io::Result<i32> {
    let raw = raw
        .strip_prefix(b"FVCA-HYPERVISOR-TRIAL-WATCHDOG-1\nseconds=")
        .and_then(|value| value.strip_suffix(b"\n"))
        .ok_or_else(|| invalid("invalid signed trial watchdog policy"))?;
    let value: i32 = std::str::from_utf8(raw)
        .ok()
        .and_then(|text| text.parse::<i32>().ok())
        .filter(|value| (10..=300).contains(value) && value.to_string().as_bytes() == raw)
        .ok_or_else(|| invalid("trial watchdog deadline must be between 10 and 300 seconds"))?;
    Ok(value)
}

fn state(file: &str) -> io::Result<String> {
    fs::read_to_string(Path::new(SYSFS).join(file))
}

fn open(expected_state: &str) -> io::Result<File> {
    if state("identity")? != IDENTITY
        || state("nowayout")? != "0\n"
        || state("state")? != expected_state
    {
        return Err(invalid(
            "the qualified, stoppable i6300ESB watchdog is unavailable",
        ));
    }
    let metadata = fs::symlink_metadata(DEVICE)?;
    // Decode the Linux device number before opening it, since opening starts the timer.
    let number = metadata.rdev();
    let major = ((number >> 8) & 0xfff) | ((number >> 32) & 0xfffff000);
    let minor = (number & 0xff) | ((number >> 12) & 0xffffff00);
    if !metadata.file_type().is_char_device() || state("dev")? != format!("{major}:{minor}\n") {
        return Err(invalid("the watchdog node does not match its sysfs device"));
    }
    OpenOptions::new()
        .write(true)
        .custom_flags(O_NOFOLLOW)
        .open(DEVICE)
}

fn uptime() -> io::Result<u64> {
    let uptime = fs::read_to_string("/proc/uptime")?;
    uptime
        .split_ascii_whitespace()
        .next()
        .and_then(|time| time.split_once('.'))
        .filter(|(_, fraction)| fraction.len() == 2)
        .and_then(|(whole, fraction)| {
            let whole: u64 = whole.parse().ok()?;
            let fraction: u64 = fraction.parse().ok()?;
            whole.checked_mul(100)?.checked_add(fraction)
        })
        .ok_or_else(|| invalid("cannot establish the trial watchdog deadline"))
}

pub fn arm(seconds: i32, boot: &str, transaction: &str) -> io::Result<()> {
    // Runtime activation normally creates this directory later in the boot.
    fs::create_dir_all("/run/fvca")?;
    run(Command::new("/usr/bin/modprobe").args(["--ignore-install", "i6300esb", "nowayout=0"]))?;
    let device = open("inactive\n")?;
    let deadline = uptime()? + seconds as u64 * 100;
    if fvca_watchdog_boundary::set_timeout(&device, seconds)? != seconds
        || state("timeout")? != format!("{seconds}\n")
    {
        return Err(invalid(
            "the watchdog did not accept the signed health deadline",
        ));
    }
    // The i6300ESB driver uses magic close. Closing without it leaves the timer
    // running across switch-root, with one final kernel keepalive on release.
    drop(device);
    publish(
        Path::new(RECORD),
        format!("{boot}\n{transaction}\n{deadline}\n").as_bytes(),
    )?;
    println!("FVCA_TRIAL_WATCHDOG_ARMED {transaction} {seconds}");
    Ok(())
}

pub fn stop(boot: &str, transaction: &str) -> io::Result<()> {
    let record = match read_record(Path::new(RECORD)) {
        Ok(record) => record,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let record = std::str::from_utf8(&record).map_err(io::Error::other)?;
    let (prefix, deadline) = record
        .trim_end()
        .rsplit_once('\n')
        .ok_or_else(|| invalid("invalid trial watchdog record"))?;
    let deadline: u64 = deadline.parse().map_err(io::Error::other)?;
    if prefix != format!("{boot}\n{transaction}") || uptime()? >= deadline {
        return Err(invalid(
            "candidate health is outside the armed watchdog trial",
        ));
    }
    let device = open("active\n")?;
    if uptime()? >= deadline {
        return Err(invalid(
            "candidate health deadline elapsed before watchdog disarm",
        ));
    }
    fvca_watchdog_boundary::stop(&device)?;
    if state("state")? != "inactive\n" {
        return Err(invalid("the qualified watchdog did not stop"));
    }
    println!("FVCA_TRIAL_WATCHDOG_DISARMED {transaction}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::seconds;

    #[test]
    fn accepts_only_canonical_bounded_deadlines() {
        let policy = |value| format!("FVCA-HYPERVISOR-TRIAL-WATCHDOG-1\nseconds={value}\n");
        for good in ["10", "300"] {
            assert!(seconds(policy(good).as_bytes()).is_ok());
        }
        for bad in [
            "9",
            "301",
            "+30",
            "030",
            "30 ",
            "30\nseconds=10",
            "4294967296",
        ] {
            assert!(seconds(policy(bad).as_bytes()).is_err());
        }
    }
}
