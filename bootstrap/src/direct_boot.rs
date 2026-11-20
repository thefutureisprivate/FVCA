//! Apply the Service Guest's signed direct-boot policy before starting systemd.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;

use crate::{WORKLOAD_VERITY_CERTIFICATE, invalid, kernel_policy, run};

pub const READY_IN_INITRD: &str = "/usr/lib/fvca/direct-boot-ready";
pub const READY_IN_CORE: &str = "/run/fvca/direct-boot-ready";
const COMMAND_LINE: &str = "/usr/lib/fvca/direct-boot.cmdline";
const CERTIFICATE: &str = "/usr/lib/fvca/direct-verity.der";
const VERITY_KEYRING: &str = "%:.dm-verity";

pub fn prepare() -> io::Result<bool> {
    let command_line = match fs::read_to_string(COMMAND_LINE) {
        Ok(command_line) => command_line,
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                && !Path::new(CERTIFICATE).try_exists()? =>
        {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    if !Path::new("/usr/lib/fvca/service-guest.composition").is_file()
        || Path::new("/usr/lib/fvca/hypervisor.composition").try_exists()?
    {
        return Err(invalid(
            "direct boot requires an exclusive Service Guest composition",
        ));
    }
    for (kind, path) in [
        ("proc", "/proc"),
        ("sysfs", "/sys"),
        ("securityfs", "/sys/kernel/security"),
    ] {
        run(Command::new("/usr/bin/mount").args([
            "--internal-only",
            "-t",
            kind,
            "-o",
            "nosuid,nodev,noexec",
            kind,
            path,
        ]))?;
    }
    if fs::read_to_string("/proc/cmdline")? != command_line {
        return Err(invalid(
            "direct-boot kernel command line differs from the signed command line",
        ));
    }
    if Path::new("/sys/firmware/efi").try_exists()? {
        return Err(invalid("direct boot requires a non-EFI boot"));
    }
    kernel_policy::require_signed_modules()?;
    Ok(true)
}

fn enroll(path: &str) -> io::Result<()> {
    let certificate = File::open(path)?;
    let metadata = certificate.metadata()?;
    if !metadata.is_file() || !(1..=16 * 1024).contains(&metadata.len()) {
        return Err(invalid("invalid direct-boot verity certificate"));
    }
    run(Command::new("/usr/bin/keyctl")
        .args(["padd", "asymmetric", "", VERITY_KEYRING])
        .stdin(certificate))
}

pub fn activate(workload: bool) -> io::Result<()> {
    enroll(CERTIFICATE)?;
    if workload {
        enroll(WORKLOAD_VERITY_CERTIFICATE)?;
    }
    run(Command::new("/usr/bin/keyctl").args(["restrict_keyring", VERITY_KEYRING]))?;

    // With no firmware keys, the early kernel can load only modules signed by
    // its own trust anchors. Close module loading before executing systemd.
    kernel_policy::load_modules(&[
        "virtio_pci",
        "virtio_blk",
        "virtio_console",
        "virtio_net",
        "erofs",
        "btrfs",
        "overlay",
        "loop",
        "nf_tables",
        "nft_ct",
    ])?;
    kernel_policy::seal()?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(READY_IN_INITRD)?;
    eprintln!("FVCA_DIRECT_BOOT_POLICY_ACTIVE");
    Ok(())
}
