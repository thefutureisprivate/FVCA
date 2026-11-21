#![forbid(unsafe_code)]

use std::alloc::System;
use std::fs;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{self, Command, ExitCode};

use fvca_initrd_bootstrap::{WORKLOAD_VERITY_CERTIFICATE, direct_boot, invalid, run};

#[global_allocator]
static ALLOCATOR: System = System;

fn label_initramfs() -> io::Result<()> {
    let status = Command::new("/usr/bin/setfiles")
        .env_clear()
        .args([
            "-mF",
            "-e", "/dev",
            "-e", "/proc",
            "-e", "/sys",
            "/etc/selinux/targeted/contexts/files/file_contexts",
            "/",
        ])
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!("setfiles exited with {status}")));
    }
    Ok(())
}

fn verify_recovery_boot() -> io::Result<()> {
    if Path::new("/usr/lib/fvca/host-recovery").try_exists()? {
        run(Command::new("/usr/bin/mount").args([
            "--internal-only", "-t", "proc", "-o", "nosuid,nodev,noexec", "proc", "/proc",
        ]))?;
        if fs::read_to_string("/proc/cmdline")? != fs::read_to_string("/usr/lib/fvca/host-recovery.cmdline")? {
            return Err(invalid("the kernel command line differs from the signed Host recovery policy"));
        }
    }
    Ok(())
}

fn load_verity() -> io::Result<()> {
    let direct = direct_boot::prepare()?;
    let workload = match fs::symlink_metadata(WORKLOAD_VERITY_CERTIFICATE) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Ok(metadata) if metadata.is_file() && (1..=16 * 1024).contains(&metadata.len())
            && Path::new("/usr/lib/fvca/service-guest.composition").is_file()
            && !Path::new("/usr/lib/fvca/hypervisor.composition").exists() => true,
        Ok(_) => return Err(invalid("invalid UKI workload certificate or boot role")),
        Err(error) => return Err(error),
    };
    let ring = if direct || workload { "keyring_unsealed=1" } else { "keyring_unsealed=0" };
    run(Command::new("/usr/bin/modprobe")
        .args(["--ignore-install", "dm_verity", "require_signatures=1", ring]))?;
    if direct {
        direct_boot::activate(workload)?;
    }
    Ok(())
}

fn main() -> ExitCode {
    if process::id() != 1 {
        eprintln!("FVCA bootstrap must run as PID 1");
        return ExitCode::FAILURE;
    }
    if let Err(error) = fvca_allocator_binding::require_allocator() {
        eprintln!("FVCA bootstrap allocator check failed: {error}");
        return ExitCode::FAILURE;
    }
    if let Err(error) = verify_recovery_boot() {
        eprintln!("FVCA_HOST_RECOVERY_REFUSED {error}");
        return ExitCode::FAILURE;
    }
    // CPIO has no xattrs. Label the UKI's initramfs before systemd loads the policy.
    if let Err(error) = label_initramfs() {
        eprintln!("FVCA could not label the initramfs: {error}");
        return ExitCode::FAILURE;
    }

    // The kernel and module files are already authenticated by the UKI.
    // systemd requires the kernel's signature check before loading the BPF policy.
    if let Err(error) = load_verity() {
        eprintln!("FVCA bootstrap could not configure dm-verity: {error}");
        return ExitCode::FAILURE;
    }
    let error = Command::new("/usr/lib/systemd/systemd").exec();
    eprintln!("FVCA bootstrap could not start systemd: {error}");
    ExitCode::FAILURE
}
