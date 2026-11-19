#![forbid(unsafe_code)]

use std::alloc::System;
use std::fs;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{self, Command, ExitCode};

use fvca_initrd_bootstrap::{WORKLOAD_VERITY_CERTIFICATE, invalid, run};

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

fn load_verity() -> io::Result<()> {
    let ring = match fs::symlink_metadata(WORKLOAD_VERITY_CERTIFICATE) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => "keyring_unsealed=0",
        Ok(metadata) if metadata.is_file() && (1..=16 * 1024).contains(&metadata.len())
            && Path::new("/usr/lib/fvca/service-guest.composition").is_file()
            && !Path::new("/usr/lib/fvca/hypervisor.composition").exists() => "keyring_unsealed=1",
        Ok(_) => return Err(invalid("invalid UKI workload certificate or boot role")),
        Err(error) => return Err(error),
    };
    // PID 1 starts before procfs is mounted. Pass both parameters explicitly.
    run(Command::new("/usr/bin/modprobe")
        .args(["--ignore-install", "dm_verity", "require_signatures=1", ring]))
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
