#![forbid(unsafe_code)]

use std::alloc::System;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::{self, Command, ExitCode};

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
    let result = Command::new("/usr/bin/modprobe")
        .env_clear()
        .args(["--ignore-install", "dm_verity", "require_signatures=1"])
        .status();
    match result {
        Ok(status) if status.success() => {
            let error = Command::new("/usr/lib/systemd/systemd").exec();
            eprintln!("FVCA bootstrap could not start systemd: {error}");
        }
        Ok(status) => eprintln!("FVCA bootstrap could not load dm-verity: {status}"),
        Err(error) => eprintln!("FVCA bootstrap could not run modprobe: {error}"),
    }
    ExitCode::FAILURE
}
