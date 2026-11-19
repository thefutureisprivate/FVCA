#![forbid(unsafe_code)]

use std::alloc::System;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use fvca_initrd_bootstrap::{btrfs, direct_boot, find_partition, identity, invalid, sys_block};

#[global_allocator]
static ALLOCATOR: System = System;

const SELECTION: &str = "/usr/lib/fvca/guest-data";
const DATA: &str = "/run/fvca/guest-data";

fn partition(uuid: &str) -> io::Result<PathBuf> {
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        if let Some(path) = find_partition(uuid)? {
            if !sys_block(&path)?.join("partition").try_exists()? {
                return Err(invalid("Service Guest data must use a partition"));
            }
            return Ok(path);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::NotFound, "authorized Guest data partition is missing"));
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn activate() -> io::Result<()> {
    fvca_allocator_binding::require_allocator()?;
    let manifest = fs::read_to_string(SELECTION)?;
    let fields: Vec<_> = manifest.split('\n').collect();
    let ["FVCA-GUEST-DATA-1", part, "filesystem=btrfs", filesystem, ""] = fields.as_slice() else {
        return Err(invalid("malformed Service Guest data selection"));
    };
    let uuid = [8, 4, 4, 4, 12];
    let part = identity(part, "partition=", &uuid, '-')?;
    let filesystem = identity(filesystem, "filesystem_uuid=", &uuid, '-')?;
    let source = partition(part)?;

    fs::create_dir_all("/run/fvca")?;
    let drop_in = "/run/systemd/system/fvca-base-ready.service.d";
    fs::create_dir_all(drop_in)?;
    fs::write(format!("{drop_in}/10-guest-data.conf"), format!(
        "[Service]\nExecStartPre=/usr/bin/findmnt --mountpoint {DATA} --source PARTUUID={part} --types btrfs --options rw,nodev,nosuid,noexec\n",
    ))?;
    btrfs::mount(btrfs::Pool::Guest(&source), filesystem, DATA)?;
    if Path::new(direct_boot::READY_IN_INITRD).try_exists()? {
        OpenOptions::new().write(true).create_new(true).mode(0o600).open(direct_boot::READY_IN_CORE)?;
    }
    println!("FVCA_GUEST_DATA_ACTIVE");
    Ok(())
}

fn main() -> ExitCode {
    if let Err(error) = activate() {
        eprintln!("FVCA Guest data activation failed: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
