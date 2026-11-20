//! Enable the Host update timer only for the enrollment carried by the signed UKI.

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, symlink};
use std::path::Path;
use std::process::Command;

use fvca_trial_authorization::{PEER_ENROLLMENT, peer_partitions};

use crate::{invalid, run};

const OWNER: &str = "os-update-owner";
const DEPOT: &str = "os-update-depot";
const CA: &str = "os-update-ca.pem";
const TIMER: &str = "fvca-host-update.timer";
const HOST_DATA: &str = "/run/fvca/host-data";

fn prepare_staging() -> io::Result<()> {
    let data = Path::new(HOST_DATA);
    let state = data.join("os-update");
    let parent = state.symlink_metadata()?;
    let device = data.metadata()?.dev();
    let private = |meta: &fs::Metadata| {
        meta.is_dir()
            && meta.uid() == 0
            && meta.gid() == 0
            && meta.mode() & 0o7777 == 0o700
            && meta.dev() == device
    };
    if !private(&parent) {
        return Err(invalid(
            "Host update state requires a private directory on the authenticated pool",
        ));
    }
    let staging = state.join("staged");
    match fs::DirBuilder::new().mode(0o700).create(&staging) {
        Ok(()) => fs::File::open(&state)?.sync_all()?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error),
    }
    if !private(&staging.symlink_metadata()?) {
        return Err(invalid(
            "Host release staging requires a private directory on the authenticated pool",
        ));
    }
    run(Command::new("/usr/bin/chcon")
        .args(["--no-dereference", "system_u:object_r:fvca_os_stage_t:s0"])
        .arg(staging))
}

pub fn activate_if_selected() -> io::Result<()> {
    let signed = Path::new("/usr/lib/fvca");
    let owner = match fs::read(signed.join(OWNER)) {
        Ok(owner) => owner,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if owner.len() != 32 || owner.iter().all(|byte| *byte == 0) {
        return Err(invalid("invalid signed Host update owner key"));
    }
    if let Err(error) = prepare_staging() {
        eprintln!("FVCA_HOST_UPDATE_ENROLLMENT_BLOCKED {error}");
        return Ok(());
    }
    let depot = fs::read_to_string(signed.join(DEPOT))?;
    let run = Path::new("/run/fvca");
    let units = Path::new("/run/systemd/system");
    let dropin = units.join("fvca-host-update.service.d");
    if let Some(record) = match fs::read_to_string(signed.join(PEER_ENROLLMENT)) {
        Ok(record) => Some(record),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    } {
        let mut config = String::from("[Service]\n");
        for part in peer_partitions(&record)? {
            writeln!(config, "DeviceAllow=/dev/disk/by-partuuid/{part} rw")
                .expect("formatting into a string cannot fail");
        }
        fs::create_dir_all(&dropin)?;
        fs::write(dropin.join("30-peer-slot.conf"), config)?;
        fs::write(run.join(PEER_ENROLLMENT), record)?;
    }
    if depot == "local\n" {
        if signed.join(CA).try_exists()? {
            return Err(invalid("a local Host depot must have no HTTPS authority"));
        }
    } else {
        let address = depot
            .strip_suffix('\n')
            .and_then(|value| value.parse::<IpAddr>().ok())
            .filter(|ip| !ip.is_unspecified() && !ip.is_multicast())
            .ok_or_else(|| invalid("the signed Host update depot must identify one IP address"))?;
        let ca = fs::read(signed.join(CA))?;
        if ca.len() > 65_536 || !ca.starts_with(b"-----BEGIN CERTIFICATE-----") {
            return Err(invalid("invalid signed Host update depot CA bundle"));
        }
        fs::create_dir_all(&dropin)?;
        fs::write(
            dropin.join("20-depot.conf"),
            format!("[Service]\nIPAddressAllow={address}\n"),
        )?;
        fs::write(run.join(CA), ca)?;
    }
    fs::write(run.join(DEPOT), depot)?;
    fs::write(run.join(OWNER), owner)?;
    let wants = units.join("fvca-base.target.wants");
    fs::create_dir_all(&wants)?;
    symlink(
        format!("/usr/lib/systemd/system/{TIMER}"),
        wants.join(TIMER),
    )?;
    println!("FVCA_HOST_UPDATE_TIMER_ENROLLED");
    Ok(())
}
