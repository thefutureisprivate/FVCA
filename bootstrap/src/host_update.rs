//! Enroll Host update services from the verified UKI.

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, symlink};
use std::path::Path;
use std::process::Command;

use fvca_trial_authorization::{PEER_ENROLLMENT, PROMOTION_ENROLLMENT, peer_partitions};

use crate::{invalid, run};

const HOST_STATE: &str = "os-update";
const GUEST_STATE: &str = "guest-os-update";
const FIRMWARE_STATE: &str = fvca_trial_authorization::firmware::STATE_DIRECTORY;
const HOST_DATA: &str = "/run/fvca/host-data";
const RUN: &str = "/run/fvca";
const SIGNED: &str = "/usr/lib/fvca";
const UNITS: &str = "/run/systemd/system";

fn prepare_staging(name: &str) -> io::Result<()> {
    let data = Path::new(HOST_DATA);
    let state = data.join(name);
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
    if name == GUEST_STATE {
        let inbox = Path::new(fvca_trial_authorization::guest::STORE);
        match fs::DirBuilder::new().mode(0o700).create(inbox) {
            Ok(()) => fs::File::open(data)?.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
            Err(error) => return Err(error),
        }
        if !private(&inbox.symlink_metadata()?) {
            return Err(invalid(
                "Guest trial inbox must be private and on the authenticated pool",
            ));
        }
    }
    run(Command::new("/usr/bin/chcon")
        .args(["--no-dereference", "system_u:object_r:fvca_os_stage_t:s0"])
        .arg(staging))
}

fn owner_for(name: &str) -> io::Result<Option<Vec<u8>>> {
    let owner = match fs::read(Path::new(SIGNED).join(format!("{name}-owner"))) {
        Ok(owner) => owner,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if owner.len() != 32 || owner.iter().all(|byte| *byte == 0) {
        return Err(invalid("invalid signed update owner key"));
    }
    Ok(Some(owner))
}

fn publish_depot(name: &str, service: &str, owner: &[u8]) -> io::Result<()> {
    let signed = Path::new(SIGNED);
    let run = Path::new(RUN);
    let depot_name = format!("{name}-depot");
    let ca_name = format!("{name}-ca.pem");
    let depot = fs::read_to_string(signed.join(&depot_name))?;
    if depot == "local\n" {
        if signed.join(&ca_name).try_exists()? {
            return Err(invalid("a local update depot must have no HTTPS authority"));
        }
    } else {
        let address = depot
            .strip_suffix('\n')
            .and_then(|value| value.parse::<IpAddr>().ok())
            .filter(|ip| !ip.is_unspecified() && !ip.is_multicast())
            .ok_or_else(|| invalid("the signed update depot must identify one IP address"))?;
        let ca = fs::read(signed.join(&ca_name))?;
        if ca.len() > 65_536 || !ca.starts_with(b"-----BEGIN CERTIFICATE-----") {
            return Err(invalid("invalid signed update depot CA bundle"));
        }
        let dropin = Path::new(UNITS).join(format!("{service}.service.d"));
        fs::create_dir_all(&dropin)?;
        fs::write(
            dropin.join("20-depot.conf"),
            format!("[Service]\nIPAddressAllow={address}\n"),
        )?;
        fs::write(run.join(ca_name), ca)?;
    }
    fs::write(run.join(depot_name), depot)?;
    fs::write(run.join(format!("{name}-owner")), owner)
}

fn enable_timer(service: &str) -> io::Result<()> {
    let timer = format!("{service}.timer");
    let wants = Path::new(UNITS).join("fvca-base.target.wants");
    fs::create_dir_all(&wants)?;
    symlink(
        format!("/usr/lib/systemd/system/{timer}"),
        wants.join(&timer),
    )
}

pub fn activate_if_selected() -> io::Result<()> {
    let Some(owner) = owner_for(HOST_STATE)? else {
        return Ok(());
    };
    if let Err(error) = prepare_staging(HOST_STATE) {
        eprintln!("FVCA_HOST_UPDATE_ENROLLMENT_BLOCKED {error}");
        return Ok(());
    }
    if let Some(record) = match fs::read_to_string(Path::new(SIGNED).join(PEER_ENROLLMENT)) {
        Ok(record) => Some(record),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    } {
        let mut config = String::from("[Service]\n");
        for part in peer_partitions(&record)? {
            writeln!(config, "DeviceAllow=/dev/disk/by-partuuid/{part} rw")
                .expect("formatting into a string cannot fail");
        }
        let dropin = Path::new(UNITS).join("fvca-host-update.service.d");
        fs::create_dir_all(&dropin)?;
        fs::write(dropin.join("30-peer-slot.conf"), config)?;
        fs::write(Path::new(RUN).join(PEER_ENROLLMENT), record)?;
    }
    publish_depot(HOST_STATE, "fvca-host-update", &owner)?;
    match fs::read(crate::hypervisor_trial::PROMOTION_KEY) {
        Ok(key) if key.len() == 32 => fs::write(PROMOTION_ENROLLMENT, key)?,
        Ok(_) => return Err(invalid("invalid signed Host promotion authority")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    enable_timer("fvca-host-update")?;
    println!("FVCA_HOST_UPDATE_TIMER_ENROLLED");
    Ok(())
}

pub fn activate_guest_if_selected() -> io::Result<()> {
    let Some(owner) = owner_for(GUEST_STATE)? else {
        return Ok(());
    };
    let enrollment = fs::read(fvca_trial_authorization::guest::TRIAL_ENROLLMENT)?;
    let (trial, _) = fvca_trial_authorization::guest::enrollment(&enrollment)?;
    if owner == trial {
        return Err(invalid(
            "Guest policy and trial authorities must use distinct keys",
        ));
    }
    if let Err(error) = prepare_staging(GUEST_STATE) {
        eprintln!("FVCA_GUEST_OS_UPDATE_ENROLLMENT_BLOCKED {error}");
        return Ok(());
    }
    publish_depot(GUEST_STATE, "fvca-guest-os-update", &owner)?;
    enable_timer("fvca-guest-os-update")?;
    println!("FVCA_GUEST_OS_UPDATE_TIMER_ENROLLED");
    Ok(())
}

pub fn activate_firmware_if_selected(
    esp: &str,
    epoch: &str,
    runtime: &crate::runtime::Activation,
    filesystem: &str,
    storage_policy_sha256: &str,
) -> io::Result<()> {
    let Some(owner) = owner_for(FIRMWARE_STATE)? else {
        return Ok(());
    };
    if let Err(error) = prepare_staging(FIRMWARE_STATE) {
        eprintln!("FVCA_HOST_FIRMWARE_ENROLLMENT_BLOCKED {error}");
        return Ok(());
    }
    if let Err(error) = crate::hypervisor_trial::publish_firmware_esp(esp) {
        eprintln!("FVCA_HOST_FIRMWARE_ESP_BLOCKED {error}");
    }
    if let Err(error) = crate::hypervisor_trial::publish_firmware_boot(
        esp,
        epoch,
        runtime,
        filesystem,
        storage_policy_sha256,
    ) {
        eprintln!("FVCA_HOST_FIRMWARE_BOOT_EVIDENCE_BLOCKED {error}");
    }
    publish_depot(FIRMWARE_STATE, "fvca-firmware-update", &owner)?;
    enable_timer("fvca-firmware-update")?;
    println!("FVCA_HOST_FIRMWARE_TIMER_ENROLLED");
    Ok(())
}
