//! Enroll Host update services from the verified UKI.

use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, Write};
use std::net::IpAddr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, symlink};
use std::path::Path;
use std::process::Command;

use fvca_trial_authorization::{
    GUEST_CAPTURE_LOCK, GUEST_OPERATION_LOCK, MANAGEMENT_INTENTS, MANAGEMENT_POLICY,
    MANAGEMENT_POLICY_BYTES, PEER_ENROLLMENT, PROMOTION_ENROLLMENT, management_binding,
    peer_partitions,
};

use crate::{invalid, run};

const HOST_STATE: &str = "os-update";
const GUEST_STATE: &str = "guest-os-update";
const FIRMWARE_STATE: &str = fvca_trial_authorization::firmware::STATE_DIRECTORY;
const HOST_DATA: &str = "/run/fvca/host-data";
const RUN: &str = "/run/fvca";
const SIGNED: &str = "/usr/lib/fvca";
const UNITS: &str = "/run/systemd/system";

pub fn publish_management_enrollment(cmdline: &str) -> io::Result<()> {
    let selected = management_binding(cmdline)?;
    let path = Path::new(SIGNED).join("management.json");
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound && selected.is_none() => {
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let meta = file.metadata()?;
    if !meta.is_file() || !(1..=MANAGEMENT_POLICY_BYTES as u64).contains(&meta.len()) {
        return Err(invalid("invalid signed Hypervisor management enrollment"));
    }
    let (expected, address) =
        selected.ok_or_else(|| invalid("missing signed management arguments"))?;
    let actual = crate::recovery::sha256(file.try_clone()?)?;
    if expected != actual {
        return Err(invalid(
            "Hypervisor management enrollment differs from its signed UKI",
        ));
    }
    for marker in [
        "/usr/lib/fvca/management-policy-v6",
        "/sysroot/usr/lib/fvca/management-services-v6",
    ] {
        let support = fs::symlink_metadata(marker)?;
        if !support.is_file() || support.len() != 0 {
            return Err(invalid(
                "the verified Hypervisor lacks confined management services",
            ));
        }
    }
    file.rewind()?;
    let mut enrollment = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(MANAGEMENT_POLICY)?;
    io::copy(&mut file, &mut enrollment)?;
    enrollment.flush()?;
    run(Command::new("/usr/bin/chcon").args([
        "--no-dereference",
        "system_u:object_r:fvca_management_enrollment_t:s0",
        MANAGEMENT_POLICY,
    ]))?;
    let state = Path::new(HOST_DATA).join(HOST_STATE);
    if owner_for(HOST_STATE)?.is_some() && state.try_exists()? {
        prepare_lock(Path::new(GUEST_CAPTURE_LOCK))?;
        let device = fs::metadata(HOST_DATA)?.dev();
        if !private_directory(&state.symlink_metadata()?, device) {
            return Err(invalid(
                "management intent state requires the authenticated Host pool",
            ));
        }
        let directory = Path::new(MANAGEMENT_INTENTS);
        match fs::DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => File::open(state)?.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
            Err(error) => return Err(error),
        }
        if !private_directory(&directory.symlink_metadata()?, device) {
            return Err(invalid("invalid private management intent directory"));
        }
        run(Command::new("/usr/bin/chcon").args([
            "--no-dereference",
            "system_u:object_r:fvca_management_intents_t:s0",
            MANAGEMENT_INTENTS,
        ]))?;
    }
    if let Err(error) = management_credentials() {
        eprintln!("FVCA_MANAGEMENT_CREDENTIALS_UNAVAILABLE {error}");
        return Ok(());
    }
    let dropin = Path::new(UNITS).join("fvca-management.socket.d");
    fs::create_dir_all(&dropin)?;
    fs::write(
        dropin.join("20-listener.conf"),
        format!("[Socket]\nListenStream={address}\n"),
    )?;
    let wants = Path::new(UNITS).join("fvca-base.target.wants");
    fs::create_dir_all(&wants)?;
    symlink(
        "/usr/lib/systemd/system/fvca-management.socket",
        wants.join("fvca-management.socket"),
    )?;
    println!("FVCA_MANAGEMENT_SOCKET_ENROLLED {address}");
    Ok(())
}

fn private_management_file(meta: &fs::Metadata, device: u64) -> bool {
    meta.is_file()
        && meta.uid() == 0
        && meta.gid() == 0
        && meta.nlink() == 1
        && meta.dev() == device
        && meta.mode() & 0o7777 == 0o600
}

fn management_credentials() -> io::Result<()> {
    let data = Path::new(HOST_DATA);
    let device = data.metadata()?.dev();
    let credentials = data.join("management");
    if !private_directory(&credentials.symlink_metadata()?, device) {
        return Err(invalid(
            "management credentials require a private Host pool directory",
        ));
    }
    for name in ["tls.crt", "tls.key"] {
        let meta = credentials.join(name).symlink_metadata()?;
        if !private_management_file(&meta, device) || !(1..=16 * 1024).contains(&meta.len()) {
            return Err(invalid("invalid private management credential file"));
        }
    }
    run(Command::new("/usr/bin/chcon")
        .args([
            "--no-dereference",
            "system_u:object_r:fvca_management_credentials_t:s0",
        ])
        .arg(credentials))
}

fn private_directory(meta: &fs::Metadata, device: u64) -> bool {
    meta.is_dir()
        && meta.uid() == 0
        && meta.gid() == 0
        && meta.mode() & 0o7777 == 0o700
        && meta.dev() == device
}

fn prepare_staging(name: &str) -> io::Result<()> {
    let data = Path::new(HOST_DATA);
    let state = data.join(name);
    let parent = state.symlink_metadata()?;
    let device = data.metadata()?.dev();
    if !private_directory(&parent, device) {
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
    if !private_directory(&staging.symlink_metadata()?, device) {
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
        if !private_directory(&inbox.symlink_metadata()?, device) {
            return Err(invalid(
                "Guest trial inbox must be private and on the authenticated pool",
            ));
        }
    }
    let mut label = Command::new("/usr/bin/chcon");
    label.arg("--no-dereference");
    if name == FIRMWARE_STATE {
        label
            .arg("system_u:object_r:fvca_firmware_state_t:s0")
            .arg(&state)
            .arg(&staging);
    } else {
        label
            .arg("system_u:object_r:fvca_os_stage_t:s0")
            .arg(staging);
    }
    run(&mut label)
}

fn prepare_firmware_history() -> io::Result<()> {
    let data = Path::new(HOST_DATA);
    let state = data.join(FIRMWARE_STATE);
    let history = state.join("history");
    match fs::DirBuilder::new().mode(0o700).create(&history) {
        Ok(()) => fs::File::open(&state)?.sync_all()?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error),
    }
    if !private_directory(&history.symlink_metadata()?, data.metadata()?.dev()) {
        return Err(invalid(
            "firmware history requires a private directory on the authenticated pool",
        ));
    }
    run(Command::new("/usr/bin/chcon")
        .args(["--no-dereference", "system_u:object_r:fwupd_var_lib_t:s0"])
        .arg(&history))?;
    let dropin = Path::new(UNITS).join("fvca-fwupd.service.d");
    fs::create_dir_all(&dropin)?;
    fs::write(
        dropin.join("20-history.conf"),
        format!(
            "[Unit]\nAfter=fvca-base-ready.service\nAssertPathIsMountPoint={HOST_DATA}\n\n[Service]\nEnvironment=FVCA_FWUPD_PERSISTENT_HISTORY=1\nReadWritePaths={}\n",
            history.display()
        ),
    )
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
    enable_unit(&format!("{service}.timer"))
}

fn enable_unit(unit: &str) -> io::Result<()> {
    let wants = Path::new(UNITS).join("fvca-base.target.wants");
    fs::create_dir_all(&wants)?;
    symlink(format!("/usr/lib/systemd/system/{unit}"), wants.join(unit))
}

fn prepare_firmware_control() -> io::Result<()> {
    prepare_lock(Path::new(GUEST_CAPTURE_LOCK))?;
    prepare_lock(Path::new(GUEST_OPERATION_LOCK))?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(fvca_trial_authorization::firmware::RUN_DIRECTORY)?;
    run(Command::new("/usr/bin/chcon")
        .args([
            "--no-dereference",
            "system_u:object_r:fvca_firmware_boot_input_t:s0",
        ])
        .arg(GUEST_CAPTURE_LOCK))
}

fn prepare_lock(lock: &Path) -> io::Result<()> {
    match fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(lock)
    {
        Ok(_) => (),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error),
    }
    let meta = fs::symlink_metadata(lock)?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.gid() != 0
        || meta.nlink() != 1
        || meta.mode() & 0o7777 != 0o600
    {
        return Err(invalid("invalid Host lifecycle lease file"));
    }
    Ok(())
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

pub struct FirmwareTpm {
    pub floor: u64,
    pub pcr7_sha256: String,
}

pub fn activate_firmware_if_selected(
    esp: &str,
    epoch: &str,
    runtime: &crate::runtime::Activation,
    filesystem: &str,
    storage_policy_sha256: &str,
    tpm: Option<&FirmwareTpm>,
    recovery: bool,
) -> io::Result<bool> {
    let Some(owner) = owner_for(FIRMWARE_STATE)? else {
        return Ok(false);
    };
    if let Err(error) = prepare_staging(FIRMWARE_STATE)
        .and_then(|()| prepare_firmware_history())
        .and_then(|()| prepare_firmware_control())
    {
        eprintln!("FVCA_HOST_FIRMWARE_ENROLLMENT_BLOCKED {error}");
        return Ok(false);
    }
    if let Err(error) = crate::hypervisor_trial::publish_firmware_esp(esp) {
        eprintln!("FVCA_HOST_FIRMWARE_ESP_BLOCKED {error}");
    }
    let boot = tpm
        .ok_or_else(|| invalid("missing initramfs TPM measurement for firmware continuity"))
        .and_then(|tpm| {
            crate::hypervisor_trial::publish_firmware_boot(
                esp,
                epoch,
                runtime,
                filesystem,
                storage_policy_sha256,
                tpm,
            )
        });
    if let Err(error) = boot {
        eprintln!("FVCA_HOST_FIRMWARE_BOOT_EVIDENCE_BLOCKED {error}");
    }
    publish_depot(FIRMWARE_STATE, "fvca-firmware-update", &owner)?;
    enable_unit("fvca-fwupd.service")?;
    enable_timer("fvca-firmware-update")?;
    if recovery {
        enable_unit("fvca-firmware-recovery.service")?;
    }
    println!("FVCA_HOST_FIRMWARE_TIMER_ENROLLED");
    Ok(true)
}
