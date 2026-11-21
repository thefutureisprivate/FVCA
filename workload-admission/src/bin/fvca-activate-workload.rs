#![forbid(unsafe_code)]

use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, chown};
use std::path::Path;
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use fvca_workload_admission::quadlet::{self, Definition, NAMESPACE, PAYLOAD, ROOT, SERVICE};
use fvca_workload_admission::{Trust, VerifiedWorkload, channel, read_bounded};

#[path = "activate-workload/permit.rs"]
mod permit;
#[path = "activate-workload/stage.rs"]
mod stage;
#[path = "activate-workload/trial.rs"]
mod trial;

const GUEST_DATA: &str = "/run/fvca/guest-data";
const BUNDLE: &str = "/run/fvca/guest-data/workload";
const TRUST: &str = "/run/fvca/workload-trust";
const DIRECTORY: &str = "/run/fvca/workload-image";
const MOUNTED_AUTHORIZATION: &str = "/run/fvca/workload-image/authorization";
const LIFECYCLE_LOCK: &str = "/run/fvca/workload-lifecycle.lock";
const SIGNATURE: &str = "/run/fvca/workload-image/root.p7s";
const MAPPING: &str = "fvca-workload-root";
const MAPPER: &str = "/dev/mapper/fvca-workload-root";
const VERITYSETUP: &str = "/usr/lib/systemd/systemd-veritysetup";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const UNIT_PATH: &str = "/run/systemd/system/fvca-workload-payload.service";
const QUADLET_DIR: &str = "/run/fvca/workload-image/quadlet";
const GENERATED_UNIT: &str = "/run/fvca/workload-image/quadlet/units/fvca-workload-payload.service";
const PUBLISHED_UNIT: &str = "/run/fvca/workload-image/fvca-workload-payload.service";
const OS_UNIT_DEFAULTS: &str = "/usr/lib/systemd/system/service.d/10-timeout-abort.conf";
const KERNEL_SERVICE_POLICY: &str =
    "/usr/lib/systemd/system/service.d/60-fvca-kernel-observability.conf";
const NETWORK: &str = "/run/fvca/workload-network";

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn run(command: &mut Command) -> io::Result<()> {
    let status = command.env_clear().status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "{:?} exited with {status}",
            command.get_program()
        )));
    }
    Ok(())
}

fn private_directory(path: impl AsRef<Path>) -> io::Result<fs::Metadata> {
    let path = path.as_ref();
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(io::Error::other(format!(
            "{} must be a root-owned 0700 directory",
            path.display()
        )));
    }
    Ok(metadata)
}

fn make_directory(path: &str) -> io::Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            private_directory(path).map(|_| ())
        }
        other => other,
    }
}

fn lifecycle_file() -> Result<File> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(LIFECYCLE_LOCK)?;
    let metadata = lock.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(io::Error::other("invalid Guest workload lifecycle lease").into());
    }
    Ok(lock)
}

fn provision_volumes(service: &str, definition: &Definition) -> Result<()> {
    make_directory(PAYLOAD)?;
    let base = format!("{PAYLOAD}/{service}");
    make_directory(&base)?;
    for volume in &definition.volumes {
        let path = Path::new(&base).join(&volume.name);
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            result => result?,
        }
        let state = fs::symlink_metadata(&path)?;
        if !state.is_dir() || state.mode() & 0o7777 != 0o700 {
            return Err(io::Error::other("invalid persistent workload volume directory").into());
        }
        let ownership = (state.uid(), state.gid());
        if ownership == (0, 0) && fs::read_dir(&path)?.next().is_none() {
            chown(&path, Some(volume.uid), Some(volume.gid))?;
        } else if ownership != (volume.uid, volume.gid) {
            return Err(io::Error::other(
                "persistent volume identity does not match the signed mapping",
            )
            .into());
        }
    }
    Ok(())
}

fn publish_unit(definition: &Definition) -> Result<()> {
    let input = format!("{QUADLET_DIR}/source");
    let output = format!("{QUADLET_DIR}/units");
    for path in [QUADLET_DIR, &input, &output] {
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    fs::write(
        format!("{input}/{}.container", quadlet::CONTAINER),
        &definition.source,
    )?;
    // Explicitly select the private source. The appliance ships no automatic Quadlet generator.
    let status = Command::new("/usr/libexec/podman/quadlet")
        .env_clear()
        .env("QUADLET_UNIT_DIRS", &input)
        .args(["-no-kmsg-log", &output, &output, &output])
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!("Quadlet exited with {status}")).into());
    }
    let compiled = read_bounded(Path::new(GENERATED_UNIT), 4 * 1024 * 1024)?;
    // Quadlet renames its temporary output. Create the reserved fragment by
    // name so SELinux gives it the systemd unit type before PID 1 can load it.
    let mut fragment = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(PUBLISHED_UNIT)?;
    fragment.write_all(&compiled)?;
    fragment.set_permissions(fs::Permissions::from_mode(0o644))?;
    fs::hard_link(PUBLISHED_UNIT, UNIT_PATH).map_err(|error| {
        io::Error::other(format!(
            "cannot publish the generated workload unit: {error}"
        ))
    })?;
    Ok(())
}

fn same_unit() -> io::Result<bool> {
    let generated = fs::symlink_metadata(PUBLISHED_UNIT)?;
    let loaded = fs::symlink_metadata(UNIT_PATH)?;
    Ok(generated.is_file()
        && loaded.is_file()
        && (generated.dev(), generated.ino()) == (loaded.dev(), loaded.ino()))
}

fn approved_unit(output: &str) -> bool {
    let mut fragments = output
        .lines()
        .filter_map(|line| line.strip_prefix("FragmentPath="));
    let mut overrides = output
        .lines()
        .filter_map(|line| line.strip_prefix("DropInPaths="));
    let with_defaults = format!("{OS_UNIT_DEFAULTS} {KERNEL_SERVICE_POLICY}");
    fragments.next() == Some(UNIT_PATH)
        && fragments.next().is_none()
        && overrides
            .next()
            .is_some_and(|paths| paths == KERNEL_SERVICE_POLICY || paths == with_defaults)
        && overrides.next().is_none()
}

fn check_workload_unit() -> Result<()> {
    if !same_unit()? {
        return Err(io::Error::other(
            "the published workload service differs from the generated service",
        )
        .into());
    }
    let result = Command::new(SYSTEMCTL)
        .env_clear()
        .args(["show", "--property=FragmentPath,DropInPaths", SERVICE])
        .output()?;
    if !result.status.success() {
        return Err(io::Error::other(format!(
            "could not inspect the loaded workload service: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        ))
        .into());
    }
    if !approved_unit(&String::from_utf8(result.stdout)?) {
        return Err(io::Error::other(
            "workload service was overridden outside the verified policy",
        )
        .into());
    }
    Ok(())
}

fn start_workload(replace: bool) -> Result<()> {
    run(Command::new(SYSTEMCTL).arg("daemon-reload"))?;
    check_workload_unit()?;
    if replace
        && Command::new(SYSTEMCTL)
            .env_clear()
            .args(["is-failed", "--quiet", SERVICE])
            .status()?
            .success()
    {
        run(Command::new(SYSTEMCTL).args(["reset-failed", SERVICE]))?;
    }
    run(Command::new(SYSTEMCTL).args(["start", SERVICE]))?;
    run(Command::new(SYSTEMCTL).args(["is-active", "--quiet", SERVICE]))?;
    println!("FVCA_WORKLOAD_STARTED");
    Ok(())
}

fn boot_workload() -> Result<()> {
    if Path::new(TRUST).join(channel::POLICY).try_exists()? {
        make_directory(stage::STORE)?;
    }
    start_workload(false)?;
    trial::recover()
}

fn stop_workload() -> Result<()> {
    match fs::symlink_metadata(UNIT_PATH) {
        Ok(_) => {
            check_workload_unit()?;
            run(Command::new(SYSTEMCTL).args(["stop", SERVICE]))?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn admitted_network(profile: Option<&str>) -> Result<Option<Ipv4Addr>> {
    let Some(profile) = profile else {
        return Ok(None);
    };
    let metadata = fs::symlink_metadata(NETWORK)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(
            io::Error::other("expected the protected Guest workload network enrollment").into(),
        );
    }
    let raw = String::from_utf8(read_bounded(Path::new(NETWORK), 128)?)?;
    let prefix = format!("profile={profile}\ndns=");
    let dns = raw
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or_else(|| {
            io::Error::other("the Guest network differs from the approved workload profile")
        })?;
    let mounted = Command::new("/usr/bin/findmnt")
        .env_clear()
        .args([
            "--mountpoint",
            NAMESPACE,
            "--noheadings",
            "--raw",
            "--output",
            "FSTYPE",
        ])
        .output()?;
    if !mounted.status.success() || mounted.stdout != b"nsfs\n" {
        return Err(
            io::Error::other("the approved workload network namespace is unavailable").into(),
        );
    }
    match dns {
        "none" => Ok(None),
        address => Ok(Some(address.parse()?)),
    }
}

fn check_start(
    valid_from: &str,
    expires: &str,
    provenance: &str,
    authorization: &str,
    profile: &str,
) -> Result<()> {
    let valid_from = valid_from.parse::<u64>()?;
    let expires = expires.parse::<u64>()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if !matches!(
        provenance,
        "PUBLISHER_VERIFIED" | "UNSIGNED_UPSTREAM_APPROVED"
    ) || !(valid_from..expires).contains(&now)
    {
        return Err(io::Error::other(format!(
            "{provenance} workload is outside its authorized start period"
        ))
        .into());
    }
    if stage::mounted_authorization()?.as_deref() != Some(authorization) {
        return Err(io::Error::other(
            "loaded workload service differs from the mounted authorization",
        )
        .into());
    }
    if provenance == "UNSIGNED_UPSTREAM_APPROVED" {
        permit::check_start(authorization, valid_from, expires)?;
    }
    admitted_network((profile != "none").then_some(profile))?;
    run(Command::new("/usr/bin/findmnt")
        .args([
            "--mountpoint",
            ROOT,
            "--types",
            "erofs",
            "--source",
            MAPPER,
            "--options",
            "ro,nodev,nosuid",
        ])
        .stdout(std::process::Stdio::null()))?;
    Ok(())
}

fn read_trust(device: u64) -> Result<Trust> {
    private_directory(TRUST)?;
    Trust::from_directory(Path::new(TRUST))?.with_permit_revocations(Path::new(GUEST_DATA), device)
}

fn require_guest_data(options: &str) -> Result<fs::Metadata> {
    run(Command::new("/usr/bin/findmnt")
        .args([
            "--mountpoint",
            GUEST_DATA,
            "--types",
            "btrfs",
            "--options",
            options,
        ])
        .stdout(std::process::Stdio::null()))?;
    Ok(private_directory(GUEST_DATA)?)
}

fn mount_workload() -> Result<()> {
    let data = require_guest_data("rw,nodev,nosuid,noexec")?;
    mount_verified(&stage::verify_selection(
        Path::new(stage::STORE),
        &read_trust(data.dev())?,
        data.dev(),
    )?)
}

fn mount_verified(verified: &VerifiedWorkload) -> Result<()> {
    let dns = admitted_network(verified.network_profile())?;
    let definition = quadlet::render(verified, dns)?;
    let hash = verified.verity_root_hash().to_owned();
    let authorization = verified.authorization_digest().to_owned();
    let service = verified.service().to_owned();
    provision_volumes(&service, &definition)?;
    let (artifact, image) = verified.artifact();

    // No kernel partition discovery. Both loops use the verified descriptor and bounded offsets.
    let root = fvca_workload_loop::attach(artifact, image.root.offset, image.root.size).map_err(
        |error| io::Error::other(format!("cannot attach the workload data region: {error}")),
    )?;
    let tree = fvca_workload_loop::attach(artifact, image.verity.offset, image.verity.size)
        .map_err(|error| {
            io::Error::other(format!("cannot attach the workload hash region: {error}"))
        })?;
    fs::DirBuilder::new().mode(0o700).create(DIRECTORY)?;
    fs::create_dir(ROOT)?;
    fs::write(SIGNATURE, &image.signature)?;
    run(Command::new(VERITYSETUP)
        .args(["attach", MAPPING])
        .arg(root.path())
        .arg(tree.path())
        .arg(&hash)
        .arg(format!(
            "panic-on-corruption,root-hash-signature={SIGNATURE}"
        )))?;
    run(Command::new("/usr/bin/mount").args([
        "--internal-only",
        "-t",
        "erofs",
        "-o",
        "ro,nodev,nosuid",
        MAPPER,
        ROOT,
    ]))?;
    let mut identity = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(MOUNTED_AUTHORIZATION)?;
    writeln!(identity, "{authorization}")?;
    permit::record(verified)?;
    publish_unit(&definition)?;
    println!("FVCA_WORKLOAD_ROOT_ACTIVE {service} {hash} {authorization}");
    println!(
        "FVCA_WORKLOAD_SOURCE {service} {} {} {}",
        verified.provenance().label(),
        verified.permit_id().unwrap_or("none"),
        verified.expires()
    );
    Ok(())
}

fn remove_missing(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

fn unmount_workload() -> Result<()> {
    match private_directory(DIRECTORY) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(_) => (),
    }
    if fs::read_to_string("/proc/self/mountinfo")?
        .lines()
        .any(|line| line.split_ascii_whitespace().nth(4) == Some(ROOT))
    {
        run(Command::new("/usr/bin/umount").args(["--internal-only", ROOT]))?;
    }
    if Path::new(MAPPER).try_exists()? {
        run(Command::new(VERITYSETUP).args(["detach", MAPPING]))?;
    }
    match same_unit() {
        Ok(true) => fs::remove_file(UNIT_PATH)?,
        Ok(false) => {
            return Err(io::Error::other("workload service changed after publication").into());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    remove_missing(fs::remove_dir_all(QUADLET_DIR))?;
    remove_missing(fs::remove_file(PUBLISHED_UNIT))?;
    remove_missing(fs::remove_file(MOUNTED_AUTHORIZATION))?;
    permit::clear()?;
    remove_missing(fs::remove_file(SIGNATURE))?;
    remove_missing(fs::remove_dir(ROOT))?;
    fs::remove_dir(DIRECTORY)?;
    Ok(())
}

fn execute() -> Result<()> {
    if fs::read_to_string("/usr/lib/fvca/role")? != "service-guest\n" {
        return Err(io::Error::other(
            "workload activation requires the verified Service Guest role",
        )
        .into());
    }
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let command: Vec<_> = arguments.iter().map(String::as_str).collect();
    if let [
        "check-start",
        valid_from,
        expires,
        provenance,
        authorization,
        profile,
    ] = command.as_slice()
    {
        return check_start(valid_from, expires, provenance, authorization, profile);
    }
    if command == ["monitor-permit"] {
        return permit::monitor();
    }
    let operation: fn() -> Result<()> = match command.as_slice() {
        ["mount"] => mount_workload,
        ["unmount"] => unmount_workload,
        ["start"] => boot_workload,
        ["stage"] => stage::run,
        ["trial"] => trial::run,
        ["recover"] => trial::recover,
        _ => return Err(io::Error::other("invalid workload activation operation").into()),
    };
    let lease = lifecycle_file()?;
    lease.try_lock()?;
    operation()
}

fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("FVCA workload root activation failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_unit_requires_the_verified_kernel_policy() {
        for paths in [
            KERNEL_SERVICE_POLICY.to_owned(),
            format!("{OS_UNIT_DEFAULTS} {KERNEL_SERVICE_POLICY}"),
        ] {
            assert!(approved_unit(&format!(
                "FragmentPath={UNIT_PATH}\nDropInPaths={paths}\n"
            )));
        }
        for paths in [
            String::new(),
            OS_UNIT_DEFAULTS.to_owned(),
            format!("{KERNEL_SERVICE_POLICY} /run/systemd/system/service.d/local.conf"),
            KERNEL_SERVICE_POLICY.replacen("/usr/lib/", "/etc/", 1),
            format!("{KERNEL_SERVICE_POLICY}\nDropInPaths={KERNEL_SERVICE_POLICY}"),
        ] {
            assert!(!approved_unit(&format!(
                "FragmentPath={UNIT_PATH}\nDropInPaths={paths}\n"
            )));
        }
        assert!(!approved_unit(&format!(
            "FragmentPath=/etc/systemd/system/fvca-workload-payload.service\nDropInPaths={KERNEL_SERVICE_POLICY}\n"
        )));
    }
}
