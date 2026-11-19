#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::Path;
use std::process::{Command, ExitCode};

use fvca_workload_admission::{Scope, Trust, read_bounded, verify};
use openssl::x509::X509;

const GUEST_DATA: &str = "/run/fvca/guest-data";
const BUNDLE: &str = "/run/fvca/guest-data/workload";
const TRUST: &str = "/run/fvca/workload-trust";
const DIRECTORY: &str = "/run/fvca/workload-image";
const SIGNATURE: &str = "/run/fvca/workload-image/root.p7s";
const ROOT: &str = "/run/fvca/workload-image/root";
const MAPPING: &str = "fvca-workload-root";
const MAPPER: &str = "/dev/mapper/fvca-workload-root";
const VERITYSETUP: &str = "/usr/lib/systemd/systemd-veritysetup";

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

fn private_directory(path: &str) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(io::Error::other(format!(
            "{path} must be a root-owned 0700 directory"
        )));
    }
    Ok(())
}

fn read_trust() -> Result<Trust> {
    private_directory(TRUST)?;
    let directory = Path::new(TRUST);
    let scope: Scope =
        serde_json::from_slice(&read_bounded(&directory.join("policy.json"), 1024 * 1024)?)?;
    let deployment = X509::from_der(&read_bounded(&directory.join("deployment.der"), 16 * 1024)?)?;
    let workload = X509::from_der(&read_bounded(&directory.join("verity.der"), 16 * 1024)?)?;
    Trust::new(scope, deployment, workload)
}

fn mount_workload() -> Result<()> {
    run(Command::new("/usr/bin/findmnt")
        .args([
            "--mountpoint",
            GUEST_DATA,
            "--types",
            "btrfs",
            "--options",
            "rw,nodev,nosuid,noexec",
        ])
        .stdout(std::process::Stdio::null()))?;
    private_directory(GUEST_DATA)?;
    private_directory(BUNDLE)?;
    let verified = verify(Path::new(BUNDLE), &read_trust()?)?;
    let hash = verified.verity_root_hash().to_owned();
    let service = verified.service().to_owned();
    let (artifact, image) = verified.into_artifact();

    // No kernel partition discovery. Both loops use the verified descriptor and bounded offsets.
    let root = fvca_workload_loop::attach(&artifact, image.root.offset, image.root.size).map_err(
        |error| io::Error::other(format!("cannot attach the workload data region: {error}")),
    )?;
    let tree = fvca_workload_loop::attach(&artifact, image.verity.offset, image.verity.size)
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
    println!("FVCA_WORKLOAD_ROOT_ACTIVE {service} {hash}");
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
        result => result?,
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
    let mut arguments = std::env::args_os().skip(1);
    let command = arguments.next().filter(|_| arguments.next().is_none());
    match command.as_ref().and_then(|value| value.to_str()) {
        Some("mount") => mount_workload(),
        Some("unmount") => unmount_workload(),
        _ => Err(io::Error::other("expected workload mount or unmount").into()),
    }
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
