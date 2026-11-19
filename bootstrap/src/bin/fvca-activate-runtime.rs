#![forbid(unsafe_code)]

use std::alloc::System;
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, symlink};
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[global_allocator]
static ALLOCATOR: System = System;

const COMPOSITION: &str = "/usr/lib/fvca/hypervisor.composition";
const SIGNATURE: &str = "/usr/lib/fvca/vm-runtime.p7s";
const MAPPING: &str = "fvca-vm-runtime";
const STAGING: &str = "/run/fvca/vm-runtime";
const PROBE: &str = include_str!("../../../tests/fvca-vm-runtime-probe.service");

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn hash(value: &str) -> io::Result<&str> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(invalid("expected a lowercase SHA-256 root hash"));
    }
    Ok(value)
}

fn composition(manifest: &str) -> io::Result<(&str, &str)> {
    let fields: Vec<_> = manifest.split('\n').collect();
    let [header, role, runtime, core, extension, ""] = fields.as_slice() else {
        return Err(invalid("malformed composition"));
    };
    if (*header, *role, *runtime) != ("FVCA-DEVELOPMENT-1", "role=hypervisor", "runtime=vm-runtime") {
        return Err(invalid("expected the Hypervisor VM development composition"));
    }
    let core = core.strip_prefix("core=").ok_or_else(|| invalid("missing core root hash"))?;
    let extension = extension
        .strip_prefix("runtime_root=")
        .ok_or_else(|| invalid("missing runtime root hash"))?;
    Ok((hash(core)?, hash(extension)?))
}

fn require_core(cmdline: &str, expected_hash: &str) -> io::Result<()> {
    let mut hashes = cmdline.split_ascii_whitespace().filter_map(|part| part.strip_prefix("roothash="));
    if hashes.next() != Some(expected_hash) || hashes.next().is_some() {
        return Err(invalid("core root hash does not match the UKI composition"));
    }
    Ok(())
}

fn uuid(hex: &str) -> String {
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

fn find_partition(uuid: &str) -> io::Result<Option<PathBuf>> {
    let output = Command::new("/usr/bin/blkid")
        .env_clear()
        .args(["-c", "/dev/null", "-t", &format!("PARTUUID={uuid}"), "-o", "device"])
        .stderr(Stdio::inherit())
        .output()?;
    if output.status.code() == Some(2) {
        return Ok(None);
    }
    if !output.status.success() {
        return Err(io::Error::other(format!("blkid exited with {}", output.status)));
    }
    let list = std::str::from_utf8(&output.stdout).map_err(|_| invalid("invalid partition list"))?;
    let mut paths = list.lines();
    let path = paths.next().ok_or_else(|| invalid("empty partition list"))?;
    if paths.next().is_some() {
        return Err(invalid("more than one device has the authorized partition UUID"));
    }
    let path = PathBuf::from(path);
    if !path.starts_with("/dev") || !fs::metadata(&path)?.file_type().is_block_device() {
        return Err(invalid("runtime partition is not a block device"));
    }
    Ok(Some(path))
}

fn runtime_devices(root_hash: &str) -> io::Result<(PathBuf, PathBuf)> {
    let data_uuid = uuid(&root_hash[..32]);
    let tree_uuid = uuid(&root_hash[32..]);
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        if let (Some(data), Some(tree)) = (find_partition(&data_uuid)?, find_partition(&tree_uuid)?) {
            return Ok((data, tree));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::NotFound, "authorized VM runtime partitions are missing"));
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn run(command: &mut Command) -> io::Result<()> {
    let status = command.env_clear().status()?;
    if !status.success() {
        return Err(io::Error::other(format!("{:?} exited with {status}", command.get_program())));
    }
    Ok(())
}

fn install_development_probe() -> io::Result<()> {
    let dependencies = "/run/systemd/system/fvca-base-ready.service.requires";
    fs::create_dir_all(dependencies)?;
    fs::write("/run/systemd/system/fvca-vm-runtime-probe.service", PROBE)?;
    symlink(
        "../fvca-vm-runtime-probe.service",
        format!("{dependencies}/fvca-vm-runtime-probe.service"),
    )
}

fn activate() -> io::Result<()> {
    fvca_allocator_binding::require_allocator()?;
    if fs::read_to_string("/sys/module/kvm_intel/parameters/nested")?.trim_end() != "N"
        || !fs::metadata("/dev/kvm")?.file_type().is_char_device()
    {
        return Err(invalid("Intel KVM must be available with nested virtualization disabled"));
    }
    let manifest = fs::read_to_string(COMPOSITION)?;
    let (core_hash, runtime_hash) = composition(&manifest)?;
    require_core(&fs::read_to_string("/proc/cmdline")?, core_hash)?;
    let (data, tree) = runtime_devices(runtime_hash)?;

    fs::create_dir_all(STAGING)?;
    run(Command::new("/usr/lib/systemd/systemd-veritysetup")
        .args(["attach", MAPPING])
        .arg(data)
        .arg(tree)
        .args([runtime_hash, &format!("panic-on-corruption,root-hash-signature={SIGNATURE}")]))?;
    run(Command::new("/usr/bin/mount").args([
        "-t", "erofs", "-o", "ro,nodev,nosuid", "/dev/mapper/fvca-vm-runtime", STAGING,
    ]))?;

    let binding = fs::read_to_string(format!("{STAGING}/usr/share/fvca/vm-runtime-base.roothash"))?;
    if binding.strip_suffix('\n') != Some(core_hash) {
        return Err(invalid("verified VM runtime was built for a different core"));
    }
    // The two signed layers are audited for set-ID bits and file capabilities.
    // Fedora's existing service-domain transitions must also work through /usr.
    run(Command::new("/usr/bin/mount").args([
        "-t", "overlay", "-o",
        "ro,nodev,redirect_dir=nofollow,metacopy=off,lowerdir=/run/fvca/vm-runtime/usr:/sysroot/usr",
        "fvca-vm-runtime", "/sysroot/usr",
    ]))?;
    install_development_probe()?;

    println!("FVCA_VM_RUNTIME_ACTIVE {runtime_hash}");
    Ok(())
}

fn main() -> ExitCode {
    if let Err(error) = activate() {
        eprintln!("FVCA VM runtime activation failed: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
