use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use crate::{find_partition, invalid, run};

pub enum Runtime {
    Vm,
    Oci,
}

pub fn hash(value: &str) -> io::Result<&str> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(invalid("expected a lowercase SHA-256 root hash"));
    }
    Ok(value)
}

fn composition<'a>(manifest: &'a str, role: &str, runtime: &str) -> io::Result<(&'a str, &'a str)> {
    let fields: Vec<_> = manifest.split('\n').collect();
    let [header, selected_role, selected_runtime, core, extension, ""] = fields.as_slice() else {
        return Err(invalid("malformed composition"));
    };
    if *header != "FVCA-DEVELOPMENT-1"
        || selected_role.strip_prefix("role=") != Some(role)
        || selected_runtime.strip_prefix("runtime=") != Some(runtime)
    {
        return Err(invalid("the runtime composition does not match the boot role"));
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

fn runtime_devices(root_hash: &str, name: &str) -> io::Result<(PathBuf, PathBuf)> {
    let data_uuid = uuid(&root_hash[..32]);
    let tree_uuid = uuid(&root_hash[32..]);
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        if let (Some(data), Some(tree)) = (find_partition(&data_uuid)?, find_partition(&tree_uuid)?) {
            return Ok((data, tree));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("authorized {name} runtime partitions are missing")));
        }
        thread::sleep(Duration::from_millis(200));
    }
}

pub fn install_development_probe(name: &str, content: &str) -> io::Result<()> {
    let dependencies = "/run/systemd/system/fvca-base-ready.service.requires";
    fs::create_dir_all(dependencies)?;
    fs::write(format!("/run/systemd/system/{name}"), content)?;
    symlink(
        format!("../{name}"),
        format!("{dependencies}/{name}"),
    )
}

pub fn activate(selected: Runtime) -> io::Result<String> {
    let (role, runtime, label) = match selected {
        Runtime::Vm => ("hypervisor", "vm-runtime", "VM"),
        Runtime::Oci => ("service-guest", "oci-runtime", "OCI"),
    };
    let manifest = fs::read_to_string(format!("/usr/lib/fvca/{role}.composition"))?;
    let (core_hash, runtime_hash) = composition(&manifest, role, runtime)?;
    require_core(&fs::read_to_string("/proc/cmdline")?, core_hash)?;
    let (data, tree) = runtime_devices(runtime_hash, label)?;

    let mapping = format!("fvca-{runtime}");
    let staging = format!("/run/fvca/{runtime}");
    let signature = format!("/usr/lib/fvca/{runtime}.p7s");
    fs::create_dir_all(&staging)?;
    run(Command::new("/usr/lib/systemd/systemd-veritysetup")
        .args(["attach", &mapping])
        .arg(data)
        .arg(tree)
        .args([runtime_hash, &format!("panic-on-corruption,root-hash-signature={signature}")]))?;
    run(Command::new("/usr/bin/mount").args([
        "-t", "erofs", "-o", "ro,nodev,nosuid", &format!("/dev/mapper/{mapping}"), &staging,
    ]))?;

    let binding = fs::read_to_string(format!("{staging}/usr/share/fvca/{runtime}-base.roothash"))?;
    if binding.strip_suffix('\n') != Some(core_hash) {
        return Err(invalid("verified runtime was built for a different core"));
    }
    // The two signed layers are audited for set-ID bits and file capabilities.
    // Fedora's existing service-domain transitions must also work through /usr.
    run(Command::new("/usr/bin/mount").args([
        "-t", "overlay", "-o",
        &format!("ro,nodev,redirect_dir=nofollow,metacopy=off,lowerdir={staging}/usr:/sysroot/usr"),
        &mapping, "/sysroot/usr",
    ]))?;
    Ok(runtime_hash.to_owned())
}
