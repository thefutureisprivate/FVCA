use std::fs;
use std::io;
use std::path::Path;

use crate::invalid;
use crate::selinux::require_enforcing_domain;

fn require(condition: bool, message: &str) -> io::Result<()> {
    if !condition {
        return Err(invalid(message));
    }
    Ok(())
}

fn field<'a>(status: &'a str, label: &str) -> Option<&'a str> {
    status.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key == label).then(|| value.trim())
    })
}

pub fn check_process(proc: &Path) -> io::Result<()> {
    let context = fs::read_to_string(proc.join("attr/current"))?;
    let context = context.trim_end_matches(['\0', '\n']);
    require(context.starts_with("system_u:system_r:svirt_t:s0:c"), "QEMU lacks an sVirt MCS label")?;
    require_enforcing_domain("system_u:system_r:virtqemud_t:s0")?;
    require_enforcing_domain(context)?;

    let status = fs::read_to_string(proc.join("status"))?;
    let uid = field(&status, "Uid").and_then(|value| value.split_ascii_whitespace().nth(1));
    require(uid == Some("107"), "QEMU has an unexpected effective UID")?;
    require(field(&status, "NoNewPrivs") == Some("1"), "QEMU lacks no-new-privileges")?;
    require(field(&status, "Seccomp") == Some("2"), "QEMU lacks a seccomp filter")?;
    require(field(&status, "CapEff") == Some("0000000000000000"), "QEMU retains capabilities")?;
    let namespace = fs::read_link(proc.join("ns/mnt"))?;
    require(namespace != fs::read_link("/proc/1/ns/mnt")?, "QEMU lacks a private mount namespace")?;
    println!("FVCA_KVM_GUEST_CONFINED {context}");
    Ok(())
}
