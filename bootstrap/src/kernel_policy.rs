//! Close boot-only kernel facilities before the verified runtime starts.

use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;

use crate::{invalid, run};

pub fn require_signed_modules() -> io::Result<()> {
    let lockdown = fs::read_to_string("/sys/kernel/security/lockdown")?;
    if !lockdown
        .split_ascii_whitespace()
        .any(|mode| matches!(mode, "[integrity]" | "[confidentiality]"))
        || fs::read_to_string("/sys/module/module/parameters/sig_enforce")? != "Y\n"
    {
        return Err(invalid(
            "the appliance requires kernel lockdown and enforced module signatures",
        ));
    }
    Ok(())
}

pub fn load_modules(modules: &[&str]) -> io::Result<()> {
    for module in modules {
        run(Command::new("/usr/bin/modprobe").args(["--ignore-install", module]))?;
    }
    Ok(())
}

const CONTROLS: [&str; 3] = [
    "unprivileged_bpf_disabled",
    "kexec_load_disabled",
    "modules_disabled",
];

pub fn seal() -> io::Result<()> {
    let kernel = Path::new("/proc/sys/kernel");
    for name in CONTROLS {
        let path = kernel.join(name);
        if fs::read_to_string(&path)? != "1\n" {
            fs::write(&path, "1\n")
                .map_err(|error| io::Error::new(error.kind(), format!("set {name}: {error}")))?;
        }
        if fs::read_to_string(&path)? != "1\n" {
            return Err(invalid(&format!(
                "kernel control {name} did not retain its required value"
            )));
        }
    }
    eprintln!("FVCA_KERNEL_POLICY_SEALED");
    Ok(())
}
