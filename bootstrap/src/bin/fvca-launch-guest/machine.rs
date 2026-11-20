//! Render the fixed machine profile with the Host's admitted resource settings.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use fvca_initrd_bootstrap::{
    guest_resources::{self, Resources},
    host_workload, invalid,
};

const PROFILE: &str = include_str!("../../../../policy/guest-direct-boot.xml");
const COMMAND_LINE_LIMIT: u64 = 2048;
const MACHINE_LIMIT: u64 = 8192;

fn read(path: &Path, limit: u64) -> io::Result<String> {
    let mut text = String::new();
    File::open(path)?
        .take(limit + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > limit {
        return Err(invalid("Guest machine artifact exceeds its size bound"));
    }
    Ok(text)
}

fn signed_command_line(line: &str, core: &str) -> io::Result<String> {
    let line = line
        .strip_suffix('\n')
        .filter(|line| line.bytes().all(|byte| (b' '..=b'~').contains(&byte)))
        .ok_or_else(|| invalid("invalid approved Guest kernel command line"))?;
    let mut roots = line
        .split_ascii_whitespace()
        .filter_map(|word| word.strip_prefix("roothash="));
    if roots.next() != Some(core) || roots.next().is_some() {
        return Err(invalid(
            "Guest kernel command line differs from the selected core",
        ));
    }
    Ok(line
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;"))
}

fn profile(command_line: &str) -> String {
    PROFILE
        .trim_end_matches('\n')
        .replace("FVCA_SIGNED_COMMAND_LINE", command_line)
}

fn render(command_line: &str, boot: &Path, resources: Resources, mac: Option<&str>) -> String {
    // Rebind only paths from the fixed definition. The signed kernel command
    // line is added after path replacement.
    let template = match mac {
        Some(mac) => PROFILE.replace("  <devices>\n", &format!(
            "  <devices>\n\
             <interface type=\"ethernet\">\n\
               <mac address=\"{mac}\"/>\n\
               <target dev=\"{}\" managed=\"no\"/>\n\
               <model type=\"virtio-non-transitional\"/>\n\
               <driver name=\"qemu\"/>\n\
               <rom enabled=\"no\"/>\n\
               <address type=\"pci\" domain=\"0x0000\" bus=\"0x00\" slot=\"0x06\" function=\"0x0\"/>\n\
             </interface>\n", host_workload::TAP)),
        None => PROFILE.to_owned(),
    };
    template
        .trim_end_matches('\n')
        .replace("/run/fvca/guest-boot/", &format!("{}/", boot.display()))
        .replace(
            ">2048</memory>",
            &format!(">{}</memory>", resources.memory_mib),
        )
        .replace(">2</vcpu>", &format!(">{}</vcpu>", resources.vcpus))
        .replace("FVCA_SIGNED_COMMAND_LINE", command_line)
}

pub(super) fn verify(boot: &Path, core: &str) -> io::Result<(String, Option<String>)> {
    let command_line =
        signed_command_line(&read(&boot.join("cmdline"), COMMAND_LINE_LIMIT)?, core)?;
    if read(&boot.join("domain.xml"), MACHINE_LIMIT)? != profile(&command_line) {
        return Err(invalid(
            "the signed Guest machine differs from the fixed direct-boot profile",
        ));
    }
    let mac = host_workload::guest_mac(&command_line)?;
    Ok((command_line, mac))
}

pub(super) fn definition(boot: &Path, core: &str) -> io::Result<CString> {
    let (command_line, mac) = verify(boot, core)?;
    let resources = guest_resources::active()?;
    guest_resources::require_capacity(resources)?;
    CString::new(render(&command_line, boot, resources, mac.as_deref())).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_only_host_resources_and_selected_bundle_paths() -> io::Result<()> {
        let settings = Resources {
            vcpus: 3,
            memory_mib: 2560,
        };
        let line = signed_command_line("roothash=core example=<x>&y>z\n", "core")?;
        let boot = Path::new("/run/fvca/guest-releases/verified");
        let xml = render(&line, boot, settings, None);
        assert_eq!(xml.matches("/run/fvca/guest-releases/verified/").count(), 4);
        assert!(xml.contains("<memory unit=\"MiB\">2560</memory>"));
        assert!(xml.contains("<vcpu placement=\"static\">3</vcpu>"));
        assert!(xml.contains("<cmdline>roothash=core example=&lt;x&gt;&amp;y&gt;z</cmdline>"));
        assert!(!xml.contains("<interface"));
        let connected = render(&line, boot, settings, Some("52:54:00:10:20:30"));
        assert_eq!(connected.matches("<interface ").count(), 1);
        assert!(connected.contains("dev=\"fvca-wl-tap\" managed=\"no\""));
        assert!(connected.contains("slot=\"0x06\""));
        assert!(connected.contains("driver name=\"qemu\""));
        assert!(connected.contains("<rom enabled=\"no\"/>"));
        assert!(signed_command_line("roothash=other\n", "core").is_err());
        assert!(signed_command_line("roothash=core roothash=core\n", "core").is_err());
        assert!(signed_command_line("roothash=core \n\n", "core").is_err());
        Ok(())
    }
}
