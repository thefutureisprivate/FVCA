//! Enable the Host update timer only for the enrollment carried by the signed UKI.

use std::fs;
use std::io;
use std::net::IpAddr;
use std::os::unix::fs::symlink;
use std::path::Path;

use crate::invalid;

const OWNER: &str = "os-update-owner";
const DEPOT: &str = "os-update-depot";
const CA: &str = "os-update-ca.pem";
const TIMER: &str = "fvca-host-update.timer";

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
    let depot = fs::read_to_string(signed.join(DEPOT))?;
    let run = Path::new("/run/fvca");
    let units = Path::new("/run/systemd/system");
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
        let dropin = units.join("fvca-host-update.service.d");
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
