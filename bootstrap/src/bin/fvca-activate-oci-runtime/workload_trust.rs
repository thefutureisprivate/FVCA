use std::fs::{self, File};
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::process::Command;

use fvca_initrd_bootstrap::{WORKLOAD_VERITY_CERTIFICATE, direct_boot, invalid, run};

const SOURCE: &str = "/usr/lib/fvca";
const DESTINATION: &str = "/run/fvca/workload-trust";
const RING: &str = "%:.dm-verity";

pub fn enroll() -> io::Result<()> {
    let certificate = match File::open(WORKLOAD_VERITY_CERTIFICATE) {
        Ok(certificate) => certificate,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let policy = Path::new(SOURCE).join("workload-policy.json");
    let deployment = Path::new(SOURCE).join("workload-deployment.der");
    if !policy.is_file() || !deployment.is_file() {
        return Err(invalid("incomplete signed Guest workload trust configuration"));
    }
    if fs::read_to_string("/sys/module/dm_verity/parameters/keyring_unsealed")? != "Y\n"
        || fs::read_to_string("/sys/module/dm_verity/parameters/require_signatures")? != "Y\n"
    {
        return Err(invalid("unexpected kernel workload keyring configuration"));
    }

    if !Path::new(direct_boot::READY_IN_INITRD).try_exists()? {
        let added = run(Command::new("/usr/bin/keyctl")
            .args(["padd", "asymmetric", "", RING])
            .stdin(certificate));
        let sealed = run(Command::new("/usr/bin/keyctl").args(["restrict_keyring", RING]));
        added?;
        sealed?;
        run(Command::new("/usr/bin/modprobe").args(["--ignore-install", "loop"]))?;
    }

    let destination = Path::new(DESTINATION);
    fs::DirBuilder::new().mode(0o700).create(destination)?;
    for (source, name) in [
        (policy.as_path(), "policy.json"),
        (deployment.as_path(), "deployment.der"),
        (Path::new(WORKLOAD_VERITY_CERTIFICATE), "verity.der"),
    ] {
        fs::copy(source, destination.join(name))?;
    }
    println!("FVCA_WORKLOAD_KEYRING_SEALED");
    Ok(())
}
