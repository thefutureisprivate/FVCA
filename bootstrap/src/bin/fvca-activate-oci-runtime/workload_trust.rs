use std::fs::{self, File};
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::process::Command;

use fvca_initrd_bootstrap::{WORKLOAD_VERITY_CERTIFICATE, direct_boot, invalid, run};

const SOURCE: &str = "/usr/lib/fvca";
const DESTINATION: &str = "/run/fvca/workload-trust";
const RING: &str = "%:.dm-verity";
const CHANNEL_FILES: [&str; 4] = [
    "channel-policy.json",
    "channel-root.json",
    "channel-depot.json",
    "channel-ca.pem",
];

pub fn enroll() -> io::Result<bool> {
    let certificate = match File::open(WORKLOAD_VERITY_CERTIFICATE) {
        Ok(certificate) => certificate,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let policy = Path::new(SOURCE).join("workload-policy.json");
    let deployment = Path::new(SOURCE).join("workload-deployment.der");
    if !policy.is_file() || !deployment.is_file() {
        return Err(invalid(
            "incomplete signed Guest workload trust configuration",
        ));
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
    let source = Path::new(SOURCE);
    let channel_policy = source.join("workload-channel-policy.json");
    if channel_policy.try_exists()? {
        for name in CHANNEL_FILES {
            fs::copy(
                source.join(format!("workload-{name}")),
                destination.join(name),
            )?;
        }
    } else {
        for name in CHANNEL_FILES[1..].iter() {
            if source.join(format!("workload-{name}")).try_exists()? {
                return Err(invalid("incomplete signed workload channel enrollment"));
            }
        }
    }
    println!("FVCA_WORKLOAD_KEYRING_SEALED");
    Ok(true)
}
