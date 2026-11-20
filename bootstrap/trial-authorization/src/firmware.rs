//! Persistent firmware activation fence shared across Host boots and services.

use std::fs;
use std::io;
use std::path::Path;

pub const STATE_DIRECTORY: &str = "firmware-update";
pub const ACTIVATION: &str = "activation.json";
pub const VERIFIED_BOOT: &str = "/run/fvca/firmware-verified-boot";
pub const VERIFIED_BOOT_LIMIT: u64 = 640;
pub const DRAIN_RECEIPT: &str = "firmware-guest-drained";
const HOST_DATA: &str = "/run/fvca/host-data";

pub fn drain_receipt(boot: &str, transaction: &str, offer: &str) -> io::Result<String> {
    let boot = crate::uuid(boot)?;
    let transaction = crate::uuid(transaction)?;
    let offer = crate::digest(offer, "")?;
    Ok(format!(
        "FVCA-FIRMWARE-DRAIN-1\nboot_id={boot}\ntransaction={transaction}\noffer_sha256={offer}\n"
    ))
}

pub struct VerifiedBoot<'a> {
    pub boot_id: &'a str,
    pub esp: &'a str,
    pub core: &'a str,
    pub runtime: &'a str,
    pub epoch: u64,
    pub epoch_policy_sha256: &'a str,
    pub tpm_floor: u64,
    pub pcr7_sha256: &'a str,
    pub filesystem: &'a str,
    pub storage_policy_sha256: &'a str,
}

impl<'a> VerifiedBoot<'a> {
    pub fn parse(text: &'a str) -> io::Result<Self> {
        use crate::{digest, invalid, number, uuid};

        let lines: Vec<_> = text.split('\n').collect();
        let [
            "FVCA-FIRMWARE-BOOT-2",
            boot,
            esp,
            core,
            runtime,
            epoch,
            floor,
            pcr7,
            filesystem,
            storage,
            "",
        ] = lines.as_slice()
        else {
            return Err(invalid("invalid verified firmware boot receipt"));
        };
        let identifier = |line: &'a str, name: &str| {
            let value = line
                .strip_prefix(name)
                .filter(|value| {
                    !matches!(
                        *value,
                        "00000000-0000-0000-0000-000000000000"
                            | "ffffffff-ffff-ffff-ffff-ffffffffffff"
                    )
                })
                .ok_or_else(|| invalid("invalid verified firmware boot identifier"))?;
            uuid(value)
        };
        let (epoch, policy) = epoch
            .split_once(',')
            .ok_or_else(|| invalid("invalid verified firmware boot epoch"))?;
        let epoch = number(epoch, "epoch=")?;
        let tpm_floor = number(floor, "tpm_floor=")?;
        let pcr7_sha256 = digest(pcr7, "pcr7_sha256=")?;
        if tpm_floor > epoch || pcr7_sha256.bytes().all(|byte| byte == b'0') {
            return Err(invalid("invalid measured firmware TPM policy"));
        }
        Ok(Self {
            boot_id: identifier(boot, "boot_id=")?,
            esp: identifier(esp, "esp=")?,
            core: digest(core, "core=")?,
            runtime: digest(runtime, "runtime=")?,
            epoch,
            epoch_policy_sha256: digest(policy, "")?,
            tpm_floor,
            pcr7_sha256,
            filesystem: identifier(filesystem, "filesystem=")?,
            storage_policy_sha256: digest(storage, "storage_policy_sha256=")?,
        })
    }
}

pub fn activation_pending() -> io::Result<bool> {
    let path = Path::new(HOST_DATA).join(STATE_DIRECTORY).join(ACTIVATION);
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

pub fn require_idle() -> io::Result<()> {
    if activation_pending()? {
        return Err(crate::invalid(
            "a Host firmware activation requires reconciliation",
        ));
    }
    Ok(())
}
