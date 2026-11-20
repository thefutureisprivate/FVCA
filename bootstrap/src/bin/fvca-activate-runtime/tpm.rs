use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::process::{Command, Stdio};

use super::{invalid, run};

const CRYPTSETUP: &str = "/usr/bin/cryptsetup";
const HEADER: &str = "/run/cryptsetup/fvca-host-header";
const SIGNATURE: &str = "/run/systemd/tpm2-pcr-signature.json";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    Auto,
    Pin,
}

fn output(command: &mut Command) -> io::Result<Vec<u8>> {
    let result = command.env_clear().output()?;
    if !result.status.success() {
        return Err(io::Error::other(format!("{:?} exited with {}", command.get_program(), result.status)));
    }
    Ok(result.stdout)
}

fn token_digest(token: &[u8]) -> io::Result<Vec<u8>> {
    let mut digest = Command::new("/usr/bin/sha256sum").env_clear()
        .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
    let written = digest.stdin.take().expect("SHA-256 input is piped").write_all(token);
    let result = digest.wait_with_output()?;
    written?;
    if !result.status.success() {
        return Err(io::Error::other("could not hash the LUKS2 token"));
    }
    Ok(result.stdout)
}

fn verify_header(uuid: &str, token: &str, expected: &str) -> io::Result<()> {
    let identity = output(Command::new(CRYPTSETUP).args(["luksUUID", HEADER]))?;
    if identity.strip_suffix(b"\n") != Some(uuid.as_bytes()) {
        return Err(invalid("copied LUKS2 header UUID does not match the signed selection"));
    }
    let json = output(Command::new(CRYPTSETUP).args(["token", "export", "--token-id", token, HEADER]))?;
    let actual = token_digest(&json)?;
    if actual.strip_suffix(b"  -\n") != Some(expected.as_bytes()) {
        return Err(invalid("LUKS2 TPM token does not match the signed selection"));
    }
    Ok(())
}

fn activate(source: &Path, mapper: &str, token: &str, mode: Mode) -> io::Result<()> {
    let mut command = Command::new(CRYPTSETUP);
    command.args([
        "open", "--type", "luks2", "--header", HEADER, "--token-id", token,
        "--token-type", "systemd-tpm2", "--token-only", "--tries", "1",
    ]).arg(source).arg(mapper);
    if mode == Mode::Auto {
        return run(command.arg("--batch-mode").stdin(Stdio::null()));
    }

    let mut prompt = Command::new("/usr/bin/systemd-ask-password").env_clear()
        .args(["--no-tty", "--timeout=55", "--echo=masked", "Enter FVCA storage TPM PIN:"])
        .stdin(Stdio::null()).stdout(Stdio::piped()).spawn()?;
    let pin = prompt.stdout.take().expect("PIN output is piped");
    if let Err(error) = run(command.stdin(pin)) {
        let _ = prompt.kill();
        let _ = prompt.wait();
        return Err(error);
    }
    match prompt.wait() {
        Ok(status) if status.success() => Ok(()),
        outcome => {
            let _ = run(Command::new(CRYPTSETUP).args(["close", mapper]));
            outcome?;
            Err(io::Error::other("the operator PIN prompt did not complete"))
        }
    }
}

pub(super) fn unlock(source: &Path, mapper: &str, uuid: &str, token: &str, expected: &str, mode: Mode) -> io::Result<()> {
    if !fs::metadata("/dev/tpmrm0").is_ok_and(|dev| dev.file_type().is_char_device()) {
        return Err(invalid("TPM resource manager device is required"));
    }
    if !fs::symlink_metadata(SIGNATURE).is_ok_and(|metadata| metadata.is_file()) {
        return Err(invalid("the boot PCR policy signature is missing"));
    }
    if fs::symlink_metadata(HEADER).is_ok() {
        return Err(invalid("unexpected existing LUKS2 header copy"));
    }

    // Open the same private header copy that was checked, so later changes to
    // the block device cannot substitute a different token during unlock.
    let result = run(Command::new(CRYPTSETUP)
        .arg("luksHeaderBackup").arg(source).args(["--header-backup-file", HEADER]))
        .and_then(|()| verify_header(uuid, token, expected))
        .and_then(|()| activate(source, mapper, token, mode));
    let cleanup = fs::remove_file(HEADER);
    result?;
    if let Err(error) = cleanup {
        let _ = run(Command::new(CRYPTSETUP).args(["close", mapper]));
        return Err(error);
    }
    Ok(())
}
