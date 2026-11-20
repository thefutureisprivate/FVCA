#![deny(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use fvca_initrd_bootstrap::{backup_policy, guest_boot, identity, invalid, runtime};

#[path = "fvca-backup-worker/json.rs"]
// Keep the native parser's pointer handling inside this module.
#[allow(unsafe_code)]
mod json;

const ROOT: &str = "/run/fvca-backup";
const ENGINE: &str = "/usr/bin/restic";
const SMALL_REPLY: usize = 65_536;

struct Repository<'a> {
    policy: backup_policy::Policy<'a>,
    base: &'a Path,
    credentials: PathBuf,
}

impl Repository<'_> {
    fn command(&self) -> Command {
        let p = &self.policy;
        let mut destination = format!("s3:https://{}/{}", p.endpoint, p.bucket);
        if !p.prefix.is_empty() {
            destination.push('/');
            destination.push_str(p.prefix);
        }
        let mut command = Command::new(ENGINE);
        command.env_clear().env("HOME", "/nonexistent").env("TMPDIR", self.base.join("tmp"))
            .env("AWS_SHARED_CREDENTIALS_FILE", self.credentials.join("s3-credentials"))
            .env("AWS_PROFILE", "default").env("AWS_EC2_METADATA_DISABLED", "true")
            .env("GOMAXPROCS", "2").env("GOMEMLIMIT", "512MiB")
            .current_dir(self.base.join("input"))
            .arg("--repo").arg(destination)
            .arg("--cacert").arg(self.base.join("ca.pem"))
            .arg("--password-file").arg(self.credentials.join("repository-password"))
            .args(["--no-cache", "-o", "s3.bucket-lookup=path", "-o", "s3.connections=2", "-o"])
            .arg(format!("s3.region={}", p.region));
        command
    }

    fn reply(&self, args: &[&str], limit: usize, seconds: u64, stage: &'static str) -> io::Result<Vec<u8>> {
        let mut child = self.command().args(args).stdin(Stdio::null()).stdout(Stdio::piped())
            .stderr(Stdio::null()).spawn()?;
        let pipe = child.stdout.take().expect("restic stdout is piped");
        let reader = thread::spawn(move || {
            let mut output = Vec::new();
            pipe.take(limit as u64 + 1).read_to_end(&mut output)?;
            Ok::<_, io::Error>(output)
        });
        let deadline = Instant::now() + Duration::from_secs(seconds);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
                other => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(other.err().unwrap_or_else(|| io::Error::new(
                        io::ErrorKind::TimedOut, format!("restic {stage} timed out"))));
                }
            }
        };
        let output = reader.join().map_err(|_| io::Error::other("restic output reader failed"))??;
        let status = status?;
        if output.len() > limit {
            return Err(invalid("restic output exceeded its size bound"));
        }
        if !status.success() {
            return Err(io::Error::other(format!("restic {stage} failed with {status}")));
        }
        Ok(output)
    }

    fn verify(&self) -> io::Result<()> {
        let config = self.reply(&["cat", "config"], SMALL_REPLY, 20, "repository authentication")?;
        let config = json::Object::parse(&config)?;
        if config.integer(c"version")? != 2 || config.text(c"id")? != self.policy.repository {
            return Err(invalid("the S3 repository does not match the authorized version and identity"));
        }
        Ok(())
    }

    fn upload(&self) -> io::Result<String> {
        let reply = self.reply(&["--json", "--quiet", "--limit-upload", "32768", "backup",
            "--host", "fvca-service-guest", "--compression", "auto", "--read-concurrency", "1", "--force",
            "--", "data.raw", "manifest", "release"], 1024 * 1024, 43_200, "backup")?;
        let mut summary = None;
        for line in reply.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()) {
            let object = json::Object::parse(line)?;
            match object.text(c"message_type")? {
                "summary" if summary.is_none() => summary = Some(runtime::hash(object.text(c"snapshot_id")?)?.to_owned()),
                "status" => {}
                _ => return Err(invalid("unexpected restic backup result")),
            }
        }
        summary.ok_or_else(|| invalid("restic returned no snapshot ID"))
    }

    fn verify_snapshot(&self, snapshot: &str, mut members: BTreeMap<String, u64>, manifest: &[u8]) -> io::Result<()> {
        let listing = self.reply(&["--json", "ls", snapshot], SMALL_REPLY, 45, "snapshot listing")?;
        let mut snapshot_seen = false;
        let mut directory_seen = false;
        for line in listing.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()) {
            let node = json::Object::parse(line)?;
            match node.text(c"message_type")? {
                "snapshot" if !snapshot_seen && node.text(c"id")? == snapshot => snapshot_seen = true,
                "node" if node.text(c"type")? == "dir" && node.text(c"path")? == "/release" && !directory_seen => {
                    directory_seen = true;
                }
                "node" if node.text(c"type")? == "file" => {
                    let path = node.text(c"path")?;
                    if members.remove(path) != Some(node.integer(c"size")?) {
                        return Err(invalid("S3 snapshot includes an unexpected member or file size"));
                    }
                }
                _ => return Err(invalid("unexpected S3 snapshot inventory")),
            }
        }
        if !snapshot_seen || !directory_seen || !members.is_empty() {
            return Err(invalid("S3 snapshot inventory is incomplete"));
        }
        let stored = self.reply(&["dump", snapshot, "/manifest"], 8192, 45, "manifest readback")?;
        if stored != manifest {
            return Err(invalid("S3 snapshot manifest differs from its sealed local source"));
        }
        Ok(())
    }
}

fn file_size(path: &Path) -> io::Result<u64> {
    let info = fs::symlink_metadata(path)?;
    if !info.is_file() || info.len() == 0 {
        return Err(invalid("backup members must be nonempty regular files"));
    }
    Ok(info.len())
}

fn check_s3_credentials(file: &Path) -> io::Result<()> {
    let text = fs::read_to_string(file)?;
    let mut lines = text.lines();
    let value = |line: Option<&str>, key: &str| {
        line.and_then(|line| line.split_once('=')).is_some_and(|(name, value)| {
            name.trim() == key && !value.trim().is_empty()
                && value.trim().bytes().all(|byte| byte.is_ascii_alphanumeric() || b"+=/_.-".contains(&byte))
        })
    };
    if lines.next() != Some("[default]")
        || !value(lines.next(), "aws_access_key_id")
        || !value(lines.next(), "aws_secret_access_key")
        || lines.next().is_some_and(|line| !value(Some(line), "aws_session_token"))
        || lines.next().is_some()
    {
        return Err(invalid("expected a bounded AWS shared credentials profile"));
    }
    Ok(())
}

fn activate() -> io::Result<()> {
    fvca_allocator_binding::require_allocator()?;
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let [capture] = args.as_slice() else { return Err(invalid("backup worker requires one capture UUID")); };
    let capture = identity(capture, "", &[8, 4, 4, 4, 12], '-')?;
    let base = Path::new(ROOT);
    let text = fs::read_to_string(base.join("policy"))?;
    let policy = backup_policy::parse(&text)?;
    let credentials = std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from)
        .ok_or_else(|| invalid("systemd did not supply the backup credentials"))?;
    for (name, limit) in [("repository-password", 4096), ("s3-credentials", 8192)] {
        if file_size(&credentials.join(name))? > limit {
            return Err(invalid("a backup credential exceeds its size bound"));
        }
    }
    check_s3_credentials(&credentials.join("s3-credentials"))?;
    let input = base.join("input");
    let manifest_path = input.join("manifest");
    let mut members = BTreeMap::new();
    members.insert("/data.raw".to_owned(), file_size(&input.join("data.raw"))?);
    let manifest_bytes = file_size(&manifest_path)?;
    if manifest_bytes > 8192 {
        return Err(invalid("the capture manifest exceeds its size bound"));
    }
    members.insert("/manifest".to_owned(), manifest_bytes);
    let manifest = fs::read(manifest_path)?;
    let selection = std::str::from_utf8(&manifest).map_err(io::Error::other)?
        .split_once("FVCA-GUEST-LAUNCH-1\n").ok_or_else(|| invalid("capture manifest lacks its launch selection"))?;
    if !selection.0.starts_with("CAPTURE_COMPLETE\n") || !selection.0.lines().any(|line| line == format!("capture_id={capture}")) {
        return Err(invalid("the capture is not finalized"));
    }
    let payload = format!("FVCA-GUEST-LAUNCH-1\n{}", selection.1);
    let guest = guest_boot::parse(&payload)?;
    let release = input.join("release");
    let expected = guest.checksums.lines().map(|line| &line[66..]).collect::<Vec<_>>();
    let mut names = fs::read_dir(&release)?.map(|item| item.map(|entry| entry.file_name())).collect::<io::Result<Vec<_>>>()?;
    names.sort();
    let mut sorted = expected.clone();
    sorted.sort_unstable();
    if names != sorted {
        return Err(invalid("the backup release directory has unexpected members"));
    }
    for file in expected {
        members.insert(format!("/release/{file}"), file_size(&release.join(file))?);
    }
    let repo = Repository { policy, base, credentials };
    repo.verify()?;
    let snapshot = repo.upload()?;
    repo.verify_snapshot(&snapshot, members, &manifest)?;
    println!("FVCA-S3-VERIFIED-1\nrepository={}\nsnapshot={snapshot}", repo.policy.repository);
    Ok(())
}

fn main() -> ExitCode {
    if let Err(error) = activate() {
        eprintln!("FVCA backup worker failed: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
