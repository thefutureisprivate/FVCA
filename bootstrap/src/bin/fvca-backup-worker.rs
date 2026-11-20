#![deny(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{ChildStdout, Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use fvca_initrd_bootstrap::{backup_policy, guest_boot, invalid, recovery, runtime};

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
    read_only: bool,
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
            .current_dir(self.base)
            .arg("--repo").arg(destination)
            .arg("--cacert").arg(self.base.join("ca.pem"))
            .arg("--password-file").arg(self.credentials.join("repository-password"))
            .args(["--no-cache", "-o", "s3.bucket-lookup=path", "-o", "s3.connections=2", "-o"])
            .arg(format!("s3.region={}", p.region));
        if self.read_only {
            command.args(["--no-lock", "--limit-download", "32768"]);
        } else {
            command.current_dir(self.base.join("input"));
        }
        command
    }

    fn receive<T: Send + 'static>(&self, args: &[&str], seconds: u64, stage: &'static str,
                                 receive: impl FnOnce(ChildStdout) -> io::Result<T> + Send + 'static) -> io::Result<T> {
        let mut child = self.command().args(args).stdin(Stdio::null()).stdout(Stdio::piped())
            .stderr(Stdio::null()).spawn()?;
        let pipe = child.stdout.take().expect("restic stdout is piped");
        let reader = thread::spawn(move || receive(pipe));
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
        let output = reader.join().map_err(|_| io::Error::other("restic output reader failed"))?;
        let status = status?;
        if !status.success() {
            return Err(io::Error::other(format!("restic {stage} failed with {status}")));
        }
        output
    }

    fn reply(&self, args: &[&str], limit: usize, seconds: u64, stage: &'static str) -> io::Result<Vec<u8>> {
        self.receive(args, seconds, stage, move |pipe| {
            let mut output = Vec::new();
            pipe.take(limit as u64 + 1).read_to_end(&mut output)?;
            if output.len() > limit {
                return Err(invalid("restic output exceeded its size bound"));
            }
            Ok(output)
        })
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

    fn inventory(&self, snapshot: &str) -> io::Result<BTreeMap<String, u64>> {
        let listing = self.reply(&["--json", "ls", snapshot], SMALL_REPLY, 45, "snapshot listing")?;
        let mut members = BTreeMap::new();
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
                    if members.insert(path.to_owned(), node.integer(c"size")?).is_some() {
                        return Err(invalid("S3 snapshot repeats a member"));
                    }
                }
                _ => return Err(invalid("unexpected S3 snapshot inventory")),
            }
        }
        if !snapshot_seen || !directory_seen {
            return Err(invalid("S3 snapshot inventory is incomplete"));
        }
        Ok(members)
    }

    fn verify_snapshot(&self, snapshot: &str, members: BTreeMap<String, u64>, manifest: &[u8]) -> io::Result<()> {
        if self.inventory(snapshot)? != members {
            return Err(invalid("S3 snapshot includes an unexpected member or file size"));
        }
        let stored = self.reply(&["dump", snapshot, "/manifest"], 8192, 45, "manifest readback")?;
        if stored != manifest {
            return Err(invalid("S3 snapshot manifest differs from its sealed local source"));
        }
        Ok(())
    }

    fn dump_member(&self, snapshot: &str, name: &str, target: File, size: u64) -> io::Result<()> {
        self.receive(&["dump", snapshot, name], 43_200, "recovery member download", move |pipe| {
            let mut output = target;
            let mut remaining = size;
            let mut input = pipe.take(size);
            let mut buffer = vec![0u8; 256 * 1024];
            while remaining != 0 {
                let count = usize::try_from(remaining.min(buffer.len() as u64)).expect("bounded by the buffer size");
                let block = &mut buffer[..count];
                input.read_exact(block)?;
                if block.iter().all(|byte| *byte == 0) {
                    output.seek(SeekFrom::Current(count as i64))?;
                } else {
                    output.write_all(block)?;
                }
                remaining -= count as u64;
            }
            if input.into_inner().read(&mut buffer[..1])? != 0 {
                return Err(invalid("a recovery member exceeds its authorized size"));
            }
            output.set_len(size)?;
            output.sync_all()
        })
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

fn upload(repo: &Repository<'_>, capture: &str) -> io::Result<()> {
    let capture = recovery::uuid(capture)?;
    let input = repo.base.join("input");
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
    repo.verify()?;
    let snapshot = repo.upload()?;
    repo.verify_snapshot(&snapshot, members, &manifest)?;
    println!("FVCA-S3-VERIFIED-1\nrepository={}\nsnapshot={snapshot}", repo.policy.repository);
    Ok(())
}

fn download(repo: &Repository<'_>, key: &str) -> io::Result<()> {
    let text = fs::read_to_string(repo.base.join("authorization"))?;
    let request = recovery::Request::parse(&text)?;
    if request.key() != key || request.repository != repo.policy.repository {
        return Err(invalid("the requested recovery set is outside boot authorization"));
    }
    repo.verify()?;
    let paths = ["/data.raw".to_owned(), "/manifest".to_owned()].into_iter()
        .chain(guest_boot::FILES.map(|name| format!("/release/{name}"))).collect::<Vec<_>>();
    let members = repo.inventory(request.snapshot)?;
    if members.len() != paths.len() || paths.iter().any(|name| !matches!(members.get(name), Some(size) if *size > 0))
        || members.get("/data.raw") != Some(&request.disk_bytes) || members.get("/manifest").is_none_or(|size| *size > 8192)
        || members.values().try_fold(0u64, |sum, bytes| sum.checked_add(*bytes)) != Some(request.total_bytes)
    {
        return Err(invalid("repository inventory differs from the signed recovery set sizes"));
    }
    let output = repo.base.join("output");
    let target = |name: &str| OpenOptions::new().write(true).truncate(true).open(output.join(&name[1..]));
    let manifest = repo.reply(&["dump", request.snapshot, "/manifest"], 8192, 45, "recovery manifest download")?;
    if manifest.len() as u64 != members["/manifest"] {
        return Err(invalid("downloaded manifest length differs from the repository inventory"));
    }
    let mut file = target("/manifest")?;
    file.write_all(&manifest)?;
    file.sync_all()?;
    if recovery::sha256(File::open(output.join("manifest"))?)? != request.manifest {
        return Err(invalid("downloaded manifest differs from the independently authorized digest"));
    }
    for path in paths.iter().filter(|name| *name != "/manifest") {
        repo.dump_member(request.snapshot, path, target(path)?, members[path])?;
    }
    Ok(())
}

fn activate() -> io::Result<()> {
    fvca_allocator_binding::require_allocator()?;
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let read_only = matches!(args.as_slice(), [mode, _] if mode == "--download");
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
    let repo = Repository { policy, base, credentials, read_only };
    match args.as_slice() {
        [capture] => upload(&repo, capture),
        [_, key] if read_only => download(&repo, key),
        _ => Err(invalid("invalid backup worker arguments")),
    }
}

fn main() -> ExitCode {
    if let Err(error) = activate() {
        eprintln!("FVCA backup worker failed: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
