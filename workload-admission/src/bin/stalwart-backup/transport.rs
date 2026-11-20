use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use fvca_workload_admission::read_bounded;
use serde::Deserialize;

use super::{Result, digest, file_hash, invalid, private_directory, private_input};
use super::policy::{MANIFEST, Member, Policy, hash};

pub fn run<T: Send>(command: &mut Command, timeout: u64, stage: &str,
                   read: impl FnOnce(ChildStdout) -> io::Result<T> + Send) -> Result<T> {
    let mut child = command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()?;
    let output = child.stdout.take().expect("the program has piped stdout");
    thread::scope(|scope| -> Result<T> {
        let reader = scope.spawn(move || read(output));
        let deadline = Instant::now() + Duration::from_secs(timeout);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                outcome => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(outcome.err().unwrap_or_else(|| io::Error::new(
                        io::ErrorKind::TimedOut, format!("{stage} timed out"))));
                }
            }
        };
        let result = reader.join().map_err(|_| invalid("work reader failed"))?;
        let status = status?;
        if !status.success() {
            return Err(invalid(&format!("{stage} failed with {status}")));
        }
        Ok(result?)
    })
}

pub fn reply(command: &mut Command, timeout: u64, limit: u64, stage: &str) -> Result<Vec<u8>> {
    run(command, timeout, stage, |stream| {
        let mut output = Vec::new();
        stream.take(limit + 1).read_to_end(&mut output)?;
        if output.len() as u64 > limit {
            return Err(io::Error::other("tool reply exceeds its size limit"));
        }
        Ok(output)
    })
}

pub fn discard(command: &mut Command, timeout: u64, stage: &str) -> Result<()> {
    run(command, timeout, stage, |mut stream| {
        io::copy(&mut stream, &mut io::sink()).map(|_| ())
    })
}

#[derive(Deserialize)]
struct RepositoryConfig {
    id: String,
    version: u32,
}

pub struct Repo<'a> {
    policy: &'a Policy,
    executable: PathBuf,
    credentials: PathBuf,
    work: &'a Path,
    ca: PathBuf,
}

impl<'a> Repo<'a> {
    pub fn open(policy: &'a Policy, executable: &Path, credentials: &Path, ca: &Path, work: &'a Path) -> Result<Self> {
        let executable = executable.canonicalize()?;
        let engine = private_input(&executable)?;
        let engine_bytes = engine.metadata()?.len();
        if engine_bytes == 0 || engine_bytes > 250 * 1024 * 1024
            || file_hash(engine)? != policy.endpoint.restic_sha256
        {
            return Err(invalid("restic does not match the signed executable digest"));
        }
        private_directory(credentials)?;
        let credentials = credentials.canonicalize()?;
        let owner = fs::metadata(&credentials)?.uid();
        for (name, max) in [("repository-password", 4096), ("s3-credentials", 8192)] {
            let path = credentials.join(name);
            let metadata = private_input(&path)?.metadata()?;
            if metadata.uid() != owner || !matches!(metadata.mode() & 0o7777, 0o400 | 0o600)
                || metadata.len() == 0 || metadata.len() > max
            {
                return Err(invalid("unexpected private application repository credential"));
            }
        }
        let credentials_record = read_bounded(&credentials.join("s3-credentials"), 8192)?;
        let mut fields = std::str::from_utf8(&credentials_record)?.lines();
        let key = |line: Option<&str>, expected| {
            line.and_then(|line| line.split_once('=')).is_some_and(|(name, value)| {
                let value = value.trim();
                name.trim() == expected && !value.is_empty()
                    && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"+=/_.-".contains(&b))
            })
        };
        if fields.next() != Some("[default]") || !key(fields.next(), "aws_access_key_id")
            || !key(fields.next(), "aws_secret_access_key")
            || fields.next().is_some_and(|line| !key(Some(line), "aws_session_token")) || fields.next().is_some()
        {
            return Err(invalid("expected a bounded AWS shared credentials profile"));
        }
        let ca = read_bounded(ca, 65_536)?;
        if !ca.starts_with(b"-----BEGIN CERTIFICATE-----") || digest(&ca) != policy.endpoint.ca_sha256 {
            return Err(invalid("the endpoint CA does not match the signed policy"));
        }
        let ca_path = work.join("s3-ca.pem");
        fs::write(&ca_path, ca)?;
        let repo = Self { policy, executable, credentials, work, ca: ca_path };
        let config: RepositoryConfig = serde_json::from_slice(&repo.read(&["cat", "config"], 65536, "repository identity")?)?;
        if config.version != 2 || config.id != policy.endpoint.repository {
            return Err(invalid("application repository identity or format differs from approval"));
        }
        Ok(repo)
    }

    fn command(&self) -> Command {
        let p = &self.policy.endpoint;
        let mut destination = format!("s3:https://{}/{}", p.address, p.bucket);
        if !p.prefix.is_empty() {
            destination.push('/');
            destination.push_str(&p.prefix);
        }
        let limit = self.policy.bandwidth_kib.to_string();
        let mut cmd = Command::new(&self.executable);
        cmd.env_clear().env("HOME", self.work).env("TMPDIR", self.work)
            .env("AWS_SHARED_CREDENTIALS_FILE", self.credentials.join("s3-credentials"))
            .env("AWS_PROFILE", "default").env("AWS_EC2_METADATA_DISABLED", "true")
            .env("GOMAXPROCS", "2").env("GOMEMLIMIT", "512MiB").current_dir(self.work)
            .args(["--repo", &destination, "--cacert"]).arg(&self.ca)
            .arg("--password-file").arg(self.credentials.join("repository-password"))
            .args(["--no-cache", "--limit-download", &limit, "--limit-upload", &limit,
                   "-o", "s3.bucket-lookup=path", "-o", "s3.connections=2", "-o"])
            .arg(format!("s3.region={}", p.region));
        if matches!(self.policy.operation, super::policy::Operation::Recover { .. }) {
            cmd.arg("--no-lock");
        }
        cmd
    }

    fn read(&self, args: &[&str], limit: u64, stage: &str) -> Result<Vec<u8>> {
        reply(self.command().args(args), self.policy.timeout_seconds.min(120), limit, stage)
    }

    pub fn upload(&self, source: &Path) -> Result<String> {
        #[derive(Deserialize)]
        struct Event<'a> {
            message_type: &'a str,
            snapshot_id: Option<&'a str>,
        }
        let events = reply(self.command().current_dir(source).args([
            "--json", "--quiet", "backup", "--host", "fvca-stalwart-application", "--compression", "auto",
            "--force", "--read-concurrency", "1", "--", "config", "data", MANIFEST,
        ]), self.policy.timeout_seconds, 1024 * 1024, "application upload")?;
        let mut result = None;
        for line in events.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()) {
            let message: Event<'_> = serde_json::from_slice(line)?;
            match message.message_type {
                "summary" if result.is_none() => result = message.snapshot_id,
                "status" => {}
                _ => return Err(invalid("unexpected application upload event")),
            }
        }
        let result = result.ok_or_else(|| invalid("application upload included no snapshot ID"))?;
        hash(result)?;
        Ok(result.to_owned())
    }

    pub fn manifest(&self, id: &str) -> Result<Vec<u8>> {
        self.read(&["dump", id, "/manifest.json"], 65_536, "application manifest readback")
    }

    pub fn inventory(&self, id: &str, manifest_size: u64, members: &[Member]) -> Result<()> {
        #[derive(Deserialize)]
        #[serde(tag = "message_type", rename_all = "lowercase")]
        enum Event {
            Snapshot { id: String },
            Node { path: String, #[serde(rename = "type")] kind: String, size: Option<u64> },
        }
        let response = self.read(&["--json", "ls", id], 262_144, "application member inventory")?;
        let mut wanted: BTreeMap<_, _> = members.iter().map(|file| (format!("/{}", file.path), ("file", Some(file.bytes)))).collect();
        wanted.extend([
            ("/config".into(), ("dir", None)), ("/data".into(), ("dir", None)),
            ("/manifest.json".into(), ("file", Some(manifest_size))),
        ]);
        let mut seen = false;
        for line in response.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
            match serde_json::from_slice(line)? {
                Event::Snapshot { id: received } if !seen && received == id => seen = true,
                Event::Node { path, kind, size } if seen => {
                    let Some((expected_type, expected_size)) = wanted.remove(&path) else {
                        return Err(invalid("unexpected or duplicate application snapshot member"));
                    };
                    if kind != expected_type || (expected_size.is_some() && size != expected_size) {
                        return Err(invalid("application snapshot member has the wrong type or size"));
                    }
                }
                _ => return Err(invalid("unexpected application snapshot identity")),
            }
        }
        if !seen || !wanted.is_empty() {
            return Err(invalid("the application snapshot inventory is incomplete"));
        }
        Ok(())
    }

    pub fn download(&self, id: &str, member: &Member, mut file: File) -> Result<()> {
        let path = format!("/{}", member.path);
        run(self.command().args(["dump", id, &path]), self.policy.timeout_seconds,
            "application member retrieval", |stream| {
            let count = io::copy(&mut stream.take(member.bytes + 1), &mut file)?;
            if count != member.bytes {
                return Err(io::Error::other("application member size differs from the approved manifest"));
            }
            file.seek(SeekFrom::Start(0))?;
            file.sync_all()
        })
    }
}
