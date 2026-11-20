#![forbid(unsafe_code)]

//! Promote a verified stopped VM capture into an independent Stalwart recovery set.

#[path = "stalwart-backup/policy.rs"]
mod policy;
#[path = "stalwart-backup/transport.rs"]
mod transport;

use std::collections::BTreeSet;
use std::env;
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use fvca_workload_admission::{Launch, read_bounded};
use gpt::disk::LogicalBlockSize::Lb512;
use gpt::header::read_header_from_arbitrary_device;
use gpt::partition::file_read_partitions;
use gpt::GptConfig;
use openssl::sha::{Sha256, sha256};
use serde::{Deserialize, Serialize};

use policy::{DB, MANIFEST, Manifest, ManifestSource, Member, Operation, PROFILE, Policy, Source, hash, uuid};
use transport::{Repo, discard, reply};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const MAX_MANIFEST: u64 = 65_536;
const SECTOR: u64 = 512;
const LINUX_DATA: &str = "0fc63daf-8483-4772-8e79-3d69d8477de4";

fn invalid(reason: &str) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidData, reason).into()
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn digest(bytes: &[u8]) -> String {
    hex(&sha256(bytes))
}

fn file_hash(mut file: File) -> Result<String> {
    let mut hash = Sha256::new();
    let mut block = vec![0; 1024 * 1024];
    loop {
        let count = file.read(&mut block)?;
        if count == 0 {
            return Ok(hex(&hash.finish()));
        }
        hash.update(&block[..count]);
    }
}

fn private_directory(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.mode() & 0o7777 != 0o700 {
        return Err(invalid("expected a private mode-0700 directory"));
    }
    Ok(())
}

fn create_directory(path: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}

fn private_input(path: &Path) -> Result<File> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 || meta.mode() & 0o022 != 0 {
        return Err(invalid("expected a regular input file with private write permissions"));
    }
    Ok(file)
}

fn new_file(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
}

fn write_file(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = new_file(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

struct Scratch(PathBuf);

impl Scratch {
    fn in_parent(path: &Path) -> Result<Self> {
        private_directory(path)?;
        let mut random = [0; 16];
        openssl::rand::rand_bytes(&mut random)?;
        let scratch = path.canonicalize()?.join(format!(".fvca-stalwart-{}", hex(&random)));
        create_directory(&scratch)?;
        Ok(Self(scratch))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if fs::remove_dir_all(&self.0).is_err() {
            eprintln!("FVCA application backup scratch cleanup failed");
        }
    }
}

fn fields<'a>(text: &'a str, key: &str) -> Result<&'a str> {
    let mut values = text.lines().filter_map(|line| line.strip_prefix(key));
    let value = values.next().ok_or_else(|| invalid("source VM manifest is missing a required field"))?;
    if values.next().is_some() {
        return Err(invalid("source VM manifest has a duplicate field"));
    }
    Ok(value)
}

struct VmCapture {
    id: String,
    time: u64,
    bytes: u64,
    disk_hash: String,
}

impl VmCapture {
    fn approved(manifest: &Path, source: &Source) -> Result<Self> {
        let content = read_bounded(manifest, 8192)?;
        if digest(&content) != source.vm_manifest_sha256 {
            return Err(invalid("source VM manifest differs from signed approval"));
        }
        let text = std::str::from_utf8(&content)?;
        if !text.starts_with("CAPTURE_COMPLETE\n") || !text.lines().any(|line| line == "FVCA-STOPPED-CAPTURE-1")
            || fields(text, "requested_consistency=")? != "clean-stopped"
            || fields(text, "achieved_consistency=")? != "clean-stopped"
            || fields(text, "member=")? != "data.raw,raw,vdc"
            || fields(text, "external_storage=")? != "none"
            || fields(text, "workload_state=")? != "contained-in-data.raw"
        {
            return Err(invalid("the application source requires a finalized orderly stopped VM capture"));
        }
        let id = fields(text, "capture_id=")?;
        uuid(id)?;
        let disk_hash = fields(text, "disk_sha256=")?;
        hash(disk_hash)?;
        let bytes = fields(text, "disk_bytes=")?.parse::<u64>()?;
        let time = fields(text, "capture_unix_seconds=")?.parse::<u64>()?;
        if !(2 * 1024 * 1024..=1 << 40).contains(&bytes) || !bytes.is_multiple_of(SECTOR) || time == 0 {
            return Err(invalid("invalid source disk length or capture time"));
        }
        Ok(Self { id: id.to_owned(), time, bytes, disk_hash: disk_hash.to_owned() })
    }
}

fn partition_range(source: &mut File, selection: &str, size: u64) -> Result<(u64, u64)> {
    let primary = read_header_from_arbitrary_device(source, Lb512)?;
    let last = size / SECTOR - 1;
    if primary.header_size_le != 92 || primary.reserved != 0 || primary.current_lba != 1
        || primary.backup_lba != last || primary.num_parts != 128 || primary.part_size != 128
        || primary.part_start != 2 || primary.first_usable < 34 || primary.last_usable > last - 33
    {
        return Err(invalid("unexpected Guest data disk GPT geometry"));
    }
    let mut table = GptConfig::new().logical_block_size(Lb512).only_valid_headers(true).open_from_device(&mut *source)?;
    let alternate = table.backup_header()?.clone();
    let entries = table.take_partitions();
    if alternate.header_size_le != 92 || alternate.reserved != 0 || alternate.current_lba != last
        || alternate.backup_lba != 1 || alternate.part_start != last - 32 || alternate.num_parts != 128
        || alternate.part_size != 128 || alternate.disk_guid != primary.disk_guid
        || alternate.first_usable != primary.first_usable || alternate.last_usable != primary.last_usable
        || alternate.crc32_parts != primary.crc32_parts || file_read_partitions(source, &alternate, Lb512)? != entries
        || !entries.keys().copied().eq([1])
    {
        return Err(invalid("the Guest data disk partition tables differ"));
    }
    let part = &entries[&1];
    if part.part_guid.to_string() != selection || part.part_type_guid.guid.to_string() != LINUX_DATA
        || part.first_lba < primary.first_usable || part.first_lba > part.last_lba
        || part.last_lba > primary.last_usable
    {
        return Err(invalid("the Btrfs partition differs from signed approval"));
    }
    Ok((part.first_lba * SECTOR, (part.last_lba + 1) * SECTOR))
}

fn extract_partition(path: &Path, output: &Path, mount: &str, capture: &VmCapture) -> Result<()> {
    let mut source = private_input(path)?;
    if source.metadata()?.len() != capture.bytes {
        return Err(invalid("source raw VM disk length differs from its finalized manifest"));
    }
    let (from, to) = partition_range(&mut source, mount, capture.bytes)?;
    source.seek(SeekFrom::Start(0))?;
    let mut out = new_file(output)?;
    let mut hash = Sha256::new();
    let mut block = vec![0; 1024 * 1024];
    let mut offset = 0;
    while offset < capture.bytes {
        let count = (capture.bytes - offset).min(block.len() as u64) as usize;
        let input = &mut block[..count];
        source.read_exact(input)?;
        hash.update(input);
        let end = offset + count as u64;
        if offset < to && from < end {
            let selected = &input[(from.max(offset) - offset) as usize..(to.min(end) - offset) as usize];
            if selected.iter().any(|byte| *byte != 0) {
                out.write_all(selected)?;
            } else {
                out.seek(SeekFrom::Current(selected.len() as i64))?;
            }
        }
        offset = end;
    }
    if source.read(&mut block[..1])? != 0 || hex(&hash.finish()) != capture.disk_hash {
        return Err(invalid("source raw VM disk digest differs from its finalized manifest"));
    }
    out.set_len(to - from)?;
    out.sync_all()?;
    Ok(())
}

fn names(path: &Path) -> Result<BTreeSet<String>> {
    if !fs::symlink_metadata(path)?.is_dir() {
        return Err(invalid("expected a directory in the application set"));
    }
    fs::read_dir(path)?.map(|entry| {
        entry?.file_name().into_string().map_err(|_| invalid("non-UTF-8 application file name"))
    }).collect()
}

fn check_deployment(extracted: &Path, source: &Source) -> Result<()> {
    #[derive(Deserialize)]
    struct Deployment {
        service: String,
        launch: String,
    }
    let deployment = read_bounded(&extracted.join("workload/deployment.json"), 65_536)?;
    if digest(&deployment) != source.deployment_sha256 {
        return Err(invalid("the source Stalwart deployment differs from signed approval"));
    }
    let deployment: Deployment = serde_json::from_slice(&deployment)?;
    let launch = read_bounded(&extracted.join("workload/launch.json"), 65_536)?;
    if deployment.service != "stalwart" || deployment.launch != format!("sha256:{}", digest(&launch)) {
        return Err(invalid("the source launch definition does not belong to Stalwart"));
    }
    let launch: Launch = serde_json::from_slice(&launch)?;
    if launch.entrypoint != ["/usr/local/bin/stalwart"] || launch.command != ["--config", "/etc/stalwart/config.json"]
        || launch.volumes.iter().map(String::as_str).collect::<BTreeSet<_>>() != BTreeSet::from(["/etc/stalwart", "/var/lib/stalwart"])
        || launch.volumes.len() != 2
        || launch.environment.iter().any(|entry| !entry.starts_with("PATH=") && !entry.starts_with("STALWART_HEALTHCHECK_URL="))
    {
        return Err(invalid("unsupported Stalwart process arguments, environment or volume layout"));
    }
    Ok(())
}

fn check_config(path: &Path) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct LocalSqlite {
        #[serde(rename = "@type")]
        backend: String,
        path: String,
        pool_workers: Option<u32>,
        pool_max_connections: Option<u32>,
    }
    let cfg: LocalSqlite = serde_json::from_slice(&read_bounded(path, 65_536)?)?;
    if cfg.backend != "Sqlite" || cfg.path != "/var/lib/stalwart/stalwart.db"
        || cfg.pool_workers == Some(0) || cfg.pool_max_connections == Some(0)
    {
        return Err(invalid("the approved application profile requires the local SQLite store"));
    }
    Ok(())
}

fn create_sqlite(source: &Path, output: &Path, budget: u64, timeout: u64) -> Result<()> {
    let entries = names(source)?;
    if !entries.contains(DB) || entries.iter().any(|name| !matches!(name.as_str(), DB | "stalwart.db-wal" | "stalwart.db-shm")) {
        return Err(invalid("unexpected Stalwart data or external store files"));
    }
    let mut bytes = 0u64;
    for entry in entries {
        let member = private_input(&source.join(entry))?;
        bytes = bytes.checked_add(member.metadata()?.len()).ok_or_else(|| invalid("SQLite input size overflow"))?;
    }
    if bytes > budget {
        return Err(invalid("SQLite and sidecars exceed the signed application budget"));
    }
    discard(Command::new("/usr/bin/sqlite3").env_clear().current_dir(source)
        .args(["-batch", "-bail", "-init", "/dev/null", DB, ".backup fvca-export.db"]), timeout, "SQLite backup")?;
    fs::rename(source.join("fvca-export.db"), output)?;
    fs::set_permissions(output, fs::Permissions::from_mode(0o600))?;
    let mode = reply(Command::new("/usr/bin/sqlite3").env_clear()
        .args(["-batch", "-bail", "-init", "/dev/null"]).arg(output)
        .arg("PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE;"), timeout, 8192, "SQLite standalone journal mode")?;
    if mode != b"delete\n" {
        return Err(invalid("the SQLite copy did not enter standalone journal mode"));
    }
    check_sqlite(output, timeout)
}

fn check_sqlite(path: &Path, timeout: u64) -> Result<()> {
    let output = reply(Command::new("/usr/bin/sqlite3").env_clear()
        .args(["-batch", "-bail", "-safe", "-readonly", "-init", "/dev/null"]).arg(path)
        .arg("PRAGMA trusted_schema=OFF; PRAGMA journal_mode; PRAGMA integrity_check(1);"), timeout, 8192, "SQLite integrity check")?;
    if output != b"delete\nok\n" {
        return Err(invalid("the standalone SQLite copy failed journal or integrity verification"));
    }
    Ok(())
}

fn add_member(path: &Path, file: &str, budget: &mut u64) -> Result<Member> {
    let handle = private_input(&path.join(file))?;
    let bytes = handle.metadata()?.len();
    *budget = budget.checked_sub(bytes).ok_or_else(|| invalid("the application data exceed signed byte limits"))?;
    handle.sync_all()?;
    Ok(Member { path: file.to_owned(), bytes, sha256: file_hash(handle)? })
}

fn validate_manifest(manifest: &Manifest, policy: &Policy, expected_deployment: &str) -> Result<()> {
    manifest.source.selection.validate(&policy.endpoint.repository)?;
    uuid(&manifest.source.capture)?;
    if manifest.schema != PROFILE || manifest.application_repository != policy.endpoint.repository
        || manifest.source.selection.deployment_sha256 != expected_deployment || manifest.source.captured == 0
        || !(2..=65).contains(&manifest.members.len())
    {
        return Err(invalid("application manifest is outside the signed recovery scope"));
    }
    let mut remaining = policy.max_application_bytes;
    let mut seen = BTreeSet::new();
    for member in &manifest.members {
        member.valid()?;
        remaining = remaining.checked_sub(member.bytes).ok_or_else(|| invalid("application recovery exceeds signed byte limits"))?;
        if !seen.insert(member.path.as_str()) {
            return Err(invalid("duplicate application member"));
        }
    }
    if !seen.contains("config/config.json") || !seen.contains("data/stalwart.db") {
        return Err(invalid("application manifest misses required configuration or data"));
    }
    Ok(())
}

struct Create<'a> {
    source: &'a Source,
    partition: &'a str,
    filesystem: &'a str,
    configuration: &'a [String],
    raw: &'a Path,
    vm_manifest: &'a Path,
    receipt: &'a Path,
}

fn create(job: Create<'_>, policy: &Policy, repo: &Repo<'_>, work: &Path) -> Result<()> {
    if fs::symlink_metadata(job.receipt).is_ok() {
        return Err(invalid("application backup receipt already exists"));
    }
    let capture = VmCapture::approved(job.vm_manifest, job.source)?;
    let partition = work.join("source.btrfs");
    extract_partition(job.raw, &partition, job.partition, &capture)?;
    let identity = reply(Command::new("/usr/bin/blkid").env_clear().args(["--probe", "--output", "export"])
        .arg(&partition), 30, 8192, "Btrfs partition identity")?;
    let identity = std::str::from_utf8(&identity)?;
    if fields(identity, "TYPE=")? != "btrfs" || fields(identity, "UUID=")? != job.filesystem {
        return Err(invalid("the restored Guest Btrfs filesystem differs from signed approval"));
    }
    discard(Command::new("/usr/bin/btrfs").env_clear().args(["check", "--readonly", "--check-data-csum"])
        .arg(&partition), policy.timeout_seconds, "source Btrfs verification")?;

    let extracted = work.join("source");
    create_directory(&extracted)?;
    let config = digest(b"/etc/stalwart");
    let data = digest(b"/var/lib/stalwart");
    let filter = format!("^/(|workload(|/deployment[.]json|/launch[.]json)|payload(|/stalwart(|/({config}|{data})(|/.*))))$");
    discard(Command::new("/usr/bin/btrfs").env_clear().args(["restore", "-r", "5", "--path-regex", &filter])
        .arg(&partition).arg(&extracted), policy.timeout_seconds, "application-only Btrfs extraction")?;
    fs::remove_file(partition)?;
    check_deployment(&extracted, job.source)?;
    let source = extracted.join("payload/stalwart");
    let configuration = source.join(config);
    let data = source.join(data);
    if names(&configuration)? != job.configuration.iter().cloned().collect() {
        return Err(invalid("Stalwart configuration files differ from signed approval"));
    }
    check_config(&configuration.join("config.json"))?;

    let bundle = work.join("bundle");
    for directory in [bundle.clone(), bundle.join("config"), bundle.join("data")] {
        create_directory(&directory)?;
    }
    create_sqlite(&data, &bundle.join("data").join(DB), policy.max_application_bytes, policy.timeout_seconds)?;
    if names(&bundle.join("data"))? != BTreeSet::from([DB.to_owned()]) {
        return Err(invalid("standalone application staging contains unexpected SQLite sidecars"));
    }
    let mut remaining = policy.max_application_bytes;
    let mut members = vec![add_member(&bundle, "data/stalwart.db", &mut remaining)?];
    let mut files = job.configuration.to_vec();
    files.sort_unstable();
    for file in files {
        let input = private_input(&configuration.join(&file))?;
        let mut output = new_file(&bundle.join("config").join(&file))?;
        if io::copy(&mut input.take(remaining + 1), &mut output)? > remaining {
            return Err(invalid("configuration exceeds signed application byte limits"));
        }
        members.push(add_member(&bundle, &format!("config/{file}"), &mut remaining)?);
    }
    let manifest = Manifest {
        schema: PROFILE.to_owned(), application_repository: policy.endpoint.repository.clone(), members,
        source: ManifestSource { selection: job.source.clone(), capture: capture.id, captured: capture.time },
    };
    validate_manifest(&manifest, policy, &job.source.deployment_sha256)?;
    let content = serde_json::to_vec(&manifest)?;
    write_file(&bundle.join(MANIFEST), &content)?;
    let snapshot = repo.upload(&bundle)?;
    repo.inventory(&snapshot, content.len() as u64, &manifest.members)?;
    if repo.manifest(&snapshot)? != content {
        return Err(invalid("the uploaded application manifest differs from its local source"));
    }
    #[derive(Serialize)]
    struct Receipt<'a> {
        application_repository: &'a str,
        snapshot: &'a str,
        manifest_sha256: String,
        deployment_sha256: &'a str,
        vm_capture: &'a str,
        captured: u64,
    }
    let receipt = Receipt {
        application_repository: &policy.endpoint.repository, snapshot: &snapshot,
        manifest_sha256: digest(&content), deployment_sha256: &job.source.deployment_sha256,
        vm_capture: &manifest.source.capture, captured: manifest.source.captured,
    };
    write_file(job.receipt, &serde_json::to_vec_pretty(&receipt)?)?;
    File::open(job.receipt.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))?.sync_all()?;
    println!("FVCA_STALWART_APPLICATION_BACKUP {snapshot}");
    Ok(())
}

fn recover(snapshot: &str, approved_manifest: &str, deployment: &str, dest: &Path,
           policy: &Policy, repo: &Repo<'_>, work: &Path) -> Result<()> {
    let content = repo.manifest(snapshot)?;
    if content.len() as u64 > MAX_MANIFEST || digest(&content) != approved_manifest {
        return Err(invalid("application manifest differs from independent recovery approval"));
    }
    let manifest: Manifest = serde_json::from_slice(&content)?;
    validate_manifest(&manifest, policy, deployment)?;
    repo.inventory(snapshot, content.len() as u64, &manifest.members)?;
    let bundle = work.join("recovered");
    for directory in [bundle.clone(), bundle.join("config"), bundle.join("data")] {
        create_directory(&directory)?;
    }
    for member in &manifest.members {
        let path = bundle.join(&member.path);
        repo.download(snapshot, member, new_file(&path)?)?;
        if file_hash(private_input(&path)?)? != member.sha256 {
            return Err(invalid("a recovered application file differs from its approved digest"));
        }
    }
    check_config(&bundle.join("config/config.json"))?;
    check_sqlite(&bundle.join("data/stalwart.db"), policy.timeout_seconds)?;
    write_file(&bundle.join(MANIFEST), &content)?;
    for path in [bundle.join("config"), bundle.join("data"), bundle.clone()] {
        File::open(path)?.sync_all()?;
    }
    create_directory(dest)?;
    fs::rename(bundle, dest.join("application"))?;
    File::open(dest)?.sync_all()?;
    File::open(dest.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))?.sync_all()?;
    println!("FVCA_STALWART_APPLICATION_RECOVERED {snapshot}");
    Ok(())
}

fn execute() -> Result<()> {
    let args = env::args_os().skip(1).map(PathBuf::from).collect::<Vec<_>>();
    let [policy_path, signature, authority, credentials, restic, ca, scratch, remaining @ ..] = args.as_slice() else {
        return Err(invalid("usage: fvca-stalwart-backup POLICY SIGNATURE AUTHORITY CREDENTIALS RESTIC CA SCRATCH (create VM_DISK VM_MANIFEST RECEIPT | recover DESTINATION)"));
    };
    let policy = Policy::approved(policy_path, signature, authority)?;
    let work = Scratch::in_parent(scratch)?;
    match (&policy.operation, remaining) {
        (Operation::Create { source, partition, filesystem, configuration }, [action, raw, vm_manifest, receipt])
            if action == Path::new("create") => {
                let repo = Repo::open(&policy, restic, credentials, ca, &work.0)?;
                create(Create { source, partition, filesystem, configuration, raw, vm_manifest, receipt },
                       &policy, &repo, &work.0)
            }
        (Operation::Recover { snapshot, manifest_sha256, deployment_sha256 }, [action, destination])
            if action == Path::new("recover") => {
                let repo = Repo::open(&policy, restic, credentials, ca, &work.0)?;
                recover(snapshot, manifest_sha256, deployment_sha256, destination, &policy, &repo, &work.0)
            }
        _ => Err(invalid("command does not match signed application approval")),
    }
}

fn main() -> ExitCode {
    if let Err(error) = execute() {
        eprintln!("FVCA Stalwart application backup failed: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
