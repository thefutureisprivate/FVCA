//! Stage a verified recovery set and commit its S3 receipt after upload.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

use fvca_initrd_bootstrap::backup_policy;

use super::{Consistency, Store, btrfs, complete_record, directory, disk_digest, files,
            guest_boot, invalid, lease, live, parse_plan, private_directory, publish,
            read_record, remove_stale_stage, run, runtime, stopped, verify_boot_files};

const OUTGOING: &str = "/run/fvca/host-data/captures/outgoing";
pub(super) const BACKUP_LOCK: &str = "/run/fvca/guest-backup.lock";

pub(super) fn mountable_directory(path: &Path) -> io::Result<()> {
    match fs::DirBuilder::new().mode(0o755).create(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o755))?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.gid() != 0 || metadata.mode() & 0o7777 != 0o755 {
        return Err(invalid("unexpected backup staging directory"));
    }
    Ok(())
}

fn readonly_copy(source: &Path, target: &Path) -> io::Result<()> {
    let parent = target.parent().expect("a staged file has a parent");
    if !target.try_exists()? {
        let scratch = parent.join(".backup.tmp");
        remove_stale_stage(&scratch)?;
        let output = OpenOptions::new().create_new(true).read(true).write(true).mode(0o600).open(&scratch)?;
        btrfs::reflink(&File::open(source)?, &output)?;
        output.set_permissions(fs::Permissions::from_mode(0o444))?;
        output.sync_all()?;
        fs::rename(scratch, target)?;
    }
    let meta = fs::symlink_metadata(target)?;
    if !meta.is_file() || meta.nlink() != 1 || meta.uid() != 0 || meta.gid() != 0 || meta.mode() & 0o7777 != 0o444 {
        return Err(invalid("unexpected backup staging file"));
    }
    Ok(())
}

pub(super) fn preflight_credentials(parent: &Path) -> io::Result<()> {
    private_directory(parent)?;
    for (name, bound) in [("repository-password", 4096), ("s3-credentials", 8192)] {
        let meta = fs::symlink_metadata(parent.join(name))?;
        if !meta.is_file() || meta.nlink() != 1 || meta.uid() != 0 || meta.gid() != 0
            || !matches!(meta.mode() & 0o7777, 0o400 | 0o600) || meta.len() == 0 || meta.len() > bound
        {
            return Err(invalid("unexpected protected backup credential"));
        }
    }
    Ok(())
}

fn snapshot_id(record: &str, repository: &str) -> io::Result<String> {
    let prefix = format!("FVCA-S3-VERIFIED-1\nrepository={repository}\nsnapshot=");
    let id = record.strip_prefix(&prefix).and_then(|line| line.strip_suffix('\n'))
        .ok_or_else(|| invalid("unexpected S3 upload verification record"))?;
    Ok(runtime::hash(id)?.to_owned())
}

pub(super) fn received_snapshot(record: &str, capture: &str, digest: &str, repository: &str) -> io::Result<String> {
    let prefix = format!("FVCA-S3-BACKUP-1\ncapture={capture}\ndisk_sha256={digest}\n");
    snapshot_id(record.strip_prefix(&prefix).ok_or_else(|| invalid("backup receipt scope mismatch"))?, repository)
}

fn release_stage(store: &Store, id: &str, pending: &str, selection: &guest_boot::Selection<'_>) -> io::Result<()> {
    let staging = Path::new(OUTGOING).join(id);
    if staging.try_exists()? {
        private_directory(&staging)?;
        let unit = format!("fvca-backup-upload@{id}.service");
        run(Command::new("/usr/bin/systemctl").args(["stop", &unit]))?;
        let input = staging.join("input");
        for name in files(selection) {
            remove_stale_stage(&input.join("release").join(name))?;
        }
        for name in ["data.raw", "manifest", ".backup.tmp"] {
            remove_stale_stage(&input.join(name))?;
        }
        remove_stale_stage(&input.join("release/.backup.tmp"))?;
        remove_stale_stage(&staging.join("result"))?;
    }
    remove_stale_stage(&store.path.join(pending))?;
    private_directory(&store.path)?.sync_all()
}

pub(crate) fn upload(id: &str, running: bool) -> io::Result<()> {
    let policy_text = fs::read_to_string(backup_policy::POLICY)?;
    let policy = backup_policy::parse(&policy_text)?;
    let _job = lease(Path::new(BACKUP_LOCK))?;
    upload_locked(id, running, &policy)
}

pub(super) fn upload_locked(id: &str, running: bool, policy: &backup_policy::Policy<'_>) -> io::Result<()> {
    super::uuid(id)?;
    preflight_credentials(Path::new(backup_policy::CREDENTIALS))?;
    let consistency = if running {
        live::capture(id)?;
        Consistency::Filesystem
    } else {
        stopped(id, true)?;
        Consistency::CleanStopped
    };
    let store = Store::open(id, consistency)?;
    let _pin = lease(&store.path.join("lock"))?;
    let (manifest, disk_hash, disk) = complete_record(&store, id, false)?;
    let manifest_path = store.path.join("manifest");
    if read_record(&manifest_path)? != manifest {
        return Err(invalid("backup capture differs from its finalized manifest"));
    }

    let text = read_record(&store.path.join("plan"))?;
    let plan = parse_plan(&text, id, &store)?;
    let selection = guest_boot::parse(plan.launch)?;
    let receipt = format!("backup-{}", policy.repository);
    let pending = format!("backup-pending-{}", policy.repository);
    if store.path.join(&receipt).try_exists()? {
        let saved = read_record(&store.path.join(&receipt))?;
        let snapshot = received_snapshot(&saved, id, &disk_hash, policy.repository)?;
        println!("FVCA_S3_BACKUP_COMPLETE {id} {snapshot}");
        return release_stage(&store, id, &pending, &selection);
    }
    btrfs::require_capture_space(&store.pool, 0)?;
    publish(&store.path, &pending, &format!("FVCA-S3-PENDING-1\ncapture={id}\ndisk_sha256={disk_hash}\n"))?;
    let unit = format!("fvca-backup-upload@{id}.service");
    // Reclaim an orphaned same-ID job before replacing its result descriptor.
    run(Command::new("/usr/bin/systemctl").args(["stop", &unit]))?;
    let out = Path::new(OUTGOING);
    directory(out)?;
    let staging = out.join(id);
    directory(&staging)?;
    let output = staging.join("result");
    remove_stale_stage(&output)?;
    OpenOptions::new().create_new(true).write(true).mode(0o600).open(&output)?;
    run(Command::new("/usr/bin/chcon").args([
        "--no-dereference", "system_u:object_r:fvca_backup_result_t:s0",
    ]).arg(&output))?;
    let input = staging.join("input");
    let release = input.join("release");
    mountable_directory(&input)?;
    mountable_directory(&release)?;
    readonly_copy(&disk, &input.join("data.raw"))?;
    readonly_copy(&manifest_path, &input.join("manifest"))?;
    let escrowed = store.releases.join(selection.bundle);
    for name in files(&selection) {
        readonly_copy(&escrowed.join(name), &release.join(name))?;
    }
    if disk_digest(&input.join("data.raw"))? != disk_hash || fs::read_to_string(input.join("manifest"))? != manifest {
        return Err(invalid("staged backup files differ from the verified capture"));
    }
    verify_boot_files(&release, &selection)?;
    File::open(&release)?.sync_all()?;
    File::open(&input)?.sync_all()?;
    File::open(&staging)?.sync_all()?;

    run(Command::new("/usr/bin/systemctl").args(["start", &unit]))?;
    let result = read_record(&output)?;
    let snapshot = snapshot_id(&result, policy.repository)?;
    publish(&store.path, &receipt, &format!("FVCA-S3-BACKUP-1\ncapture={id}\ndisk_sha256={disk_hash}\n{result}"))?;
    println!("FVCA_S3_BACKUP_COMPLETE {id} {snapshot}");
    release_stage(&store, id, &pending, &selection)
}
