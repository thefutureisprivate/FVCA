//! Cold-restore the registered Guest with a durable, reversible slot exchange.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use fvca_libvirt_boundary::{Connection, RUNNING};
use fvca_initrd_bootstrap::recovery;

use super::{Consistency, GUEST_UNIT, Store, attached_disk, backup, btrfs, complete_record, directory,
            disk_digest, guest_boot, invalid, lease, live, only_data_member, parse_plan_fields, private_directory,
            publish, raw_disk, read_record, remove_stale_stage, run, runtime, uuid, verify_boot_files, wait_for_lease};
use crate::{ALIAS, CAPTURE_LOCK, OPERATION_LOCK, PID, UUID, VM_DIRECTORY, verified_definition};

const RESTORES: &str = "/run/fvca/host-data/captures/restores";
const RESTORE_LOCK: &str = "/run/fvca/guest-restore.lock";
const DOWNLOADS: &str = "/run/fvca/host-data/captures/restore-downloads";
const VM_PARENT: &str = "/run/fvca/host-data/vms";
const HEADER: &str = "FVCA-GUEST-RESTORE-1";

struct Request<'a> {
    key: &'a str,
    capture: &'a str,
    id: &'a str,
}

impl<'a> Request<'a> {
    fn parse(key: &'a str) -> io::Result<Self> {
        let (capture, id) = key.split_once('.')
            .ok_or_else(|| invalid("provide the capture UUID followed by the restore UUID"))?;
        Ok(Self { key, capture: uuid(capture)?, id: uuid(id)? })
    }

    fn directory(&self) -> PathBuf {
        Path::new(RESTORES).join(self.id)
    }
}

struct Intent<'a> {
    bundle: &'a str,
    previous: Option<&'a str>,
    candidate: &'a str,
    digest: &'a str,
}

impl<'a> Intent<'a> {
    fn parse(text: &'a str, request: &Request<'_>) -> io::Result<Self> {
        let mut lines = text.lines();
        let binding = format!("request={}", request.key);
        if lines.next() != Some(HEADER) || lines.next() != Some(&binding) {
            return Err(invalid("the restore record belongs to a different operation"));
        }
        let mut field = |key| lines.next().and_then(|line| line.strip_prefix(key))
            .ok_or_else(|| invalid("the restore record is incomplete"));
        let bundle = runtime::hash(field("bundle=")?)?;
        let previous = match field("previous=")? {
            "none" => None,
            value => Some(uuid(value)?),
        };
        let candidate = uuid(field("candidate=")?)?;
        let digest = runtime::hash(field("disk_sha256=")?)?;
        if lines.next().is_some() || previous == Some(candidate) {
            return Err(invalid("unexpected restore record contents"));
        }
        Ok(Self { bundle, previous, candidate, digest })
    }

    fn installed(&self, dir: &Path) -> io::Result<bool> {
        let slot = volume_uuid(Path::new(VM_DIRECTORY))?;
        let branch = volume_uuid(&dir.join("branch"))?;
        match (slot.as_deref(), branch.as_deref()) {
            (slot, Some(branch)) if slot == self.previous && branch == self.candidate => Ok(false),
            (Some(slot), branch) if slot == self.candidate && branch == self.previous => Ok(true),
            _ => Err(invalid("restore volume identities do not match the recorded transaction")),
        }
    }
}

fn volume_uuid(path: &Path) -> io::Result<Option<String>> {
    match private_directory(path) {
        Ok(dir) => {
            let info = btrfs::subvolume(&dir)?;
            if info.read_only {
                return Err(invalid("a restore slot must be a writable Btrfs subvolume"));
            }
            Ok(Some(info.uuid))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn active() -> io::Result<Option<String>> {
    match read_record(&Path::new(RESTORES).join("active")) {
        Ok(text) => Ok(Some(Request::parse(text.trim_end())?.key.to_owned())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) fn require_idle() -> io::Result<()> {
    if let Some(key) = active()? {
        return Err(io::Error::other(format!("restore {key} owns the Guest operation lease")));
    }
    Ok(())
}

fn authorization() -> io::Result<Option<String>> {
    match fs::read_to_string(recovery::AUTHORIZATION) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) fn authorize_launch(bundle: &str) -> io::Result<()> {
    let state = active()?;
    let remote = authorization()?;
    let authorized = remote.as_deref().map(recovery::Request::parse).transpose()?.map(|request| request.key());
    let key = match (state.as_deref(), authorized.as_deref()) {
        (None, None) => return Ok(()),
        (Some(active), Some(expected)) if active != expected => return Err(invalid("another recovery owns the Guest identity")),
        (Some(active), _) => active,
        (None, Some(expected)) => expected,
    };
    let request = Request::parse(key)?;
    let dir = request.directory();
    private_directory(&dir)?;
    let text = read_record(&dir.join("intent"))?;
    let intent = Intent::parse(&text, &request)?;
    if let Some(remote) = remote {
        if remote != read_record(&dir.join("s3-authorization"))?
            || (state.is_none() && read_record(&dir.join("verified"))? != format!("RESTORE_VERIFIED\n{text}"))
        {
            return Err(invalid("the Guest disk has no approved recoverable identity"));
        }
    } else if dir.join("s3-authorization").try_exists()? {
        return Err(invalid("pending S3 recovery requires its authorized recovery UKI"));
    }
    if intent.bundle != bundle || dir.join("rollback").try_exists()?
        || read_record(&dir.join("trial"))? != "1\n" || !intent.installed(&dir)?
    {
        return Err(invalid("the in-progress restore has no authorized bootable candidate"));
    }
    Ok(())
}

fn require_stopped() -> io::Result<()> {
    let connection = Connection::connect()?;
    if connection.lookup(UUID)?.is_some() || Path::new(PID).try_exists()? || Path::new(ALIAS).try_exists()? {
        return Err(invalid("cold restore requires the Service Guest to be stopped and its disk detached"));
    }
    Ok(())
}

fn current_bundle() -> io::Result<String> {
    let payload = fs::read_to_string(guest_boot::SELECTION)?;
    let selection = guest_boot::parse(&payload)?;
    verified_definition(&selection)?;
    Ok(selection.bundle.to_owned())
}

fn stage_local(request: &Request<'_>, dir: &Path, bundle: &str) -> io::Result<()> {
    let mut store = Store::open(request.capture, Consistency::CleanStopped)?;
    private_directory(&store.path)?;
    let _pin = lease(&store.path.join("lock"))?;
    let manifest = read_record(&store.path.join("manifest"))?;
    let plan = read_record(&store.path.join("plan"))?;
    if plan.lines().next() == Some(Consistency::Filesystem.header()) {
        store.consistency = Consistency::Filesystem;
    }
    let (actual, digest, disk) = complete_record(&store, request.capture, false)?;
    if actual != manifest {
        return Err(invalid("the capture does not match its finalized manifest"));
    }
    let source = File::open(disk)?;
    let size = source.metadata()?.len();
    btrfs::require_capture_space(&store.pool, size)?;
    stage_disk(request, dir, bundle, &source, size, &digest)
}

fn stage_disk(request: &Request<'_>, dir: &Path, bundle: &str, source: &File, size: u64, digest: &str) -> io::Result<()> {
    let branch = dir.join("branch");
    let job = private_directory(dir)?;
    if !branch.try_exists()? {
        btrfs::create_subvolume(&job, "branch")?;
        fs::set_permissions(&branch, fs::Permissions::from_mode(0o700))?;
    }
    let root = private_directory(&branch)?;
    let data = branch.join("data.raw");
    let scratch = branch.join(".data.tmp");
    remove_stale_stage(&scratch)?;
    let new = OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&scratch)?;
    btrfs::reflink(source, &new)?;
    new.sync_all()?;
    let candidate = raw_disk(&scratch)?;
    if candidate.metadata()?.len() != size || recovery::sha256(candidate)? != digest {
        return Err(invalid("the staged Guest disk does not match the verified capture"));
    }
    fs::rename(&scratch, &data)?;
    only_data_member(&branch)?;
    root.sync_all()?;
    job.sync_all()?;
    let candidate = volume_uuid(&branch)?.ok_or_else(|| invalid("the restore candidate is missing"))?;
    let previous = volume_uuid(Path::new(VM_DIRECTORY))?;
    let text = format!("{HEADER}\nrequest={}\nbundle={bundle}\nprevious={}\ncandidate={candidate}\ndisk_sha256={digest}\n",
                       request.key, previous.as_deref().unwrap_or("none"));
    publish(dir, "intent", &text)
}

fn download_file(path: &Path) -> io::Result<()> {
    let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    run(Command::new("/usr/bin/chcon").args([
        "--no-dereference", "system_u:object_r:fvca_restore_data_t:s0",
    ]).arg(path))?;
    file.set_permissions(fs::Permissions::from_mode(0o666))
}

fn seal_download(path: &Path) -> io::Result<File> {
    let stat = fs::symlink_metadata(path)?;
    if !stat.is_file() || stat.nlink() != 1 || stat.uid() != 0 || stat.gid() != 0 || stat.mode() & 0o7777 != 0o666 {
        return Err(invalid("unexpected file in the isolated recovery set"));
    }
    let file = File::open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    Ok(file)
}

fn received_plan<'a>(manifest: &'a str, request: &recovery::Request<'_>) -> io::Result<super::Plan<'a>> {
    let mut lines = manifest.splitn(5, '\n');
    if lines.next() != Some("CAPTURE_COMPLETE") {
        return Err(invalid("the downloaded recovery set is incomplete"));
    }
    let snapshot = uuid(lines.next().and_then(|line| line.strip_prefix("snapshot_uuid="))
        .ok_or_else(|| invalid("missing recovered snapshot UUID"))?)?;
    let root_id = lines.next().and_then(|line| line.strip_prefix("snapshot_id="))
        .and_then(|value| value.parse::<u64>().ok()).filter(|id| *id >= 256)
        .ok_or_else(|| invalid("invalid recovered snapshot ID"))?;
    if lines.next().and_then(|line| line.strip_prefix("disk_sha256=")) != Some(request.disk) {
        return Err(invalid("recovered manifest has a mismatched disk digest"));
    }
    let plan = lines.next().ok_or_else(|| invalid("missing recovered capture plan"))?;
    let consistency = if plan.starts_with(Consistency::Filesystem.header()) { Consistency::Filesystem } else { Consistency::CleanStopped };
    let parsed = parse_plan_fields(plan, request.capture, consistency, None)?;
    if parsed.source == snapshot || parsed.source_id == root_id || parsed.bytes != request.disk_bytes {
        return Err(invalid("recovered snapshot topology or size does not match the capture"));
    }
    Ok(parsed)
}

fn discard_download(unit: &str, staged: &Path) -> io::Result<()> {
    run(Command::new("/usr/bin/systemctl").args(["stop", unit]))?;
    if staged.try_exists()? {
        backup::mountable_directory(staged)?;
        fs::remove_dir_all(staged)?;
        File::open(Path::new(DOWNLOADS))?.sync_all()?;
    }
    Ok(())
}

fn download(request: &Request<'_>, dir: &Path, bundle: &str, remote: &recovery::Request<'_>) -> io::Result<()> {
    backup::preflight_credentials(Path::new(recovery::CREDENTIALS))?;
    btrfs::require_capture_space(&crate::verify_pool()?, remote.total_bytes)?;
    let unit = format!("fvca-backup-download@{}.service", request.key);
    let parent = Path::new(DOWNLOADS);
    directory(parent)?;
    let staged = parent.join(request.key);
    discard_download(&unit, &staged)?;
    let result = (|| {
        backup::mountable_directory(&staged)?;
        let release = staged.join("release");
        backup::mountable_directory(&release)?;
        for name in guest_boot::FILES {
            download_file(&release.join(name))?;
        }
        let disk_file = staged.join("data.raw");
        let manifest_file = staged.join("manifest");
        download_file(&disk_file)?;
        download_file(&manifest_file)?;
        run(Command::new("/usr/bin/systemctl").args(["start", &unit]))?;
        let disk = seal_download(&disk_file)?;
        let mut size = disk.metadata()?.len();
        let manifest = seal_download(&manifest_file)?;
        let manifest_size = manifest.metadata()?.len();
        if size != remote.disk_bytes || manifest_size > 8192 || recovery::sha256(manifest)? != remote.manifest {
            return Err(invalid("downloaded recovery manifest or disk size differs from authorization"));
        }
        for name in guest_boot::FILES {
            size = size.checked_add(seal_download(&release.join(name))?.metadata()?.len())
                .ok_or_else(|| invalid("recovery set size overflows"))?;
        }
        if size.checked_add(manifest_size) != Some(remote.total_bytes) {
            return Err(invalid("downloaded recovery set size differs from authorization"));
        }
        let text = fs::read_to_string(manifest_file)?;
        let plan = received_plan(&text, remote)?;
        verify_boot_files(&release, &guest_boot::parse(plan.launch)?)?;
        btrfs::require_cow_and_checksums(&disk)?;
        stage_disk(request, dir, bundle, &disk, remote.disk_bytes, remote.disk)
    })();
    result.and(discard_download(&unit, &staged))
}

fn move_slot(dir: &Path, intent: &Intent<'_>, install: bool) -> io::Result<()> {
    let job = private_directory(dir)?;
    let vms = private_directory(Path::new(VM_PARENT))?;
    let pool = btrfs::filesystem_uuid(&crate::verify_pool()?)?;
    if btrfs::filesystem_uuid(&job)? != pool || btrfs::filesystem_uuid(&vms)? != pool {
        return Err(invalid("both restore slots must be on the authorized Host pool"));
    }
    if intent.installed(dir)? != install {
        let branch = dir.join("branch");
        let slot = Path::new(VM_DIRECTORY);
        for path in [branch.as_path(), slot] {
            if path.try_exists()? {
                run(Command::new("/usr/bin/chcon").args([
                    "--no-dereference", "system_u:object_r:fvca_vm_slot_t:s0",
                ]).arg(path))?;
            }
        }
        if install {
            btrfs::place_subvolume(&job, c"branch", &vms, c"service-guest", intent.previous.is_some())?;
        } else {
            btrfs::place_subvolume(&vms, c"service-guest", &job, c"branch", intent.previous.is_some())?;
        }
    }
    if intent.installed(dir)? != install {
        return Err(invalid("the restore slot exchange did not reach the requested state"));
    }
    job.sync_all()?;
    vms.sync_all()
}

fn clear(request: &Request<'_>) -> io::Result<()> {
    if active()?.as_deref() == Some(request.key) {
        fs::remove_file(Path::new(RESTORES).join("active"))?;
        private_directory(Path::new(RESTORES))?.sync_all()?;
    }
    Ok(())
}

fn control(action: &str) -> io::Result<()> {
    run(Command::new("/usr/bin/systemctl").args([action, GUEST_UNIT]))
}

fn verify_running(intent: &Intent<'_>, dir: &Path) -> io::Result<()> {
    if !intent.installed(dir)? {
        return Err(invalid("the restored volume is no longer installed"));
    }
    live::require_instance(intent.bundle)?;
    attached_disk()?;
    let connection = Connection::connect()?;
    let domain = connection.lookup(UUID)?.ok_or_else(|| invalid("the restored Service Guest is absent"))?;
    if domain.state()? != RUNNING || domain.guest_frozen()? {
        return Err(invalid("the restored Service Guest is not running and thawed"));
    }
    domain.require_guest_agent()
}

fn rollback(request: &Request<'_>, dir: &Path, intent: &Intent<'_>) -> io::Result<()> {
    {
        let _capture = wait_for_lease(Path::new(CAPTURE_LOCK))?;
        publish(dir, "rollback", "1\n")?;
    }
    control("stop")?;
    let _capture = wait_for_lease(Path::new(CAPTURE_LOCK))?;
    let _operation = lease(Path::new(OPERATION_LOCK))?;
    require_stopped()?;
    // Discard any queued failure handler while the trial is still identified.
    run(Command::new("/usr/bin/systemctl").args(["stop", "fvca-guest-failure.service"]))?;
    move_slot(dir, intent, false)?;
    publish(dir, "rolled-back", "1\n")?;
    clear(request)?;
    println!("FVCA_RESTORE_ROLLED_BACK {}", request.key);
    Ok(())
}

pub(crate) fn cold_restore(key: &str, from_s3: bool) -> io::Result<()> {
    let request = Request::parse(key)?;
    let authorization = authorization()?;
    let remote = authorization.as_deref().map(recovery::Request::parse).transpose()?;
    if from_s3 != remote.is_some() || remote.as_ref().is_some_and(|remote| remote.key() != key) {
        return Err(invalid("the requested restore mode or ID is outside boot authorization"));
    }
    let _restore = lease(Path::new(RESTORE_LOCK))?;
    let capture = lease(Path::new(CAPTURE_LOCK))?;
    live::require_idle()?;
    crate::verify_pool()?;
    let state = active()?;
    if state.as_deref().is_some_and(|owner| owner != request.key) {
        return Err(invalid("a different Guest restore is already pending"));
    }
    let base = Path::new(RESTORES);
    directory(base.parent().expect("restore journals have a parent"))?;
    directory(base)?;
    let dir = request.directory();
    directory(&dir)?;
    publish(&dir, "request", &format!("{key}\n"))?;
    let authorization_path = dir.join("s3-authorization");
    let has_remote = authorization_path.try_exists()?;
    if (has_remote && !from_s3) || (!has_remote && from_s3 && dir.join("intent").try_exists()?) {
        return Err(invalid("the restore operation has a different source"));
    }
    if let Some(authorization) = authorization.as_deref() {
        publish(&dir, "s3-authorization", authorization)?;
    }
    if dir.join("verified").try_exists()? {
        let text = read_record(&dir.join("intent"))?;
        Intent::parse(&text, &request)?;
        if read_record(&dir.join("verified"))? != format!("RESTORE_VERIFIED\n{text}") {
            return Err(invalid("the verified restore receipt differs from its intent"));
        }
        clear(&request)?;
        println!("FVCA_RESTORE_VERIFIED {key}");
        return Ok(());
    }
    if dir.join("rolled-back").try_exists()? {
        if read_record(&dir.join("rolled-back"))? != "1\n" {
            return Err(invalid("unexpected rollback receipt"));
        }
        clear(&request)?;
        return Err(invalid("this restore was rolled back"));
    }
    let operation = lease(Path::new(OPERATION_LOCK))?;
    let bundle = current_bundle()?;
    let prepared = dir.join("intent").try_exists()?;
    if prepared && from_s3 {
        let unit = format!("fvca-backup-download@{key}.service");
        discard_download(&unit, &Path::new(DOWNLOADS).join(key))?;
    }
    if !prepared {
        require_stopped()?;
        directory(Path::new(VM_PARENT))?;
        if let Some(remote) = remote.as_ref() {
            download(&request, &dir, &bundle, remote)?;
        } else {
            stage_local(&request, &dir, &bundle)?;
        }
    }
    let text = read_record(&dir.join("intent"))?;
    let intent = Intent::parse(&text, &request)?;
    if dir.join("rollback").try_exists()? || (state.as_deref() == Some(key) && bundle != intent.bundle) {
        drop(operation);
        drop(capture);
        rollback(&request, &dir, &intent)?;
        return Err(invalid("the unfinished restore was rolled back"));
    }
    if bundle != intent.bundle {
        return Err(invalid("the currently authorized Guest release changed during restoration"));
    }
    if !dir.join("trial").try_exists()? {
        require_stopped()?;
        if prepared {
            let candidate = if intent.installed(&dir)? { PathBuf::from(VM_DIRECTORY) } else { dir.join("branch") };
            let disk = only_data_member(&candidate)?;
            raw_disk(&disk)?;
            if disk_digest(&disk)? != intent.digest {
                return Err(invalid("the prepared restore disk differs from the verified capture"));
            }
        }
        publish(base, "active", &format!("{key}\n"))?;
        move_slot(&dir, &intent, true)?;
        publish(&dir, "trial", "1\n")?;
    } else if state.as_deref() != Some(key) || !intent.installed(&dir)? {
        return Err(invalid("the pending restore lost its authorized trial volume"));
    }
    drop(operation);
    drop(capture);

    if let Err(error) = control("start").and_then(|()| verify_running(&intent, &dir)) {
        eprintln!("FVCA restored Guest did not reach readiness: {error}");
        rollback(&request, &dir, &intent)?;
        return Err(error);
    }
    let _capture = wait_for_lease(Path::new(CAPTURE_LOCK))?;
    let _operation = lease(Path::new(OPERATION_LOCK))?;
    verify_running(&intent, &dir)?;
    publish(&dir, "verified", &format!("RESTORE_VERIFIED\n{text}"))?;
    clear(&request)?;
    println!("FVCA_RESTORE_VERIFIED {key}");
    Ok(())
}
