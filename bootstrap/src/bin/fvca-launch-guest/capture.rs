//! Persist a complete stopped capture of the fixed, networkless Service Guest.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use fvca_btrfs_boundary::{self as btrfs, Subvolume};
use fvca_initrd_bootstrap::{guest_boot, identity, invalid, run, runtime};
use fvca_libvirt_boundary::Connection;

use super::{ALIAS, CAPTURE_LOCK, DISK, OPERATION_LOCK, PID, POOL, RECEIPT, UUID, private_directory, raw_disk,
            raw_disk_metadata, verified_definition, verify_boot_files, verify_data, verify_pool, verify_storage_directory};

const CAPTURE_HEADER: &str = "FVCA-STOPPED-CAPTURE-1";
const UUID_GROUPS: &[usize] = &[8, 4, 4, 4, 12];
const GUEST_UNIT: &str = "fvca-service-guest.service";
const O_NOFOLLOW: i32 = 0o400000;

fn lock_file(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new().read(true).write(true).create(true).truncate(false)
        .custom_flags(O_NOFOLLOW).mode(0o600).open(path)?;
    let stat = file.metadata()?;
    if !stat.is_file() || stat.nlink() != 1 || stat.uid() != 0 || stat.gid() != 0 || stat.mode() & 0o7777 != 0o600 {
        return Err(invalid("invalid FVCA lease file"));
    }
    Ok(file)
}

pub(super) fn lease(path: &Path) -> io::Result<File> {
    let file = lock_file(path)?;
    file.try_lock().map_err(io::Error::from)?;
    Ok(file)
}

pub(super) fn wait_for_lease(path: &Path) -> io::Result<File> {
    let file = lock_file(path)?;
    file.lock()?;
    Ok(file)
}

fn directory(path: &Path) -> io::Result<File> {
    let builder = &mut fs::DirBuilder::new();
    match builder.mode(0o700).create(path) {
        Ok(()) => File::open(path.parent().expect("FVCA paths have a parent"))?.sync_all()?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    private_directory(path)
}

fn read_record(path: &Path) -> io::Result<String> {
    let stat = fs::symlink_metadata(path)?;
    if !stat.is_file() || stat.nlink() != 1 || stat.uid() != 0 || stat.gid() != 0 || stat.mode() & 0o7777 != 0o600 {
        return Err(invalid("unexpected capture record file"));
    }
    let mut text = String::new();
    File::open(path)?.take(8193).read_to_string(&mut text)?;
    if text.len() > 8192 {
        return Err(invalid("capture record exceeds its size bound"));
    }
    Ok(text)
}

fn remove_stale_stage(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

pub(super) fn publish(dir: &Path, name: &str, text: &str) -> io::Result<()> {
    let path = dir.join(name);
    if path.try_exists()? {
        if read_record(&path)? != text {
            return Err(invalid("an immutable capture record already differs"));
        }
        return File::open(dir)?.sync_all();
    }
    let staged = dir.join(format!(".{name}.tmp"));
    remove_stale_stage(&staged)?;
    let mut file = OpenOptions::new().create_new(true).write(true).mode(0o600).open(&staged)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    fs::rename(staged, path)?;
    File::open(dir)?.sync_all()
}

pub(super) fn stop_receipt(root: &File, disk: &File) -> io::Result<String> {
    let subvol = btrfs::subvolume(root)?;
    let meta = disk.metadata()?;
    Ok(format!("{}:{}:{}:{}:{}:{}:{}:{}\n", subvol.uuid, subvol.id, meta.ino(), meta.len(),
               meta.mtime(), meta.mtime_nsec(), meta.ctime(), meta.ctime_nsec()))
}

fn uuid(value: &str) -> io::Result<&str> {
    identity(value, "", UUID_GROUPS, '-')
}

fn files<'a>(selection: &guest_boot::Selection<'a>) -> impl Iterator<Item = &'a str> {
    // guest_boot::parse requires the exact ordered allowlist.
    selection.checksums.lines().map(|line| &line[66..])
}

fn escrow(releases: &Path, payload: &str, pool: &File, disk_size: u64) -> io::Result<()> {
    let selection = guest_boot::parse(payload)?;
    let dir = releases.join(selection.bundle);
    directory(&dir)?;
    if dir.join("selection").try_exists()? {
        return verify_escrow(&dir, payload, &selection);
    }
    let boot = Path::new(guest_boot::BOOT);
    let mut required = disk_size;
    for name in files(&selection) {
        required = required.checked_add(boot.join(name).metadata()?.len())
            .ok_or_else(|| invalid("capture space requirement overflows"))?;
    }
    btrfs::require_capture_space(pool, required)?;
    for name in files(&selection) {
        let staged = dir.join(".member.tmp");
        remove_stale_stage(&staged)?;
        run(Command::new("/usr/bin/cp").args(["--sparse=always", "--reflink=never", "--no-target-directory", "--"])
            .arg(boot.join(name)).arg(&staged))?;
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o400))?;
        File::open(&staged)?.sync_all()?;
        fs::rename(staged, dir.join(name))?;
    }
    verify_boot_files(&dir, &selection)?;
    File::open(&dir)?.sync_all()?;
    publish(&dir, "selection", payload)
}

fn verify_escrow(dir: &Path, payload: &str, selection: &guest_boot::Selection<'_>) -> io::Result<()> {
    private_directory(dir)?;
    if read_record(&dir.join("selection"))? != payload {
        return Err(invalid("the retained Guest release has a different launch selection"));
    }
    for name in files(selection) {
        let stat = fs::symlink_metadata(dir.join(name))?;
        if !stat.is_file() || stat.nlink() != 1 || stat.uid() != 0 || stat.gid() != 0 || stat.mode() & 0o7777 != 0o400 {
            return Err(invalid("invalid retained Guest release file"));
        }
    }
    verify_boot_files(dir, selection)
}

struct Plan<'a> {
    source: &'a str,
    bytes: u64,
    launch: &'a str,
}

fn parse_plan<'a>(text: &'a str, id: &str, fsid: &str) -> io::Result<Plan<'a>> {
    let launch_header = "FVCA-GUEST-LAUNCH-1\n";
    let start = text.find(launch_header).ok_or_else(|| invalid("capture record lacks its authorized launch selection"))?;
    let (prefix, launch) = text.split_at(start);
    guest_boot::parse(launch)?;
    let mut lines = prefix.lines();
    for expected in [CAPTURE_HEADER.to_owned(), format!("capture_id={id}"), format!("vm_uuid={}", UUID.to_str().unwrap()),
        "requested_consistency=clean-stopped".to_owned(), "achieved_consistency=clean-stopped".to_owned(),
        format!("filesystem_uuid={fsid}"), "identity_policy=single-instance".to_owned(),
        "persistent_firmware=none".to_owned(), "persistent_vtpm=none".to_owned(),
        "external_storage=none".to_owned(), "workload_state=contained-in-data.raw".to_owned(),
        "member=data.raw,raw,vdc".to_owned()] {
        if lines.next() != Some(expected.as_str()) {
            return Err(invalid("unexpected stopped capture fields"));
        }
    }
    let mut take = |key| lines.next().and_then(|line| line.strip_prefix(key))
        .ok_or_else(|| invalid("incomplete stopped capture metadata"));
    let source = uuid(take("source_uuid=")?)?;
    let number = |value: &str| value.parse::<u64>().map_err(io::Error::other);
    let root_id = number(take("source_id=")?)?;
    let time = number(take("capture_unix_seconds=")?)?;
    let bytes = number(take("disk_bytes=")?)?;
    if root_id < 256 || time == 0 || bytes == 0 || !bytes.is_multiple_of(512) || lines.next().is_some() {
        return Err(invalid("invalid stopped capture metadata"));
    }
    Ok(Plan { source, bytes, launch })
}

fn snapshot(dir: &Path, plan: &Plan<'_>) -> io::Result<(Subvolume, PathBuf)> {
    let path = dir.join("snapshot");
    let info = btrfs::subvolume(&private_directory(&path)?)?;
    if !info.read_only || info.parent_uuid != plan.source || info.uuid == plan.source {
        return Err(invalid("the Btrfs snapshot does not match the sealed source"));
    }
    let mut members = fs::read_dir(&path)?;
    if members.next().transpose()?.as_ref().is_none_or(|entry| entry.file_name() != "data.raw")
        || members.next().transpose()?.is_some()
    {
        return Err(invalid("the captured subvolume has unexpected members"));
    }
    let data = path.join("data.raw");
    if raw_disk(&data)?.metadata()?.len() != plan.bytes {
        return Err(invalid("the captured raw disk length changed"));
    }
    Ok((info, data))
}

fn snapshot_record(snapshot: &Subvolume) -> String {
    format!("snapshot_uuid={}\nsnapshot_id={}\n", snapshot.uuid, snapshot.id)
}

fn seal(dir: &Path, id: &str, fsid: &str, text: &str) -> io::Result<()> {
    let (info, _) = snapshot(dir, &parse_plan(text, id, fsid)?)?;
    let record = format!("CAPTURE_SEALED_PENDING_VALIDATION\n{}{text}", snapshot_record(&info));
    publish(dir, "sealed", &record)?;
    println!("FVCA_CAPTURE_SEALED_PENDING_VALIDATION {id} {}", info.uuid);
    Ok(())
}

fn finalize(dir: &Path, releases: &Path, id: &str, fsid: &str) -> io::Result<()> {
    let _pin = lease(&dir.join("lock"))?;
    let text = read_record(&dir.join("plan"))?;
    let plan = parse_plan(&text, id, fsid)?;
    let (info, data) = snapshot(dir, &plan)?;
    let state = snapshot_record(&info);
    let sealed = format!("CAPTURE_SEALED_PENDING_VALIDATION\n{state}{text}");
    publish(dir, "sealed", &sealed)?;
    let selection = guest_boot::parse(plan.launch)?;
    verify_escrow(&releases.join(selection.bundle), plan.launch, &selection)?;
    let output = Command::new("/usr/bin/sha256sum").env_clear()
        .current_dir(data.parent().expect("captured disk is below its snapshot"))
        .arg("data.raw").output()?;
    if !output.status.success() {
        return Err(invalid("could not hash the sealed raw disk"));
    }
    let digest = String::from_utf8(output.stdout).map_err(io::Error::other)?;
    let digest = runtime::hash(digest.strip_suffix("  data.raw\n")
        .ok_or_else(|| invalid("unexpected captured disk digest output"))?)?;
    if snapshot(dir, &plan)?.0 != info {
        return Err(invalid("Btrfs snapshot identity changed during finalization"));
    }
    let manifest = format!("CAPTURE_COMPLETE\n{state}disk_sha256={digest}\n{text}");
    publish(dir, "manifest", &manifest)?;
    println!("FVCA_CAPTURE_COMPLETE {id} {digest}");
    Ok(())
}

pub(super) fn stopped(id: &str, restart: bool) -> io::Result<()> {
    uuid(id)?;
    let pool = verify_pool()?;
    let fsid = btrfs::filesystem_uuid(&pool)?;
    let base = Path::new(POOL).join("captures");
    directory(&base)?;
    let releases = base.join("releases");
    let sets = base.join("sets");
    directory(&releases)?;
    directory(&sets)?;
    let path = sets.join(id);
    let guard = lease(Path::new(CAPTURE_LOCK))?;
    if path.try_exists()? {
        private_directory(&path)?;
        drop(guard);
        return finalize(&path, &releases, id, &fsid);
    }
    let launch = fs::read_to_string(guest_boot::SELECTION)?;
    let selection = guest_boot::parse(&launch)?;
    verified_definition(&selection)?;
    let connection = Connection::connect()?;
    let running = connection.lookup(UUID)?.is_some();
    let bytes = if running {
        // The active sVirt attachment has libvirt's temporary ownership.
        verify_storage_directory()?;
        let source = raw_disk_metadata(Path::new(DISK))?;
        let attachment = raw_disk_metadata(Path::new(ALIAS))?;
        if source.dev() != attachment.dev() || source.ino() != attachment.ino() {
            return Err(invalid("the running Guest attachment does not match its raw disk"));
        }
        source.len()
    } else {
        verify_data()?.1.metadata()?.len()
    };
    escrow(&releases, &launch, &pool, bytes)?;
    btrfs::require_capture_space(&pool, bytes)?;

    // Normal systemd stop can take the lifecycle lock while the capture lease
    // holds any new start before it reaches the data attachment.
    if running {
        run(Command::new("/usr/bin/systemctl").args(["stop", GUEST_UNIT]))?;
    }
    {
        let _lifecycle = lease(Path::new(OPERATION_LOCK))?;
        if connection.lookup(UUID)?.is_some() || Path::new(PID).try_exists()? || Path::new(ALIAS).try_exists()? {
            return Err(invalid("the Guest or its disk attachment is still active"));
        }
        let (root, disk) = verify_data()?;
        let source = btrfs::subvolume(&root)?;
        if source.read_only || disk.metadata()?.len() != bytes
            || read_record(Path::new(RECEIPT))? != stop_receipt(&root, &disk)?
        {
            return Err(invalid("the selected raw disk has no matching orderly stop receipt"));
        }
        disk.sync_all()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_secs();
        let text = format!("{CAPTURE_HEADER}\ncapture_id={id}\nvm_uuid={}\nrequested_consistency=clean-stopped\n\
            achieved_consistency=clean-stopped\nfilesystem_uuid={fsid}\nidentity_policy=single-instance\n\
            persistent_firmware=none\npersistent_vtpm=none\nexternal_storage=none\nworkload_state=contained-in-data.raw\n\
            member=data.raw,raw,vdc\nsource_uuid={}\nsource_id={}\ncapture_unix_seconds={now}\ndisk_bytes={bytes}\n{launch}",
            UUID.to_str().unwrap(), source.uuid, source.id);
        let dir = directory(&path)?;
        publish(&path, "plan", &text)?;
        btrfs::snapshot_read_only(&root, &dir, "snapshot")?;
        dir.sync_all()?;
        seal(&path, id, &fsid, &text)?;
    }
    drop(guard);
    let recovered = if running && restart {
        run(Command::new("/usr/bin/systemctl").args(["start", GUEST_UNIT]))
    } else {
        Ok(())
    };
    if running && restart && recovered.is_ok() {
        println!("FVCA_CAPTURE_GUEST_RESUMED {id}");
    }
    finalize(&path, &releases, id, &fsid)?;
    recovered
}
