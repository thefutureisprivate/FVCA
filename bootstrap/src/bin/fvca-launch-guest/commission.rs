//! Install the exact initial Service Guest data without mounting its filesystem.

use std::path::Path;

use fvca_initrd_bootstrap::{guest_boot::Commissioning, recovery};

use super::{
    ALIAS, CAPTURE_LOCK, Connection, File, MetadataExt, OPERATION_LOCK, OpenOptions, OpenOptionsExt, PID,
    UUID, btrfs, directory, fs, guest_boot, invalid, io, live, only_data_member, optional_record,
    private_directory, publish, raw_disk, remove_stale_stage, restore, uuid, wait_for_lease,
};
use crate::{ATTACHMENT, VM_PARENT, require_pool_path};

const JOB: &str = "/run/fvca/host-data/guest-commissioning";

fn require_disk(disk: File, policy: &Commissioning<'_>) -> io::Result<()> {
    if disk.metadata()?.len() != policy.bytes || recovery::sha256(disk)? != policy.digest {
        return Err(invalid("the Guest disk does not match the signed commissioning seed"));
    }
    Ok(())
}

fn volume(path: &Path, fsid: &str) -> io::Result<Option<String>> {
    let dir = match private_directory(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        result => result?,
    };
    if btrfs::filesystem_uuid(&dir)? != fsid || dir.metadata()?.ino() != 256 {
        return Err(invalid("commissioning requires an authorized Btrfs subvolume"));
    }
    let info = btrfs::subvolume(&dir)?;
    if info.read_only {
        return Err(invalid("the Guest data volume must be writable"));
    }
    Ok(Some(info.uuid))
}

fn ready(job: &Path) -> io::Result<Option<String>> {
    let text = optional_record(&job.join("ready"))?;
    if let Some(text) = &text {
        uuid(text.strip_suffix('\n').ok_or_else(|| invalid("invalid commissioning volume receipt"))?)?;
    }
    Ok(text)
}

fn installed(job: &Path) -> io::Result<bool> {
    let Some(installed) = optional_record(&job.join("installed"))? else { return Ok(false) };
    if ready(job)?.as_ref() != Some(&installed) {
        return Err(invalid("the commissioning installation differs from the prepared subvolume"));
    }
    Ok(true)
}

fn stage(pool: &File, job: &Path, branch: &Path, fsid: &str, policy: &Commissioning<'_>) -> io::Result<String> {
    let seed = raw_disk(&job.join("seed.raw"))?;
    if seed.metadata()?.len() != policy.bytes {
        return Err(invalid("the Service Guest commissioning seed differs in size"));
    }
    if !btrfs::headroom(pool)?.affords(policy.bytes, 64 * 1024 * 1024) {
        return Err(invalid("insufficient mirrored Btrfs space for the initial Guest disk"));
    }
    if volume(branch, fsid)?.is_none() {
        // The commissioning service's private umask applies to new subvolumes.
        btrfs::create_subvolume(&private_directory(job)?, "branch")?;
    }
    let root = private_directory(branch)?;
    btrfs::require_cow_and_checksums(&root)?;
    let scratch = branch.join(".data.tmp");
    remove_stale_stage(&scratch)?;
    let checked = (|| {
        let new = OpenOptions::new().write(true).read(true).create_new(true).mode(0o600).open(&scratch)?;
        btrfs::reflink(&seed, &new)?;
        new.sync_all()?;
        require_disk(raw_disk(&scratch)?, policy)
    })();
    if let Err(error) = checked {
        remove_stale_stage(&scratch)?;
        return Err(error);
    }
    fs::rename(&scratch, branch.join("data.raw"))?;
    only_data_member(branch)?;
    root.sync_all()?;
    btrfs::sync(pool)?;
    volume(branch, fsid)?.ok_or_else(|| invalid("the staged Guest subvolume disappeared"))
}

fn install(
    pool: &File,
    job: &Path,
    vms: &Path,
    text: &str,
    label: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let policy = Commissioning::parse(text)?;
    let fsid = btrfs::filesystem_uuid(pool)?;
    btrfs::require_raid1_profiles(pool)?;
    let journal = private_directory(job)?;
    let parent = private_directory(vms)?;
    if btrfs::filesystem_uuid(&journal)? != fsid || btrfs::filesystem_uuid(&parent)? != fsid {
        return Err(invalid("commissioning must use the authorized Host pool"));
    }
    let branch = job.join("branch");
    let slot = vms.join("service-guest");
    if !installed(job)? {
        let slot_uuid = volume(&slot, &fsid)?;
        let prepared = ready(job)?;
        if prepared.is_none() && slot_uuid.is_some() {
            return Err(invalid("commissioning cannot replace or adopt a registered Guest disk"));
        }
        if optional_record(&job.join("request"))?.is_none()
            && (prepared.is_some() || volume(&branch, &fsid)?.is_some())
        {
            return Err(invalid("the staged Guest disk has no commissioning request"));
        }
        publish(job, "request", text)?;
        let expected = if let Some(record) = prepared {
            let expected = record.trim_end();
            let staged = volume(&branch, &fsid)?;
            let disk = match (staged.as_deref(), slot_uuid.as_deref()) {
                (Some(staged), None) if staged == expected => &branch,
                (None, Some(current)) if current == expected => &slot,
                _ => return Err(invalid("the Guest subvolume differs from the commissioning journal")),
            };
            require_disk(raw_disk(&only_data_member(disk)?)?, &policy)?;
            expected.to_owned()
        } else {
            let expected = stage(pool, job, &branch, &fsid, &policy)?;
            publish(job, "ready", &format!("{expected}\n"))?;
            btrfs::sync(pool)?;
            expected
        };
        if slot_uuid.is_none() {
            label(&branch)?;
            btrfs::place_subvolume(&journal, c"branch", &parent, c"service-guest", false)?;
        }
        if volume(&slot, &fsid)?.as_deref() != Some(&expected) {
            return Err(invalid("the initial Guest slot has a different subvolume identity"));
        }
        btrfs::sync(pool)?;
        publish(job, "installed", &format!("{expected}\n"))?;
        btrfs::sync(pool)?;
        println!("FVCA_GUEST_DATA_COMMISSIONED {expected}");
    } else if optional_record(&job.join("request"))?.as_deref() != Some(text) || volume(&slot, &fsid)?.is_none() {
        return Err(invalid("commissioning cannot recreate or replace an installed Guest disk"));
    }
    // Retire only a seed that still matches this authorization. A later
    // authorized cold restore may replace the mutable disk in the slot.
    let seed = job.join("seed.raw");
    match raw_disk(&seed) {
        Ok(disk) => {
            require_disk(disk, &policy)?;
            fs::remove_file(seed)?;
            journal.sync_all()?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    Ok(())
}

fn launch_allowed(job: &Path, selected: Option<&str>) -> io::Result<()> {
    let request = optional_record(&job.join("request"))?;
    match (selected, request.as_deref()) {
        (None, None) if ready(job)?.is_none() && !job.join("installed").try_exists()? => Ok(()),
        (selected, Some(request)) if selected.is_none_or(|text| text == request) && installed(job)? => Ok(()),
        _ => Err(invalid("the authorized initial Guest disk has not been installed")),
    }
}

pub(crate) fn require_installed() -> io::Result<()> {
    let text = optional_record(Path::new(guest_boot::COMMISSIONING_RUNTIME))?;
    let job = Path::new(JOB);
    match private_directory(job) {
        Err(error) if error.kind() == io::ErrorKind::NotFound && text.is_none() => return Ok(()),
        result => result?,
    };
    require_pool_path(job)?;
    launch_allowed(job, text.as_deref())
}

pub(crate) fn run() -> io::Result<()> {
    let text = optional_record(Path::new(guest_boot::COMMISSIONING_RUNTIME))?
        .ok_or_else(|| invalid("no verified Service Guest commissioning authorization"))?;
    let policy = Commissioning::parse(&text)?;
    let launch = fs::read_to_string(guest_boot::SELECTION)?;
    let selection = guest_boot::parse(&launch)?;
    if selection.bundle != policy.bundle {
        return Err(invalid("the initial Guest disk is authorized for a different boot bundle"));
    }
    let _capture = wait_for_lease(Path::new(CAPTURE_LOCK))?;
    let _operation = super::lease(Path::new(OPERATION_LOCK))?;
    let pool = crate::verify_pool()?;
    let job = Path::new(JOB);
    let vms = Path::new(VM_PARENT);
    require_pool_path(job)?;
    private_directory(job)?;
    if job.join("seed.raw").try_exists()? {
        require_pool_path(&job.join("seed.raw"))?;
    }
    if !installed(job)? {
        live::require_idle()?;
        restore::require_idle()?;
        super::verified_definition(&selection)?;
        if Connection::connect()?.lookup(UUID)?.is_some() || Path::new(PID).try_exists()?
            || Path::new(ALIAS).try_exists()? || vms.join(ATTACHMENT).try_exists()?
        {
            return Err(invalid("commissioning requires a stopped and detached Guest slot"));
        }
        directory(vms)?;
    }
    require_pool_path(vms)?;
    install(&pool, job, vms, &text, |branch| {
        super::run(super::Command::new("/usr/bin/chcon").args([
            "--no-dereference", "system_u:object_r:fvca_vm_slot_t:s0",
        ]).arg(branch))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    #[ignore = "requires a fresh, privately mounted two-device Btrfs RAID1 fixture and root"]
    fn initial_guest_disk_is_atomic_and_repeatable() -> io::Result<()> {
        let mount = std::env::var("FVCA_TEST_COMMISSIONING_POOL").map_err(io::Error::other)?;
        let mount = Path::new(&mount);
        let pool = private_directory(mount)?;
        let fsid = btrfs::filesystem_uuid(&pool)?;
        let fixture = mount.join("fvca-commissioning-test");
        fs::create_dir(&fixture)?;
        let contents = [42; 4096];
        let no_label = |_: &Path| Ok(());

        for case in ["reboot", "moved", "bad-seed", "exists", "orphan"] {
            println!("commissioning case {case}");
            let base = fixture.join(case);
            directory(&base)?;
            let job = base.join("job");
            let vms = base.join("vms");
            let journal = directory(&job)?;
            let parent = directory(&vms)?;
            let seed = job.join("seed.raw");
            let boot = "b".repeat(64);
            let slot = vms.join("service-guest");
            let mut seed_file = OpenOptions::new().create_new(true).write(true).mode(0o600).open(&seed)?;
            seed_file.write_all(&contents)?;
            seed_file.sync_all()?;
            let sha = recovery::sha256(raw_disk(&seed)?)?;
            let request = format!(
                "FVCA-GUEST-COMMISSIONING-1\nguest={}\nbundle={boot}\nbytes=4096\nseed_sha256={sha}\n",
                UUID.to_str().expect("ASCII Guest UUID"),
            );
            assert!(launch_allowed(&job, Some(&request)).is_err());
            match case {
                "exists" => {
                    btrfs::create_subvolume(&parent, "service-guest")?;
                    let original = volume(&slot, &fsid)?;
                    assert!(install(&pool, &job, &vms, &request, no_label).is_err());
                    assert_eq!(original, volume(&slot, &fsid)?);
                    assert!(seed.try_exists()?);
                    assert!(!job.join("ready").try_exists()?);
                    continue;
                }
                "orphan" => {
                    btrfs::create_subvolume(&journal, "branch")?;
                    let branch = job.join("branch");
                    let original = volume(&branch, &fsid)?;
                    assert!(install(&pool, &job, &vms, &request, no_label).is_err());
                    assert_eq!(original, volume(&branch, &fsid)?);
                    assert!(seed.try_exists()?);
                    assert!(!slot.try_exists()?);
                    continue;
                }
                "bad-seed" => {
                    fs::write(&seed, [43; 4096])?;
                    assert!(install(&pool, &job, &vms, &request, no_label).is_err());
                    assert!(!job.join("branch/.data.tmp").try_exists()?);
                    assert!(!slot.try_exists()?);
                    assert!(seed.try_exists()?);
                    fs::write(&seed, contents)?;
                }
                "reboot" | "moved" => {
                    assert!(install(&pool, &job, &vms, &request, |_| Err(io::Error::other("interrupted"))).is_err());
                    assert!(job.join("ready").try_exists()?);
                    assert!(launch_allowed(&job, None).is_err());
                    assert!(!slot.try_exists()?);
                    if case == "moved" {
                        btrfs::place_subvolume(&journal, c"branch", &parent, c"service-guest", false)?;
                        btrfs::sync(&pool)?;
                    }
                }
                _ => unreachable!(),
            }
            install(&pool, &job, &vms, &request, no_label)?;
            assert_eq!(fs::read(slot.join("data.raw"))?, contents);
            assert!(installed(&job)?);
            launch_allowed(&job, None)?;
            launch_allowed(&job, Some(&request))?;
            assert!(!seed.try_exists()?);
            assert!(!job.join("branch").try_exists()?);

            fs::write(slot.join("data.raw"), [44; 4096])?;
            install(&pool, &job, &vms, &request, no_label)?;
            assert_eq!(fs::read(slot.join("data.raw"))?, [44; 4096]);
            fs::rename(&slot, vms.join("removed-slot"))?;
            assert!(install(&pool, &job, &vms, &request, no_label).is_err());
            assert!(!slot.try_exists()?);
        }
        Ok(())
    }
}
