use std::alloc::System;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fvca_btrfs_boundary::{ScrubProgress, scrub, scrub_members};
use fvca_initrd_bootstrap::{
    btrfs::{SCRUB_DIRECTORY, SCRUB_LIMIT, SCRUB_SELECTION, scrub_limit},
    identity, invalid,
};

#[global_allocator]
static ALLOCATOR: System = System;
static STOP: AtomicBool = AtomicBool::new(false);
const PERIOD: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const SIGTERM: i32 = 15;
const ECANCELED: i32 = 125;
const OPEN_CHECKS: i32 = 0o400000 | 0o4000; // O_NOFOLLOW | O_NONBLOCK on x86-64 Linux.

unsafe extern "C" {
    fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
}

extern "C" fn cancel(_: i32) {
    STOP.store(true, Ordering::Relaxed);
}

fn read(path: impl AsRef<Path>, limit: u64) -> io::Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(OPEN_CHECKS)
        .open(path)?;
    let mut text = String::new();
    file.take(limit + 1).read_to_string(&mut text)?;
    if text.len() as u64 > limit {
        return Err(invalid("scrub input exceeds its size limit"));
    }
    Ok(text)
}

fn seconds(time: SystemTime) -> io::Result<u64> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(io::Error::other)
}

struct Report<'a> {
    fsid: &'a str,
    boot_id: &'a str,
    started: u64,
    finished: u64,
    outcome: &'static str,
    members: usize,
    completed: usize,
    progress: ScrubProgress,
}

impl Report<'_> {
    fn write(&self, directory: &Path) -> io::Result<()> {
        let body = format!(
            concat!(
                "{{\"schema\":\"fvca-btrfs-scrub-v1\",\"filesystem_uuid\":\"{}\",\"boot_id\":\"{}\",",
                "\"started_at\":{},\"finished_at\":{},\"outcome\":\"{}\",",
                "\"members\":{},\"completed_members\":{},\"data_bytes\":{},\"metadata_bytes\":{},",
                "\"no_checksum_blocks\":{},\"corrected_errors\":{},\"uncorrectable_errors\":{},",
                "\"allocation_errors\":{}}}"
            ),
            self.fsid,
            self.boot_id,
            self.started,
            self.finished,
            self.outcome,
            self.members,
            self.completed,
            self.progress.data_bytes,
            self.progress.metadata_bytes,
            self.progress.no_checksum_blocks,
            self.progress.corrected_errors,
            self.progress.uncorrectable_errors,
            self.progress.allocation_errors,
        );
        let temporary = directory.join("report.next");
        match fs::remove_file(&temporary) {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        writeln!(file, "{body}")?;
        file.sync_all()?;
        fs::rename(&temporary, directory.join("report.json"))?;
        File::open(directory)?.sync_all()?;
        println!("FVCA_BTRFS_SCRUB {body}");
        Ok(())
    }

    fn add(&mut self, observed: ScrubProgress) {
        let total = &mut self.progress;
        total.data_bytes = total.data_bytes.saturating_add(observed.data_bytes);
        total.metadata_bytes = total.metadata_bytes.saturating_add(observed.metadata_bytes);
        total.no_checksum_blocks = total
            .no_checksum_blocks
            .saturating_add(observed.no_checksum_blocks);
        total.corrected_errors = total
            .corrected_errors
            .saturating_add(observed.corrected_errors);
        total.uncorrectable_errors = total
            .uncorrectable_errors
            .saturating_add(observed.uncorrectable_errors);
        total.allocation_errors = total
            .allocation_errors
            .saturating_add(observed.allocation_errors);
    }
}

fn due(directory: &Path, now: SystemTime) -> io::Result<bool> {
    match fs::symlink_metadata(directory.join("report.json")) {
        Ok(meta)
            if meta.is_file()
                && meta.uid() == 0
                && meta.gid() == 0
                && meta.nlink() == 1
                && meta.mode() & 0o7777 == 0o600 =>
        {
            Ok(now
                .duration_since(meta.modified()?)
                .map_err(io::Error::other)?
                >= PERIOD)
        }
        Ok(_) => Err(invalid("scrub history must be a private receipt")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
}

fn execute() -> io::Result<()> {
    fvca_allocator_binding::require_allocator()?;
    if read("/proc/self/attr/current", 128)?.trim_end_matches(['\n', '\0'])
        != "system_u:system_r:fvca_storage_scrub_t:s0"
        || read("/sys/fs/selinux/enforce", 2)?.trim_end() != "1"
    {
        return Err(invalid(
            "storage scrub requires its enforcing service domain",
        ));
    }
    // Install one process-wide handler before starting a scrub. It only sets a lock-free flag.
    if unsafe { signal(SIGTERM, cancel) } == usize::MAX {
        return Err(io::Error::last_os_error());
    }
    let selection = read(SCRUB_SELECTION, 128)?;
    let mut lines = selection.lines();
    let target = match lines.next() {
        Some(target @ ("/run/fvca/host-data" | "/run/fvca/guest-data")) => target,
        _ => return Err(invalid("no verified scrub mount selected")),
    };
    let uuid_groups = [8, 4, 4, 4, 12];
    let fsid = identity(lines.next().unwrap_or_default(), "", &uuid_groups, '-')?;
    if lines.next().is_some() {
        return Err(invalid("unexpected scrub selection fields"));
    }
    let pool = OpenOptions::new()
        .read(true)
        .custom_flags(OPEN_CHECKS)
        .open(target)?;
    let root = pool.metadata()?;
    let directory = Path::new(target).join(SCRUB_DIRECTORY);
    let state = fs::symlink_metadata(&directory)?;
    if !state.is_dir()
        || !root.is_dir()
        || state.uid() != 0
        || state.gid() != 0
        || state.mode() & 0o7777 != 0o700
        || state.dev() != root.dev()
    {
        return Err(invalid("expected scrub state on the verified data mount"));
    }
    if root.uid() != 0 || root.gid() != 0 || root.mode() & 0o7777 != 0o700 {
        return Err(invalid("expected a private verified data mount"));
    }
    let now = SystemTime::now();
    if !due(&directory, now)? {
        return Ok(());
    }
    let devices = scrub_members(&pool, fsid, target == "/run/fvca/host-data")?;
    let boot = read("/proc/sys/kernel/random/boot_id", 37)?;
    let boot_id = identity(boot.trim_end(), "", &uuid_groups, '-')?;
    let mut report = Report {
        fsid,
        boot_id,
        started: seconds(now)?,
        finished: 0,
        outcome: "in-progress-or-interrupted",
        members: devices.len(),
        completed: 0,
        progress: ScrubProgress::default(),
    };
    report.write(&directory)?;
    let result = devices.into_iter().try_for_each(|device| {
        if STOP.load(Ordering::Relaxed) {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        let limit = read(scrub_limit(fsid, device), 24)?
            .trim_end()
            .parse::<u64>()
            .map_err(io::Error::other)?;
        if !(1..=SCRUB_LIMIT).contains(&limit) {
            return Err(invalid(
                "Btrfs scrub bandwidth limit is missing or too high",
            ));
        }
        let (progress, result) = scrub(&pool, device);
        report.add(progress);
        result?;
        report.completed += 1;
        report.write(&directory)
    });
    report.finished = seconds(SystemTime::now())?;
    report.outcome = match &result {
        Ok(()) if report.progress.allocation_errors != 0 => "failed",
        Ok(()) if report.progress.uncorrectable_errors != 0 => "uncorrectable",
        Ok(()) => "completed",
        Err(error)
            if error.kind() == io::ErrorKind::Interrupted
                || error.raw_os_error() == Some(ECANCELED) =>
        {
            "cancelled"
        }
        Err(_) => "failed",
    };
    report.write(&directory)?;
    match report.outcome {
        "completed" | "cancelled" => Ok(()),
        _ => result.and(Err(io::Error::other(
            "Btrfs scrub did not verify all selected members",
        ))),
    }
}

fn main() -> ExitCode {
    if let Err(error) = execute() {
        eprintln!("FVCA Btrfs scrub failed: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
