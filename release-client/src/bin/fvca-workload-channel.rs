#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fvca_release_client::depot::{CONFIG_BYTES, METADATA_BYTES};
use fvca_release_client::workload::{self, Enrollment, admission};
use fvca_release_client::{Result, invalid, state};
#[cfg(not(feature = "appliance"))]
use fvca_workload_admission::authorization_identity;
use fvca_workload_admission::{Trust, VerifiedWorkload, channel, verify, verify_committed};
use rustix::fs::{self as unix, AtFlags, CWD, OFlags, RenameFlags, StatxFlags, renameat_with};
use sha2::{Digest, Sha256};

const DATA: &str = "/run/fvca/guest-data";
const TRUST: &str = "/run/fvca/workload-trust";
const STORE: &str = "/run/fvca/guest-data/workload-updates";
const LEASE: &str = "/run/fvca/workload-lifecycle.lock";
const MOUNTED: &str = "/run/fvca/workload-image/authorization";

fn present(path: &Path) -> io::Result<bool> {
    match state::directory(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn queued(store: &Path) -> io::Result<Option<PathBuf>> {
    let incoming = store.join("incoming");
    let staged = store.join("staged");
    match (present(&incoming)?, present(&staged)?) {
        (true, true) => Err(invalid("multiple inputs occupy the workload update inbox")),
        (true, false) => Ok(Some(incoming)),
        (false, true) => Ok(Some(staged)),
        (false, false) => Ok(None),
    }
}

fn remove_file(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

fn save(path: &Path, record: &workload::Prepared) -> Result<()> {
    let directory = path
        .parent()
        .ok_or_else(|| invalid("invalid channel receipt path"))?;
    state::directory(directory)?;
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    serde_json::to_writer(&mut file, record)?;
    file.flush()?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn clear_area(path: &Path, device: u64) -> Result<()> {
    if present(path)? {
        on_pool(path, device)?;
        fs::remove_dir_all(path)?;
    }
    Ok(())
}

fn attempted(store: &Path, grant: &str) -> Result<bool> {
    match state::read(&store.join("last-attempt"), 72) {
        Ok(bytes) => Ok(bytes == format!("sha256:{grant}\n").as_bytes()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn owned_grant(directory: &Path, owner: &Path) -> Result<String> {
    let record: workload::Prepared = serde_json::from_slice(&state::read(owner, 4096)?)?;
    let grant = state::read(&directory.join("transition.json"), 4096)?;
    let digest = hex::encode(Sha256::digest(&grant));
    if record.approval.strip_prefix("sha256:") != Some(digest.as_str()) {
        return Err(
            invalid("the queued workload grant has no matching channel delivery receipt").into(),
        );
    }
    Ok(digest)
}

fn retire(path: &Path, recovery: &Path, store: &Path, device: u64) -> Result<()> {
    renameat_with(CWD, path, CWD, recovery, RenameFlags::NOREPLACE)?;
    File::open(store)?.sync_all()?;
    clear_area(recovery, device)?;
    File::open(store)?.sync_all()?;
    Ok(())
}

fn unchanged(store: &Path, expected: &str) -> Result<()> {
    if mounted()? != expected || present(&store.join("trial"))? {
        return Err(invalid("the workload state changed during discovery").into());
    }
    Ok(())
}

fn no_offer() {
    println!("FVCA_WORKLOAD_CHANNEL_NO_ELIGIBLE_OFFER");
}

fn eligible<'a>(
    discovery: &'a workload::Discovery,
    store: &Path,
    identity: &str,
) -> Result<Option<&'a str>> {
    if let Some(grant) = discovery.grant(identity)
        && !attempted(store, grant)?
    {
        return Ok(Some(grant));
    }
    Ok(None)
}

fn pool() -> Result<u64> {
    let directory = Path::new(DATA);
    state::directory(directory)?;
    let stat = |path| unix::statx(CWD, path, AtFlags::SYMLINK_NOFOLLOW, StatxFlags::MNT_ID);
    let data = stat(DATA)?;
    let parent = stat("/run/fvca")?;
    if data.stx_mask & parent.stx_mask & StatxFlags::MNT_ID.bits() == 0
        || data.stx_mnt_id == parent.stx_mnt_id
        || unix::statfs(DATA)?.f_type as u64 != 0x9123_683e
    {
        return Err(invalid("workload discovery requires the selected Guest Btrfs mount").into());
    }
    Ok(fs::metadata(directory)?.dev())
}

fn on_pool(path: &Path, device: u64) -> Result<()> {
    state::directory(path)?;
    if fs::metadata(path)?.dev() != device {
        return Err(invalid("workload discovery path is outside the selected Btrfs pool").into());
    }
    Ok(())
}

fn lease() -> Result<File> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY).bits() as i32)
        .open(LEASE)?;
    let meta = lock.metadata()?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.gid() != 0
        || meta.nlink() != 1
        || meta.mode() & 0o7777 != 0o600
    {
        return Err(invalid("invalid Guest workload lifecycle lease").into());
    }
    // Boot can be finishing the local staging pass. The unit timeout bounds
    // this wait, and the lease is released before any depot request.
    lock.lock()?;
    Ok(lock)
}

fn mounted() -> Result<String> {
    let bytes = state::read(Path::new(MOUNTED), 72)?;
    let text = std::str::from_utf8(&bytes)?
        .strip_suffix('\n')
        .ok_or_else(|| invalid("invalid mounted workload identity"))?;
    Ok(text.to_owned())
}

fn verified_selection(store: &Path, trust: &Trust, device: u64) -> Result<VerifiedWorkload> {
    let selected = store.join("selected");
    if present(&selected)? {
        let candidate = selected.join("candidate");
        on_pool(&selected, device)?;
        on_pool(&candidate, device)?;
        admission(verify_committed(
            &candidate,
            &selected.join("transition.json"),
            &selected.join("transition.p7s"),
            trust,
        ))
    } else {
        let baseline = Path::new(DATA).join("workload");
        on_pool(&baseline, device)?;
        admission(verify(&baseline, trust))
    }
}

fn publish(prepared: &workload::Prepared, source: &Path, destination: &Path) -> Result<()> {
    admission(prepared.require_fresh())?;
    renameat_with(CWD, source, CWD, destination, RenameFlags::NOREPLACE)?;
    File::open(
        destination
            .parent()
            .ok_or_else(|| invalid("invalid workload output path"))?,
    )?
    .sync_all()?;
    println!(
        "FVCA_WORKLOAD_CHANNEL_DELIVERED {} {} {} {}",
        prepared.approval, prepared.from, prepared.to, prepared.fresh_until
    );
    Ok(())
}

async fn guest() -> Result<()> {
    if rustix::process::geteuid().as_raw() != 0
        || state::read(Path::new("/usr/lib/fvca/role"), 32)? != b"service-guest\n"
    {
        return Err(invalid("workload discovery requires the verified Service Guest role").into());
    }
    let trust_directory = Path::new(TRUST);
    state::directory(trust_directory)?;
    let device = pool()?;
    let trust = admission(Trust::from_directory(trust_directory))?;
    let trust = admission(trust.with_permit_revocations(Path::new(DATA), device))?;
    let store = Path::new(STORE);
    on_pool(store, device)?;
    let channel_state = store.join(".channel-state");
    state::staged(&channel_state)?;
    on_pool(&channel_state, device)?;
    let ready = Path::new(channel::READY);
    let runtime = ready
        .parent()
        .ok_or_else(|| invalid("invalid channel runtime directory"))?;
    let _refresh = state::lock(runtime)?;
    let spool = store.join(".channel-download");
    let discarded = store.join(".channel-discard");
    let owner = channel_state.join("delivery.json");
    let identity = {
        let _lease = lease()?;
        remove_file(ready)?;
        if present(&store.join("trial"))? {
            println!("FVCA_WORKLOAD_CHANNEL_DEFERRED trial-recovery");
            return Ok(());
        }
        mounted()?
    };
    clear_area(&spool, device)?;
    clear_area(&discarded, device)?;
    let policy = state::read(&trust_directory.join(channel::POLICY), CONFIG_BYTES)?;
    let depot = state::read(&trust_directory.join("channel-depot.json"), CONFIG_BYTES)?;
    let discovery = workload::discover(
        Enrollment {
            policy: &policy,
            initial_root: state::read(&trust_directory.join("channel-root.json"), METADATA_BYTES)?,
            depot_config: &depot,
        },
        &trust,
        &channel_state,
    )
    .await?;
    {
        let _lease = lease()?;
        unchanged(store, &identity)?;
        let grant = eligible(&discovery, store, &identity)?;
        if let Some(directory) = queued(store)? {
            on_pool(&directory, device)?;
            let digest = owned_grant(&directory, &owner)?;
            if Some(digest.as_str()) == grant {
                let prepared = discovery.confirm(
                    &trust,
                    &identity,
                    || {
                        verified_selection(store, &trust, device)
                            .map_err(|error| invalid(&error.to_string()).into())
                    },
                    &directory,
                )?;
                save(ready, &prepared)?;
                println!("FVCA_WORKLOAD_CHANNEL_REAUTHORIZED {}", prepared.approval);
                return Ok(());
            }
            retire(&directory, &discarded, store, device)?;
            println!("FVCA_WORKLOAD_CHANNEL_RETIRED sha256:{digest}");
        }
        if grant.is_none() {
            no_offer();
            return Ok(());
        }
    }
    state::staged(&spool)?;
    let result = async {
        let prepared = discovery
            .fetch(
                &trust,
                &identity,
                || {
                    let _lease = lease().map_err(|error| invalid(&error.to_string()))?;
                    unchanged(store, &identity).map_err(|error| invalid(&error.to_string()))?;
                    verified_selection(store, &trust, device)
                        .map_err(|error| invalid(&error.to_string()).into())
                },
                &spool,
            )
            .await?;
        if let Some(prepared) = prepared {
            let _lease = lease()?;
            unchanged(store, &identity)?;
            if queued(store)?.is_some() || eligible(&discovery, store, &identity)?.is_none() {
                return Err(invalid("the workload state changed before channel delivery").into());
            }
            save(&owner, &prepared)?;
            publish(&prepared, &spool, &store.join("incoming"))?;
            save(ready, &prepared)?;
        } else {
            no_offer();
        }
        Ok(())
    }
    .await;
    clear_area(&spool, device)?;
    result
}

#[cfg(not(feature = "appliance"))]
async fn prepare(args: &[String]) -> Result<()> {
    let [policy, root, depot, trust, current, channel_state, output] = args else {
        return Err(
            invalid("expected --prepare POLICY TUF_ROOT DEPOT TRUST CURRENT STATE OUTPUT").into(),
        );
    };
    let current = Path::new(current);
    let channel_state = Path::new(channel_state);
    let output = Path::new(output);
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| invalid("use an explicit parent for the workload output"))?;
    let trust = admission(Trust::from_directory(Path::new(trust)))?;
    let identity = admission(authorization_identity(current, &trust))?;
    let _refresh = state::lock(channel_state)?;
    let prepared_directory = tempfile::tempdir_in(parent)?;
    let policy = state::read(Path::new(policy), CONFIG_BYTES)?;
    let config = state::read(Path::new(depot), CONFIG_BYTES)?;
    let enrollment = Enrollment {
        policy: &policy,
        initial_root: state::read(Path::new(root), METADATA_BYTES)?,
        depot_config: &config,
    };
    let discovery = workload::discover(enrollment, &trust, channel_state).await?;
    if let Some(prepared) = discovery
        .fetch(
            &trust,
            &identity,
            || verify(current, &trust),
            prepared_directory.path(),
        )
        .await?
    {
        publish(&prepared, prepared_directory.path(), output)?;
    } else {
        no_offer();
    }
    Ok(())
}

fn run() -> Result<()> {
    #[cfg(feature = "appliance")]
    fvca_allocator_binding::require_allocator()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => runtime.block_on(guest()),
        #[cfg(not(feature = "appliance"))]
        [command, paths @ ..] if command == "--prepare" => runtime.block_on(prepare(paths)),
        _ => Err(invalid("invalid workload channel operation").into()),
    }
}

fn main() -> ExitCode {
    if let Err(error) = run() {
        eprintln!("FVCA workload channel failed: {error}");
        let mut source = error.source();
        while let Some(cause) = source {
            eprintln!("FVCA workload channel cause: {cause}");
            source = cause.source();
        }
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
