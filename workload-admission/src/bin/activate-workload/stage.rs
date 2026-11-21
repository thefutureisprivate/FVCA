//! Publish a verified inactive workload bundle on the selected Guest Btrfs pool.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use fvca_workload_admission::{
    Trust, VerifiedTransition, VerifiedWorkload, verify, verify_committed, verify_transition_from,
};

use super::{
    BUNDLE, MOUNTED_AUTHORIZATION, Result, private_directory, read_trust, require_guest_data,
};

pub(super) const STORE: &str = "/run/fvca/guest-data/workload-updates";
const INCOMING: &str = "incoming";
pub(super) const STAGED: &str = "staged";
pub(super) const SELECTED: &str = "selected";
pub(super) const TRIAL: &str = "trial";
const CANDIDATE: &str = "candidate";
const GRANT: &str = "transition.json";
const PROOF: &str = "transition.p7s";
const ATTEMPT: &str = "last-attempt";
const BUNDLE_FILES: [&str; 8] = [
    "authorization.json",
    "authorization.p7s",
    "deployment.json",
    "deployment.p7s",
    "derivation.json",
    "launch.json",
    "source-evidence.json",
    "workload.raw",
];

fn private_file(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.nlink() != 1
        || !matches!(metadata.mode() & 0o7777, 0o400 | 0o600)
    {
        return Err(io::Error::other(
            "staged workload inputs must be private root-owned files",
        ));
    }
    Ok(file)
}

pub(super) fn pool_directory(path: &Path, device: u64) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if metadata.dev() != device
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(io::Error::other(
            "the workload update directory must be private and on the selected Guest pool",
        ));
    }
    Ok(file)
}

fn pool_file(path: &Path, device: u64) -> io::Result<File> {
    let file = private_file(path)?;
    if file.metadata()?.dev() != device {
        return Err(io::Error::other(
            "workload update input is outside the selected Guest pool",
        ));
    }
    Ok(file)
}

fn exact_entries(path: &Path, names: &[&str]) -> io::Result<()> {
    let mut seen = 0;
    for entry in fs::read_dir(path)?.take(names.len() + 1) {
        let name = entry?.file_name();
        if !names.iter().any(|expected| name == *expected) {
            return Err(io::Error::other("unexpected entry in the workload update"));
        }
        seen += 1;
    }
    if seen != names.len() {
        return Err(io::Error::other("incomplete workload update"));
    }
    Ok(())
}

struct Bundle {
    directory: File,
    candidate: File,
    files: Vec<File>,
}

fn open_bundle(path: &Path, device: u64) -> io::Result<Bundle> {
    let directory = pool_directory(path, device)?;
    exact_entries(path, &[CANDIDATE, GRANT, PROOF])?;
    let candidate = path.join(CANDIDATE);
    let candidate_dir = pool_directory(&candidate, device)?;
    exact_entries(&candidate, &BUNDLE_FILES)?;
    let mut files = Vec::with_capacity(BUNDLE_FILES.len() + 2);
    for name in BUNDLE_FILES {
        files.push(pool_file(&candidate.join(name), device)?);
    }
    let grant = path.join(GRANT);
    let proof = path.join(PROOF);
    files.push(pool_file(&grant, device)?);
    files.push(pool_file(&proof, device)?);
    Ok(Bundle {
        directory,
        candidate: candidate_dir,
        files,
    })
}

pub(super) fn verify_selection(
    store: &Path,
    trust: &Trust,
    device: u64,
) -> Result<VerifiedWorkload> {
    let selected = store.join(SELECTED);
    if directory_present(store)? {
        pool_directory(store, device)?;
        if directory_present(&selected)? {
            open_bundle(&selected, device)?;
            return verify_committed(
                &selected.join(CANDIDATE),
                &selected.join(GRANT),
                &selected.join(PROOF),
                trust,
            );
        }
    }
    private_directory(BUNDLE)?;
    verify(Path::new(BUNDLE), trust)
}

pub(super) fn selected_bundle(store: &Path) -> io::Result<std::path::PathBuf> {
    let selected = store.join(SELECTED);
    Ok(if directory_present(&selected)? {
        selected.join(CANDIDATE)
    } else {
        Path::new(BUNDLE).to_path_buf()
    })
}

pub(super) fn verify_staged(
    store: &Path,
    path: &Path,
    mounted: &str,
    trust: &Trust,
    device: u64,
) -> Result<VerifiedTransition> {
    let bundle = open_bundle(path, device)?;
    let transition = verify_transition_from(
        || verify_selection(store, trust, device),
        &path.join(CANDIDATE),
        &path.join(GRANT),
        &path.join(PROOF),
        trust,
    )?;
    if transition.current.authorization_digest() != mounted {
        return Err(io::Error::other(
            "the workload transition differs from the mounted authorization",
        )
        .into());
    }
    for file in bundle.files {
        file.sync_all()?;
    }
    bundle.candidate.sync_all()?;
    bundle.directory.sync_all()?;
    transition.require_fresh()?;
    Ok(transition)
}

pub(super) fn directory_present(path: &Path) -> io::Result<bool> {
    match private_directory(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

// Only the trusted intake writer can publish incoming. All Guest-side consumers
// take the workload lifecycle lease before accessing these fixed directories.
fn prepare(
    store: &Path,
    mounted: &str,
    trust: &Trust,
    device: u64,
) -> Result<Option<(VerifiedTransition, bool)>> {
    let directory = pool_directory(store, device)?;
    let incoming = store.join(INCOMING);
    let staged = store.join(STAGED);
    let publish = match (directory_present(&incoming)?, directory_present(&staged)?) {
        (false, false) => return Ok(None),
        (true, true) => {
            return Err(
                io::Error::other("an occupied workload stage prevents a different intake").into(),
            );
        }
        (true, false) => true,
        (false, true) => false,
    };
    let path = if publish { &incoming } else { &staged };
    let transition = verify_staged(store, path, mounted, trust, device)?;
    if publish {
        fs::rename(&incoming, &staged).map_err(|error| {
            io::Error::other(format!(
                "cannot publish the verified workload stage: {error}"
            ))
        })?;
    }
    directory.sync_all()?;
    Ok(Some((transition, publish)))
}

fn read_identity(file: io::Result<File>) -> io::Result<Option<String>> {
    let mut mounted = String::new();
    match file {
        Ok(file) => file.take(73).read_to_string(&mut mounted)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    mounted
        .strip_suffix('\n')
        .filter(|digest| {
            digest.strip_prefix("sha256:").is_some_and(|hash| {
                hash.len() == 64
                    && hash
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        })
        .map(|digest| Some(digest.to_owned()))
        .ok_or_else(|| io::Error::other("invalid workload digest receipt"))
}

pub(super) fn mounted_authorization() -> io::Result<Option<String>> {
    read_identity(private_file(Path::new(MOUNTED_AUTHORIZATION)))
}

pub(super) fn attempted(store: &Path, device: u64) -> io::Result<Option<String>> {
    read_identity(pool_file(&store.join(ATTEMPT), device))
}

pub(super) fn record_attempt(store: &Path, directory: &File, approval: &str) -> io::Result<()> {
    let temporary = store.join(".last-attempt.new");
    super::remove_missing(fs::remove_file(&temporary))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    writeln!(file, "{approval}")?;
    file.sync_all()?;
    fs::rename(temporary, store.join(ATTEMPT))?;
    directory.sync_all()
}

pub(super) fn discard_trial(store: &Path, device: u64) -> io::Result<()> {
    let directory = pool_directory(store, device)?;
    let trial = store.join(TRIAL);
    pool_directory(&trial, device)?;
    let candidate = trial.join(CANDIDATE);
    if directory_present(&candidate)? {
        pool_directory(&candidate, device)?;
        for name in BUNDLE_FILES {
            super::remove_missing(fs::remove_file(candidate.join(name)))?;
        }
        fs::remove_dir(candidate)?;
    }
    for name in [GRANT, PROOF] {
        super::remove_missing(fs::remove_file(trial.join(name)))?;
    }
    fs::remove_dir(trial)?;
    directory.sync_all()
}

pub(super) fn run() -> Result<()> {
    // The stage service sees a read-only view of the pool except for its store.
    let data = require_guest_data("nodev,nosuid,noexec")?;
    let digest = mounted_authorization()?
        .ok_or_else(|| io::Error::other("missing mounted workload authorization receipt"))?;

    if let Some((stage, published)) =
        prepare(Path::new(STORE), &digest, &read_trust()?, data.dev())?
    {
        println!(
            "FVCA_WORKLOAD_STAGED {} {} {} {} {}",
            if published { "published" } else { "retained" },
            stage.approval_digest,
            stage.current.authorization_digest(),
            stage.candidate.authorization_digest(),
            stage.fresh_until,
        );
    }
    Ok(())
}
