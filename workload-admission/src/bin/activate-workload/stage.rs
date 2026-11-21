//! Publish a verified inactive workload bundle on the selected Guest Btrfs pool.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use fvca_workload_admission::{Trust, VerifiedTransition, verify_transition};

use super::{
    BUNDLE, GUEST_DATA, MOUNTED_AUTHORIZATION, Result, private_directory, read_trust,
    require_guest_data,
};

const UPDATE_DIRECTORY: &str = "workload-updates";
const INCOMING: &str = "incoming";
const STAGED: &str = "staged";
const CANDIDATE: &str = "candidate";
const GRANT: &str = "transition.json";
const PROOF: &str = "transition.p7s";
const BUNDLE_FILES: [&str; 8] = [
    "authorization.json",
    "authorization.p7s",
    "deployment.json",
    "deployment.p7s",
    "derivation.json",
    "launch.json",
    "publisher-proof.json",
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

fn pool_directory(path: &Path, device: u64) -> io::Result<File> {
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

fn verify_and_sync(
    path: &Path,
    current: &Path,
    mounted: &str,
    trust: &Trust,
    device: u64,
) -> Result<VerifiedTransition> {
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
    let transition = verify_transition(current, &candidate, &grant, &proof, trust)?;
    if transition.current.authorization_digest() != mounted {
        return Err(io::Error::other(
            "the workload transition differs from the mounted authorization",
        )
        .into());
    }
    for file in files {
        file.sync_all()?;
    }
    candidate_dir.sync_all()?;
    directory.sync_all()?;
    transition.require_fresh()?;
    Ok(transition)
}

fn directory_present(path: &Path) -> io::Result<bool> {
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
    current: &Path,
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
    let transition = verify_and_sync(path, current, mounted, trust, device)?;
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

pub(super) fn run() -> Result<()> {
    // The stage service sees a read-only view of the pool except for its store.
    let data = require_guest_data("nodev,nosuid,noexec")?;
    let mut mounted = String::new();
    private_file(Path::new(MOUNTED_AUTHORIZATION))?
        .take(73)
        .read_to_string(&mut mounted)?;
    let digest = mounted
        .strip_suffix('\n')
        .filter(|digest| digest.len() == 71)
        .ok_or_else(|| io::Error::other("invalid mounted workload authorization receipt"))?;

    if let Some((stage, published)) = prepare(
        &Path::new(GUEST_DATA).join(UPDATE_DIRECTORY),
        Path::new(BUNDLE),
        digest,
        &read_trust()?,
        data.dev(),
    )? {
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
