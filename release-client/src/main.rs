mod attestation;
mod channel;
mod firmware;
mod gpt;
mod guest_configuration;
mod handoff;
mod install;
mod management;
mod tpm;

use std::fs::{self, File, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tough::{IntoVec, Repository, TargetName};

use fvca_release_client::depot::{Depot, METADATA_BYTES};
use fvca_release_client::repository::{check_target, download, load_repository, output_file};
use fvca_release_client::{Result, depot, invalid, state};

const MANIFEST_BYTES: u64 = 64 * 1024;
const MANIFEST: &str = "release.json";
const QUALIFICATION: &str = "qualification.json";

enum Operation<'a> {
    FileBacked(install::Operation<'a>),
    HypervisorGpt(&'a Path),
}

#[derive(Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Role {
    Hypervisor,
    ServiceGuest,
}

impl Role {
    fn prefix(self) -> &'static str {
        match self {
            Self::Hypervisor => "hypervisor",
            Self::ServiceGuest => "service-guest",
        }
    }

    fn update_state(self) -> &'static str {
        match self {
            Self::Hypervisor => "os-update",
            Self::ServiceGuest => "guest-os-update",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    role: Role,
    epoch: u64,
    minimum_epoch: u64,
    manifest_sha256: String,
    max_release_bytes: u64,
}

impl Selection {
    fn validate(&self) -> io::Result<()> {
        if self.minimum_epoch == 0 || self.epoch < self.minimum_epoch {
            return Err(invalid("release epoch is below the authorized minimum"));
        }
        if self.max_release_bytes == 0
            || self.max_release_bytes == u64::MAX
            || !valid_digest(&self.manifest_sha256)
        {
            return Err(invalid("invalid release digest or staging budget"));
        }
        Ok(())
    }

    fn name(&self, file: &str) -> Result<TargetName> {
        Ok(TargetName::new(format!(
            "{}-{}-{}-{file}",
            self.role.prefix(),
            self.epoch,
            self.manifest_sha256,
        ))?)
    }

    fn require_update_from(&self, active_epoch: u64, active_digest: &str) -> io::Result<()> {
        if !valid_digest(active_digest) || active_epoch < self.minimum_epoch {
            return Err(invalid(
                "active slot is outside the approved recovery epoch",
            ));
        }
        if self.epoch < active_epoch {
            return Err(invalid("inactive release is below the active epoch"));
        }
        if self.manifest_sha256 == active_digest {
            return Err(invalid(
                "inactive release must differ from the approved active release",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Member {
    bytes: u64,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(tag = "role", rename_all = "kebab-case", deny_unknown_fields)]
enum Composition {
    Hypervisor {
        boot: Member,
        vm_runtime: Member,
        guest_boot: Member,
    },
    ServiceGuest {
        guest_boot: Member,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    epoch: u64,
    composition: Composition,
    qualification: Member,
}

impl Manifest {
    fn members(&self, role: Role, epoch: u64) -> io::Result<Vec<(&'static str, &Member)>> {
        if self.schema != "fvca-os-release-v1" || self.epoch == 0 || self.epoch != epoch {
            return Err(invalid(
                "release schema or epoch differs from the authorized selection",
            ));
        }
        let mut members = match (&self.composition, role) {
            (
                Composition::Hypervisor {
                    boot,
                    vm_runtime,
                    guest_boot,
                },
                Role::Hypervisor,
            ) => {
                vec![
                    ("boot.raw", boot),
                    ("vm-runtime.raw", vm_runtime),
                    ("guest-boot.raw", guest_boot),
                ]
            }
            (Composition::ServiceGuest { guest_boot }, Role::ServiceGuest) => {
                vec![("guest-boot.raw", guest_boot)]
            }
            _ => return Err(invalid("release composition changes the authorized role")),
        };
        members.push((QUALIFICATION, &self.qualification));
        if members.iter().any(|(_, member)| {
            member.bytes == 0 || member.bytes == u64::MAX || !valid_digest(&member.sha256)
        }) {
            return Err(invalid(
                "invalid member digest or length in release manifest",
            ));
        }
        Ok(members)
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
        && value != "00000000-0000-0000-0000-000000000000"
}

fn verify_staged(dir: &Path, manifest: &[u8], members: &[(&str, &Member)]) -> Result<()> {
    state::directory(dir)?;
    if fs::read_dir(dir)?.count() != members.len() + 1
        || state::read(&dir.join(MANIFEST), MANIFEST_BYTES)? != manifest
    {
        return Err(invalid("staged release differs from the approved manifest").into());
    }
    for (name, member) in members {
        verify_member(state::open_regular(&dir.join(name))?, member)?;
    }
    Ok(())
}

fn verify_member(input: File, member: &Member) -> Result<()> {
    if input.metadata()?.len() != member.bytes {
        return Err(invalid("staged member differs from its authorized length").into());
    }
    let mut stream = input.take(member.bytes + 1);
    let mut buffer = [0; 64 * 1024];
    let mut hash = Sha256::new();
    loop {
        let size = stream.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
    }
    if stream.limit() != 1 || hex::encode(hash.finalize()) != member.sha256 {
        return Err(invalid("staged member differs from its authorized length or digest").into());
    }
    Ok(())
}

async fn stage(repo: &Repository, selection: &Selection, parent: &Path) -> Result<PathBuf> {
    let target = selection.name(MANIFEST)?;
    let length = check_target(
        repo,
        &target,
        MANIFEST_BYTES.min(selection.max_release_bytes),
        &selection.manifest_sha256,
    )?;
    let manifest = repo
        .read_target(&target)
        .await?
        .ok_or_else(|| invalid("authorized release manifest disappeared"))?
        .into_vec()
        .await?;
    if manifest.len() as u64 != length {
        return Err(invalid("release manifest length differs from authorization").into());
    }
    let release: Manifest = serde_json::from_slice(&manifest)?;
    let members = release.members(selection.role, selection.epoch)?;
    let mut total = length;
    for (name, member) in &members {
        let target_bytes =
            check_target(repo, &selection.name(name)?, member.bytes, &member.sha256)?;
        if target_bytes != member.bytes {
            return Err(invalid("release member length differs from the TUF target length").into());
        }
        total = total
            .checked_add(member.bytes)
            .filter(|value| *value <= selection.max_release_bytes)
            .ok_or_else(|| invalid("release exceeds the approved staging budget"))?;
    }

    let destination = parent.join(&selection.manifest_sha256);
    if fs::symlink_metadata(&destination).is_ok() {
        verify_staged(&destination, &manifest, &members)?;
    } else {
        let temporary = tempfile::Builder::new()
            .prefix(".stage-")
            .permissions(Permissions::from_mode(0o700))
            .tempdir_in(parent)?;
        let mut file = output_file(&temporary.path().join(MANIFEST))?;
        file.write_all(&manifest)?;
        file.sync_all()?;
        for (name, member) in members {
            download(
                repo,
                &selection.name(name)?,
                &temporary.path().join(name),
                member.bytes,
            )
            .await?;
        }
        File::open(temporary.path())?.sync_all()?;
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            temporary.path(),
            rustix::fs::CWD,
            &destination,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        File::open(parent)?.sync_all()?;
    }
    Ok(destination)
}

async fn intake(
    root: &Path,
    depot: &Path,
    state_dir: &Path,
    selection_path: &Path,
    operation: Option<Operation<'_>>,
) -> Result<()> {
    let selection: Selection =
        serde_json::from_slice(&state::read(selection_path, MANIFEST_BYTES)?)?;
    selection.validate()?;
    let _lock = state::lock(state_dir)?;
    let staging = state_dir.join("staged");
    state::staged(&staging)?;
    let scratch = tempfile::Builder::new()
        .prefix(".tuf-")
        .tempdir_in(state_dir)?;
    let depot = Depot::from_config(
        &state::read(depot, depot::CONFIG_BYTES)?,
        selection.max_release_bytes,
    )?;
    let repo = load_repository(
        depot,
        state_dir,
        state::read(root, METADATA_BYTES)?,
        scratch.path(),
    )
    .await?;
    let location = stage(&repo, &selection, &staging).await?;
    match operation {
        Some(Operation::FileBacked(operation)) => {
            return install::execute(operation, &selection, state_dir);
        }
        Some(Operation::HypervisorGpt(plan)) => {
            return gpt::install(plan, &selection, &location, state_dir);
        }
        None => (),
    }
    println!(
        "FVCA_RELEASE_STAGED {} {} {}",
        selection.role.prefix(),
        selection.epoch,
        location.display()
    );
    Ok(())
}

fn run() -> Result<()> {
    #[cfg(feature = "appliance")]
    fvca_allocator_binding::require_allocator()?;

    let operands = std::env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    match operands.as_slice() {
        #[cfg(not(feature = "appliance"))]
        [option, scope, request, package, approvals]
            if option.as_os_str() == "--prepare-os-channel" =>
        {
            return channel::author::execute(scope, request, package, approvals, None);
        }
        #[cfg(not(feature = "appliance"))]
        [
            option,
            scope,
            request,
            package,
            approvals,
            signature,
            output,
        ] if option.as_os_str() == "--pack-os-channel" => {
            return channel::author::execute(
                scope,
                request,
                package,
                approvals,
                Some((signature, output)),
            );
        }
        [option, reference, destination] if option.as_os_str() == "--issue-boot-challenge" => {
            return attestation::issue(reference, destination);
        }
        [option, nonce] if option.as_os_str() == "--collect-boot-quote" => {
            return attestation::collect(nonce.to_str().ok_or_else(usage)?);
        }
        [option, reference, challenge, evidence]
            if option.as_os_str() == "--appraise-boot-quote" =>
        {
            return attestation::appraise(reference, challenge, evidence);
        }
        #[cfg(not(feature = "appliance"))]
        [option, reference, enrollment, ca, server_name, operator]
            if option.as_os_str() == "--appraise-remote-boot" =>
        {
            return runtime()?.block_on(attestation::appraise_remote(
                reference,
                enrollment,
                ca,
                server_name.to_str().ok_or_else(usage)?,
                operator,
            ));
        }
        _ => (),
    }
    if let [option] = operands.as_slice() {
        match option.to_str() {
            Some("--run-host-update") => {
                return runtime()?.block_on(run_scheduled_update(Role::Hypervisor));
            }
            Some("--run-guest-update") => {
                return runtime()?.block_on(run_scheduled_update(Role::ServiceGuest));
            }
            Some("--run-firmware-update") => {
                return runtime()?.block_on(firmware::scheduled());
            }
            Some("--reconcile-firmware-update") => return firmware::reconcile_scheduled(),
            Some("--serve-firmware-writer") => return firmware::serve_writer(),
            Some("--guest-configuration-status") => return guest_configuration::report(),
            Some("--serve-management-broker") => return runtime()?.block_on(management::broker()),
            Some("--serve-management") => return runtime()?.block_on(management::gateway()),
            Some("--serve-boot-quote") => return management::boot_quote::serve(),
            Some("--serve-firmware-status") => return management::firmware_status::serve(),
            Some("--serve-firmware-inventory") => return management::firmware_inventory::serve(),
            Some("--collect-boot-quote") => return attestation::collect_from_stdin(),
            _ => (),
        }
    }
    if let [option, disk, sector] = operands.as_slice()
        && option.as_os_str() == "--inspect-hypervisor-gpt"
    {
        return gpt::inspect(disk, sector.to_str().ok_or_else(usage)?.parse()?);
    }
    if let [
        option,
        root,
        depot,
        state,
        policy,
        signature,
        owner,
        observation,
    ] = operands.as_slice()
        && option.as_os_str() == "--stage-host-firmware"
    {
        let source = if observation.as_os_str() == "--live" {
            firmware::ObservationSource::Live
        } else {
            firmware::ObservationSource::File(observation)
        };
        return runtime()?.block_on(firmware::stage(
            firmware::Intake {
                trusted_root: root,
                depot_config: depot,
                directory: state,
                policy,
                signature,
                owner,
            },
            source,
        ));
    }
    if let [
        option,
        root,
        depot,
        state,
        policy,
        signature,
        owner,
        options @ ..,
    ] = operands.as_slice()
        && option.as_os_str() == "--discover-os-release"
    {
        let operation = match options {
            [] => channel::Operation::Discover,
            [flag] if flag.as_os_str() == "--prepare-inactive-gpt" => {
                channel::Operation::PrepareGpt
            }
            [flag] if flag.as_os_str() == "--deliver-prepared-trial" => {
                channel::Operation::DeliverTrial(channel::Delivery::Inbox)
            }
            [flag] if flag.as_os_str() == "--activate-prepared-trial" => {
                channel::Operation::DeliverTrial(channel::Delivery::Activate)
            }
            _ => return Err(usage().into()),
        };
        return runtime()?.block_on(channel::discover(
            root, depot, state, policy, signature, owner, operation,
        ));
    }
    if let [option, state, approval, signature, authority, certificate] = operands.as_slice()
        && option.as_os_str() == "--verify-hypervisor-floor-approval"
    {
        return gpt::verify_floor(state, approval, signature, authority, certificate, None);
    }
    if let [
        option,
        state,
        approval,
        signature,
        authority,
        certificate,
        increment_key,
        reference,
    ] = operands.as_slice()
        && option.as_os_str() == "--advance-hypervisor-floor"
    {
        return gpt::verify_floor(
            state,
            approval,
            signature,
            authority,
            certificate,
            Some((increment_key, reference)),
        );
    }
    let [root, depot, state, selection, options @ ..] = operands.as_slice() else {
        return Err(usage().into());
    };
    let operation = match options {
        [] => None,
        [option, slots] if option.as_os_str() == "--initialize-slots" => {
            Some(Operation::FileBacked(install::Operation::Initialize(slots)))
        }
        [option, slots, active] if option.as_os_str() == "--prepare-inactive" => {
            Some(Operation::FileBacked(install::Operation::Prepare {
                slots,
                active,
            }))
        }
        [option, plan] if option.as_os_str() == "--write-inactive-gpt" => {
            Some(Operation::HypervisorGpt(plan))
        }
        _ => return Err(usage().into()),
    };
    runtime()?.block_on(intake(root, depot, state, selection, operation))
}

async fn run_scheduled_update(role: Role) -> Result<()> {
    use fvca_trial_authorization::{APPROVAL_LIMIT, PEER_BYTES, PEER_ENROLLMENT, RUNNING_CONTEXT};

    let boot = Path::new("/run/fvca");
    if boot.join("boot-trial-started").try_exists()? {
        return Err(invalid("release update scheduling requires a stable Hypervisor boot").into());
    }
    let name = role.update_state();
    let directory = boot.join("host-data").join(name);
    handoff::require_pool_directory(&directory)?;
    let owner = boot.join(format!("{name}-owner"));
    let depot = depot::EnrolledDepot::load(boot, name)?;
    let operation = match role {
        Role::Hypervisor => {
            state::read(Path::new(RUNNING_CONTEXT), APPROVAL_LIMIT as u64)?;
            let peer = match state::read(&boot.join(PEER_ENROLLMENT), PEER_BYTES as u64) {
                Ok(record) => Some(String::from_utf8(record)?),
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.into()),
            };
            channel::Operation::DeliverTrial(channel::Delivery::Scheduled { depot, peer })
        }
        Role::ServiceGuest => channel::Operation::ScheduleGuest(depot),
    };
    channel::discover(
        &directory.join("trusted-root.json"),
        &directory.join("depot.json"),
        &directory,
        &directory.join("policy.json"),
        &directory.join("policy.sig"),
        &owner,
        operation,
    )
    .await
}

fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
}

fn usage() -> io::Error {
    let instructions = "usage: fvca-release-client TRUSTED_ROOT DEPOT_CONFIG PRIVATE_STATE SELECTION_JSON [--initialize-slots SLOTS | --prepare-inactive SLOTS ACTIVE_RECORD | --write-inactive-gpt PLAN]\n       fvca-release-client --discover-os-release TRUSTED_ROOT DEPOT_CONFIG PRIVATE_STATE STANDING_POLICY SIGNATURE OWNER_ED25519_PUBLIC_KEY [--prepare-inactive-gpt | --deliver-prepared-trial | --activate-prepared-trial]\n       fvca-release-client --stage-host-firmware TRUSTED_ROOT DEPOT_CONFIG PRIVATE_STATE POLICY SIGNATURE OWNER_ED25519_PUBLIC_KEY [OBSERVATION | --live]\n       fvca-release-client --inspect-hypervisor-gpt DISK SECTOR_SIZE\n       fvca-release-client --verify-hypervisor-floor-approval PRIVATE_STATE APPROVAL SIGNATURE ED25519_PUBLIC_KEY SECURE_BOOT_CERTIFICATE\n       fvca-release-client --advance-hypervisor-floor PRIVATE_STATE APPROVAL SIGNATURE ED25519_PUBLIC_KEY SECURE_BOOT_CERTIFICATE INCREMENT_TPM_PUBLIC POLICY_REFERENCE\n       fvca-release-client --issue-boot-challenge TRUSTED_REFERENCE NEW_CHALLENGE\n       fvca-release-client --collect-boot-quote NONCE_HEX\n       fvca-release-client --appraise-boot-quote TRUSTED_REFERENCE PENDING_CHALLENGE EVIDENCE";
    #[cfg(not(feature = "appliance"))]
    {
        invalid(&format!(
            "{instructions}\n       fvca-release-client --appraise-remote-boot TRUSTED_REFERENCE TRUSTED_ENROLLMENT TLS_CA TLS_SERVER_NAME OPERATOR_KEY\n       fvca-release-client --prepare-os-channel TRUSTED_SCOPE REQUEST PREPARED_RELEASE APPROVALS\n       fvca-release-client --pack-os-channel TRUSTED_SCOPE REQUEST PREPARED_RELEASE APPROVALS QUALIFICATION_SIGNATURE OUTPUT"
        ))
    }
    #[cfg(feature = "appliance")]
    {
        invalid(instructions)
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("FVCA release intake failed: {error}");
        let mut source = error.source();
        while let Some(cause) = source {
            eprintln!("  {cause}");
            source = cause.source();
        }
        std::process::exit(1);
    }
}
