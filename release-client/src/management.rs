//! Authenticate requests on the network and authorize them again at the Host broker.

pub(crate) mod boot_quote;
mod intent;
mod listener;
mod local_captures;
mod protocol;
#[cfg(not(feature = "appliance"))]
pub(crate) mod quote_client;
mod storage_health;

use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fvca_trial_authorization::{
    MANAGEMENT_POLICY, MANAGEMENT_POLICY_BYTES, guest::SERVICE_GUEST_UUID, guest_config::Change,
    guest_config::Resources, management_binding,
};
use rustix::process::{getegid, geteuid};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::{ServerConfig, version::TLS13};
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout_at};
use tokio_rustls::TlsAcceptor;

use crate::{Result, attestation, channel, guest_configuration, invalid, state};
use protocol::{Activation, Enrollment, Operation, Refusal, Request, Settings};

const SOCKET: &str = "/run/fvca-management-broker/broker.sock";
const CREDENTIAL_BYTES: u64 = 16 * 1024;
const CONNECTIONS: usize = 8;
const DEADLINE: Duration = Duration::from_secs(3);
const QUOTE_DEADLINE: Duration = Duration::from_secs(8);

fn operation_deadline(started: Instant, operation: &Operation) -> Instant {
    started
        + if matches!(operation, Operation::BootQuote { .. }) {
            QUOTE_DEADLINE
        } else {
            DEADLINE
        }
}

fn enrollment() -> Result<Option<Enrollment>> {
    let cmdline = state::read(Path::new("/proc/cmdline"), 32 * 1024)?;
    let selected = management_binding(std::str::from_utf8(&cmdline)?)?;
    let Some((expected, address)) = selected else {
        return Ok(None);
    };
    let file = state::open_regular(Path::new(MANAGEMENT_POLICY))?;
    let metadata = file.metadata()?;
    if metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o644
        || metadata.len() > MANAGEMENT_POLICY_BYTES as u64
    {
        return Err(invalid("invalid management enrollment file").into());
    }
    let mut data = Vec::new();
    file.take((MANAGEMENT_POLICY_BYTES + 1) as u64)
        .read_to_end(&mut data)?;
    if data.len() > MANAGEMENT_POLICY_BYTES || expected != channel::digest(&data) {
        return Err(invalid("management enrollment differs from its signed UKI").into());
    }
    let value: Enrollment = serde_json::from_slice(&data)?;
    value.validate()?;
    if value.address != address {
        return Err(invalid("management address differs from its signed UKI").into());
    }
    Ok(Some(value))
}

fn load_enrollment() -> Result<Arc<Enrollment>> {
    Ok(Arc::new(enrollment()?.ok_or_else(|| {
        invalid("the running Host has no management enrollment")
    })?))
}

pub(super) fn require_configuration_intent(
    change: &Change,
    is_release_authority: impl FnOnce(&[u8]) -> bool,
) -> Result<()> {
    if let Some(enrollment) = enrollment()?
        && let Some(key) = &enrollment.apply_operator_public_key
    {
        if is_release_authority(&hex::decode(key)?) {
            return Err(invalid(
                "the configuration submitter must be independent of release authorities",
            )
            .into());
        }
        intent::require_release_intent(&enrollment, change)?;
    }
    Ok(())
}

fn tls(enrollment: &Enrollment) -> Result<TlsAcceptor> {
    let credentials = PathBuf::from(
        std::env::var_os("CREDENTIALS_DIRECTORY")
            .ok_or_else(|| invalid("missing management TLS credentials directory"))?,
    );
    let chain = state::read(&credentials.join("tls.crt"), CREDENTIAL_BYTES)?;
    let certificates =
        CertificateDer::pem_slice_iter(&chain).collect::<std::result::Result<Vec<_>, _>>()?;
    let leaf = certificates
        .first()
        .ok_or_else(|| invalid("missing management TLS certificate"))?;
    if channel::digest(leaf.as_ref()) != enrollment.tls_certificate_sha256 {
        return Err(invalid("management TLS certificate differs from enrollment").into());
    }
    let key = PrivateKeyDer::from_pem_slice(&state::read(
        &credentials.join("tls.key"),
        CREDENTIAL_BYTES,
    )?)?;
    let mut tls = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&TLS13])?
    .with_no_client_auth()
    .with_single_cert(certificates, key)?;
    tls.alpn_protocols = vec![protocol::ALPN.to_vec()];
    tls.send_tls13_tickets = 0;
    Ok(TlsAcceptor::from(Arc::new(tls)))
}

async fn forward(stream: TcpStream, enrollment: &Enrollment, acceptor: TlsAcceptor) -> Result<()> {
    let started = Instant::now();
    let deadline = started + DEADLINE;
    let mut tls = timeout_at(deadline, acceptor.accept(stream)).await??;
    if tls.get_ref().1.alpn_protocol() != Some(protocol::ALPN) {
        return Err(invalid("unsupported management protocol").into());
    }
    let data = timeout_at(
        deadline,
        protocol::read_frame(&mut tls, protocol::REQUEST_BYTES),
    )
    .await??;
    let request = protocol::authorize(enrollment, &data, protocol::current_time()?)?;
    timeout_at(operation_deadline(started, &request.operation), async {
        let mut broker = UnixStream::connect(SOCKET).await.inspect_err(|error| {
            eprintln!("FVCA_MANAGEMENT_BROKER_UNAVAILABLE {error}");
        })?;
        if broker.peer_cred()?.uid() != 0 {
            return Err(invalid("invalid management broker peer identity").into());
        }
        protocol::write_frame(&mut broker, &data, protocol::REQUEST_BYTES).await?;
        let reply = protocol::read_frame(&mut broker, protocol::RESPONSE_BYTES).await?;
        protocol::write_frame(&mut tls, &reply, protocol::RESPONSE_BYTES).await?;
        tls.shutdown().await?;
        Ok(())
    })
    .await?
}

pub(super) async fn gateway() -> Result<()> {
    let enrollment = load_enrollment()?;
    if geteuid().as_raw() != enrollment.gateway_uid || getegid().as_raw() != enrollment.gateway_gid
    {
        return Err(
            invalid("the management gateway requires its enrolled unprivileged account").into(),
        );
    }
    listener::require_context("fvca_management_gateway_t")?;
    let activated = std::net::TcpListener::from(listener::take("management-tls")?);
    if activated.local_addr()? != enrollment.address {
        return Err(
            invalid("management activation socket differs from the enrolled address").into(),
        );
    }
    activated.set_nonblocking(true)?;
    let listener = TcpListener::from_std(activated)?;
    let tls = tls(&enrollment)?;
    println!("FVCA_MANAGEMENT_GATEWAY_READY");
    let available = Arc::new(Semaphore::new(CONNECTIONS));
    loop {
        let (stream, _) = listener.accept().await?;
        if let Ok(permit) = Arc::clone(&available).try_acquire_owned() {
            let enrollment = Arc::clone(&enrollment);
            let tls = tls.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = forward(stream, &enrollment, tls).await;
            });
        }
    }
}

struct HostState {
    binding: Option<fvca_trial_authorization::guest_config::Binding>,
    resources: Resources,
    configuration_enrolled: bool,
    trial: bool,
    observed_release: Option<channel::ObservedRelease>,
}

impl HostState {
    fn read() -> Result<Self> {
        let (policy, resources) = guest_configuration::running()?;
        let trial = Path::new("/run/fvca/boot-trial-started").try_exists()?;
        Ok(Self {
            binding: policy.binding,
            resources,
            configuration_enrolled: policy.authority.is_some(),
            trial,
            observed_release: channel::observed_host_release()?,
        })
    }
}

#[derive(Serialize)]
#[serde(tag = "result", rename_all = "kebab-case")]
enum Outcome {
    Status {
        boot_configuration: Settings,
        host_trial: bool,
        configuration_enrolled: bool,
        observed_release: Option<channel::ObservedRelease>,
    },
    Preflight {
        configuration: Settings,
        activation: Activation,
    },
    ConfigurationOperation {
        #[serde(flatten)]
        receipt: intent::Receipt,
    },
    BootQuote {
        evidence: attestation::Evidence,
    },
    HostStorageHealth {
        pool: serde_json::Value,
    },
    HostBackupStatus {
        scheduled: Option<storage_health::ScheduledBackup>,
    },
    HostLocalCaptures {
        captures: Vec<local_captures::Capture>,
        next: Option<local_captures::Cursor>,
    },
    HostLocalCapture {
        capture: local_captures::Capture,
    },
    Refused {
        code: Refusal,
    },
}

#[derive(Serialize)]
struct Response<'a> {
    schema: &'static str,
    nonce: &'a str,
    host: &'a str,
    guest: &'static str,
    #[serde(flatten)]
    outcome: Outcome,
}

async fn dispatch(
    operation: &Operation,
    enrollment: &Enrollment,
    packet: &[u8],
) -> std::result::Result<Outcome, Refusal> {
    match operation {
        Operation::BootQuote { challenge } => {
            let evidence = boot_quote::request(challenge)
                .await
                .map_err(|_| Refusal::BootQuoteUnavailable)?;
            Ok(Outcome::BootQuote { evidence })
        }
        Operation::HostStorageHealth {} => {
            let pool = storage_health::read().await?;
            Ok(Outcome::HostStorageHealth { pool })
        }
        Operation::HostBackupStatus {} => {
            let scheduled = storage_health::backup().await?;
            Ok(Outcome::HostBackupStatus { scheduled })
        }
        Operation::HostLocalCaptures { after } => {
            let (captures, next) = local_captures::list(after.clone()).await?;
            Ok(Outcome::HostLocalCaptures { captures, next })
        }
        Operation::HostLocalCapture { capture_id } => {
            let capture = local_captures::inspect(capture_id.clone()).await?;
            Ok(Outcome::HostLocalCapture { capture })
        }
        Operation::ApplyConfiguration { plan } => {
            let receipt = intent::submit(enrollment, plan, packet)?;
            Ok(Outcome::ConfigurationOperation { receipt })
        }
        Operation::InspectConfiguration { operation_id } => {
            let receipt = intent::status(enrollment, operation_id)?;
            Ok(Outcome::ConfigurationOperation { receipt })
        }
        Operation::Status {} => {
            let active = HostState::read().map_err(|_| Refusal::HostStateUnavailable)?;
            Ok(Outcome::Status {
                boot_configuration: Settings::new(active.binding, active.resources),
                host_trial: active.trial,
                configuration_enrolled: active.configuration_enrolled,
                observed_release: active.observed_release,
            })
        }
        Operation::Preflight {
            expected,
            vcpus,
            memory_mib,
        } => {
            let active = HostState::read().map_err(|_| Refusal::HostStateUnavailable)?;
            if active.trial {
                return Err(Refusal::TrialInProgress);
            }
            if !active.configuration_enrolled {
                return Err(Refusal::ConfigurationAuthorityUnavailable);
            }
            let desired = Resources {
                vcpus: *vcpus,
                memory_mib: *memory_mib,
            };
            let (configuration, activation) =
                protocol::preflight(active.binding, active.resources, expected.as_ref(), desired)?;
            Ok(Outcome::Preflight {
                configuration,
                activation,
            })
        }
    }
}

async fn respond(request: &Request, enrollment: &Enrollment, packet: &[u8]) -> Result<Vec<u8>> {
    let outcome = dispatch(&request.operation, enrollment, packet)
        .await
        .unwrap_or_else(|code| Outcome::Refused { code });
    Ok(serde_json::to_vec(&Response {
        schema: "fvca-management-response-v1",
        nonce: &request.nonce,
        host: &enrollment.host,
        guest: SERVICE_GUEST_UUID.to_str()?,
        outcome,
    })?)
}

async fn serve(mut stream: UnixStream, enrollment: &Enrollment) -> Result<()> {
    let started = Instant::now();
    let peer = stream.peer_cred()?;
    if peer.uid() != enrollment.gateway_uid || peer.gid() != enrollment.gateway_gid {
        return Err(invalid("management broker peer is outside enrollment").into());
    }
    let data = timeout_at(
        started + DEADLINE,
        protocol::read_frame(&mut stream, protocol::REQUEST_BYTES),
    )
    .await??;
    let request = protocol::authorize(enrollment, &data, protocol::current_time()?)?;
    timeout_at(operation_deadline(started, &request.operation), async {
        let reply = respond(&request, enrollment, &data).await?;
        protocol::write_frame(&mut stream, &reply, protocol::RESPONSE_BYTES).await?;
        Ok(())
    })
    .await?
}

pub(super) async fn broker() -> Result<()> {
    if !geteuid().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the management broker requires the Host service account",
        )
        .into());
    }
    let enrollment = load_enrollment()?;
    listener::require_context("fvca_management_broker_t")?;
    let activated = std::os::unix::net::UnixListener::from(listener::take("management-broker")?);
    if activated.local_addr()?.as_pathname() != Some(Path::new(SOCKET)) {
        return Err(invalid("management broker received an unexpected socket").into());
    }
    activated.set_nonblocking(true)?;
    let listener = UnixListener::from_std(activated)?;
    println!("FVCA_MANAGEMENT_BROKER_READY");
    let available = Arc::new(Semaphore::new(CONNECTIONS));
    loop {
        let (stream, _) = listener.accept().await?;
        if let Ok(permit) = Arc::clone(&available).try_acquire_owned() {
            let enrollment = Arc::clone(&enrollment);
            tokio::spawn(async move {
                let _permit = permit;
                let _ = serve(stream, &enrollment).await;
            });
        }
    }
}
