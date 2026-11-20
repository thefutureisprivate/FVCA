//! Authenticate requests on the network and authorize them again at the Host broker.

mod protocol;

use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fvca_trial_authorization::{
    MANAGEMENT_POLICY, MANAGEMENT_POLICY_BYTES, guest::SERVICE_GUEST_UUID, guest_config::Resources,
    management_binding,
};
use rustix::process::{Gid, getegid, geteuid};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::{ServerConfig, version::TLS13};
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::{Result, channel, guest_configuration, invalid, state};
use protocol::{Activation, Enrollment, Operation, Refusal, Request, Settings};

const SOCKET: &str = "/run/fvca-management-broker/broker.sock";
const CREDENTIAL_BYTES: u64 = 16 * 1024;
const CONNECTIONS: usize = 8;
const DEADLINE: Duration = Duration::from_secs(3);

fn load_enrollment() -> Result<Arc<Enrollment>> {
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
    let cmdline = state::read(Path::new("/proc/cmdline"), 32 * 1024)?;
    if data.len() > MANAGEMENT_POLICY_BYTES
        || management_binding(std::str::from_utf8(&cmdline)?)? != Some(&channel::digest(&data))
    {
        return Err(invalid("management enrollment differs from its signed UKI").into());
    }
    let value: Enrollment = serde_json::from_slice(&data)?;
    value.validate()?;
    Ok(Arc::new(value))
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
    let mut tls = acceptor.accept(stream).await?;
    if tls.get_ref().1.alpn_protocol() != Some(protocol::ALPN) {
        return Err(invalid("unsupported management protocol").into());
    }
    let data = protocol::read_frame(&mut tls, protocol::REQUEST_BYTES).await?;
    protocol::authorize(enrollment, &data, protocol::current_time()?)?;
    let mut broker = UnixStream::connect(SOCKET).await?;
    if broker.peer_cred()?.uid() != 0 {
        return Err(invalid("invalid management broker peer identity").into());
    }
    protocol::write_frame(&mut broker, &data, protocol::REQUEST_BYTES).await?;
    let reply = protocol::read_frame(&mut broker, protocol::RESPONSE_BYTES).await?;
    protocol::write_frame(&mut tls, &reply, protocol::RESPONSE_BYTES).await?;
    tls.shutdown().await?;
    Ok(())
}

pub(super) async fn gateway() -> Result<()> {
    let enrollment = load_enrollment()?;
    if geteuid().as_raw() != enrollment.gateway_uid || getegid().as_raw() != enrollment.gateway_gid
    {
        return Err(
            invalid("the management gateway requires its enrolled unprivileged account").into(),
        );
    }
    let tls = tls(&enrollment)?;
    let listener = TcpListener::bind(enrollment.address).await?;
    let available = Arc::new(Semaphore::new(CONNECTIONS));
    loop {
        let (stream, _) = listener.accept().await?;
        if let Ok(permit) = Arc::clone(&available).try_acquire_owned() {
            let enrollment = Arc::clone(&enrollment);
            let tls = tls.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = timeout(DEADLINE, forward(stream, &enrollment, tls)).await;
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

    fn respond(self, operation: &Operation) -> Outcome {
        match operation {
            Operation::Status => Outcome::Status {
                boot_configuration: Settings::new(self.binding, self.resources),
                host_trial: self.trial,
                configuration_enrolled: self.configuration_enrolled,
                observed_release: self.observed_release,
            },
            Operation::Preflight {
                expected,
                vcpus,
                memory_mib,
            } => {
                if self.trial {
                    return Outcome::Refused {
                        code: Refusal::TrialInProgress,
                    };
                }
                if !self.configuration_enrolled {
                    return Outcome::Refused {
                        code: Refusal::ConfigurationAuthorityUnavailable,
                    };
                }
                let desired = Resources {
                    vcpus: *vcpus,
                    memory_mib: *memory_mib,
                };
                match protocol::preflight(self.binding, self.resources, expected.as_ref(), desired)
                {
                    Ok((configuration, activation)) => Outcome::Preflight {
                        configuration,
                        activation,
                    },
                    Err(code) => Outcome::Refused { code },
                }
            }
        }
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

fn respond(request: &Request, enrollment: &Enrollment) -> Result<Vec<u8>> {
    let outcome = HostState::read()
        .map(|state| state.respond(&request.operation))
        .unwrap_or(Outcome::Refused {
            code: Refusal::HostStateUnavailable,
        });
    Ok(serde_json::to_vec(&Response {
        schema: "fvca-management-response-v1",
        nonce: &request.nonce,
        host: &enrollment.host,
        guest: SERVICE_GUEST_UUID.to_str()?,
        outcome,
    })?)
}

async fn serve(mut stream: UnixStream, enrollment: &Enrollment) -> Result<()> {
    let peer = stream.peer_cred()?;
    if peer.uid() != enrollment.gateway_uid || peer.gid() != enrollment.gateway_gid {
        return Err(invalid("management broker peer is outside enrollment").into());
    }
    let data = protocol::read_frame(&mut stream, protocol::REQUEST_BYTES).await?;
    let request = protocol::authorize(enrollment, &data, protocol::current_time()?)?;
    let reply = respond(&request, enrollment)?;
    protocol::write_frame(&mut stream, &reply, protocol::RESPONSE_BYTES).await?;
    Ok(())
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
    let path = Path::new(SOCKET);
    let listener = UnixListener::bind(path)?;
    rustix::fs::chown(path, None, Some(Gid::from_raw(enrollment.gateway_gid)))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    let available = Arc::new(Semaphore::new(CONNECTIONS));
    loop {
        let (stream, _) = listener.accept().await?;
        if let Ok(permit) = Arc::clone(&available).try_acquire_owned() {
            let enrollment = Arc::clone(&enrollment);
            tokio::spawn(async move {
                let _permit = permit;
                let _ = timeout(DEADLINE, serve(stream, &enrollment)).await;
            });
        }
    }
}
