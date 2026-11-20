//! Off-node quote requests to one explicitly enrolled Hypervisor.

use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::{
    rand,
    signature::{Ed25519KeyPair, KeyPair},
};
use fvca_trial_authorization::{MANAGEMENT_POLICY_BYTES, guest::SERVICE_GUEST_UUID};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, pem::PemObject};
use rustls::{ClientConfig, RootCertStore, version::TLS13};
use serde::Deserialize;
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use super::protocol::{self, Enrollment};
use crate::{Result, attestation::Evidence, channel, invalid, state};

const CA_BYTES: u64 = 64 * 1024;
const KEY_BYTES: u64 = 4096;
const DEADLINE: Duration = Duration::from_secs(12);

fn signer(path: &Path) -> Result<Ed25519KeyPair> {
    let file = state::open_regular(path)?;
    let metadata = file.metadata()?;
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o600
        || !(1..=KEY_BYTES).contains(&metadata.len())
    {
        return Err(invalid("expected a bounded private attestation key with mode 0600").into());
    }
    let mut pem = Zeroizing::new(Vec::with_capacity(KEY_BYTES as usize + 1));
    file.take(KEY_BYTES + 1).read_to_end(&mut pem)?;
    if pem.len() as u64 > KEY_BYTES {
        return Err(invalid("attestation key exceeds its size bound").into());
    }
    let key = Zeroizing::new(PrivatePkcs8KeyDer::from_pem_slice(&pem)?);
    Ok(Ed25519KeyPair::from_pkcs8(key.secret_pkcs8_der())?)
}

fn connector(path: &Path) -> Result<TlsConnector> {
    let pem = state::read(path, CA_BYTES)?;
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(&pem) {
        roots.add(certificate?)?;
    }
    if roots.is_empty() {
        return Err(invalid("expected a PEM trust bundle for management TLS").into());
    }
    let mut config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&TLS13])?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![protocol::ALPN.to_vec()];
    Ok(TlsConnector::from(Arc::new(config)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    schema: String,
    host: String,
    guest: String,
    nonce: String,
    result: String,
    evidence: Option<Evidence>,
    code: Option<String>,
}

pub(crate) async fn collect(
    enrollment: &Path,
    ca: &Path,
    server_name: &str,
    operator: &Path,
    host: &str,
    challenge: &str,
) -> Result<Evidence> {
    let enrollment: Enrollment =
        serde_json::from_slice(&state::read(enrollment, MANAGEMENT_POLICY_BYTES as u64)?)?;
    enrollment.validate()?;
    if enrollment.host != host {
        return Err(
            invalid("management enrollment and boot reference name different Hosts").into(),
        );
    }
    let expected_key = enrollment
        .attestation_operator_public_key
        .as_deref()
        .ok_or_else(|| invalid("the Host has no attestation operator"))?;
    let key = signer(operator)?;
    if hex::encode(key.public_key().as_ref()) != expected_key {
        return Err(invalid("attestation key differs from the enrolled operator").into());
    }
    let connector = connector(ca)?;
    let name = ServerName::try_from(server_name.to_owned())?;
    timeout(DEADLINE, async {
        let socket = TcpStream::connect(enrollment.address).await?;
        let mut tls = connector.connect(name, socket).await?;
        let (_, session) = tls.get_ref();
        let leaf = session
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or_else(|| invalid("management TLS supplied no leaf certificate"))?;
        if session.alpn_protocol() != Some(protocol::ALPN)
            || channel::digest(leaf.as_ref()) != enrollment.tls_certificate_sha256
        {
            return Err(
                invalid("management TLS protocol or certificate differs from enrollment").into(),
            );
        }

        let mut nonce = [0; 16];
        rand::fill(&mut nonce)
            .map_err(|_| io::Error::other("could not generate a request nonce"))?;
        let nonce = hex::encode(nonce);
        let guest = SERVICE_GUEST_UUID.to_str()?;
        let now = protocol::current_time()?;
        let body = serde_json::to_vec(&serde_json::json!({
            "schema": "fvca-management-request-v1", "host": host, "guest": guest, "nonce": nonce,
            "issued_at": now, "expires": now + protocol::VALIDITY_SECONDS,
            "operation": {"type": "boot-quote", "challenge": challenge},
        }))?;
        let mut request = key.sign(&body).as_ref().to_vec();
        request.extend_from_slice(&body);
        protocol::write_frame(&mut tls, &request, protocol::REQUEST_BYTES).await?;
        let reply: Reply = serde_json::from_slice(
            &protocol::read_frame(&mut tls, protocol::RESPONSE_BYTES).await?,
        )?;
        if reply.schema != "fvca-management-response-v1"
            || reply.host != host
            || reply.guest != guest
            || reply.nonce != nonce
        {
            return Err(invalid("boot quote response does not match its request").into());
        }
        match (reply.result.as_str(), reply.evidence, reply.code.as_deref()) {
            ("boot-quote", Some(evidence), None) => Ok(evidence),
            ("refused", None, Some("boot-quote-unavailable")) => {
                Err(io::Error::other("the Hypervisor could not collect a boot quote").into())
            }
            _ => Err(invalid("invalid boot quote response").into()),
        }
    })
    .await?
}
