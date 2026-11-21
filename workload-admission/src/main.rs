#![forbid(unsafe_code)]

use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fvca_workload_admission::{Scope, Trust, read_bounded, verify, verify_transition};
use openssl::x509::X509;

fn load_trust(scope: &Path, deployment: &Path, workload: &Path) -> Result<Trust, Box<dyn Error>> {
    let scope: Scope = serde_json::from_slice(&read_bounded(scope, 1024 * 1024)?)?;
    let deployment = X509::from_pem(&read_bounded(deployment, 16 * 1024)?)?;
    let workload = X509::from_pem(&read_bounded(workload, 16 * 1024)?)?;
    Trust::new(scope, deployment, workload)
}

fn check() -> Result<(), Box<dyn Error>> {
    let files = std::env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    match files.as_slice() {
        [scope, deployment, workload, bundle] => {
            let verified = verify(bundle, &load_trust(scope, deployment, workload)?)?;
            println!(
                "FVCA_WORKLOAD_BYTES_VERIFIED {} {} {}",
                verified.service(),
                verified.digest(),
                verified.verity_root_hash()
            );
            println!(
                "FVCA_WORKLOAD_SOURCE {} {} {} {}",
                verified.service(),
                verified.provenance().label(),
                verified.permit_id().unwrap_or("none"),
                verified.expires()
            );
        }
        [
            operation,
            scope,
            deployment,
            workload,
            current,
            candidate,
            approval,
            signature,
        ] if operation.as_os_str() == "--verify-transition" => {
            let verified = verify_transition(
                current,
                candidate,
                approval,
                signature,
                &load_trust(scope, deployment, workload)?,
            )?;
            println!(
                "FVCA_WORKLOAD_TRANSITION_VERIFIED {} {} {} {}",
                verified.candidate.service(),
                verified.current.authorization_digest(),
                verified.candidate.authorization_digest(),
                verified.fresh_until,
            );
        }
        _ => {
            return Err(io::Error::other(
                "usage: fvca-workload-admission POLICY DEPLOYMENT_CERT WORKLOAD_CERT PRIVATE_STAGING_DIRECTORY\n       fvca-workload-admission --verify-transition POLICY DEPLOYMENT_CERT WORKLOAD_CERT CURRENT CANDIDATE APPROVAL SIGNATURE",
            ).into());
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match check() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("FVCA workload verification failed: {error}");
            ExitCode::FAILURE
        }
    }
}
