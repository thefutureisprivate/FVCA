#![forbid(unsafe_code)]

use std::error::Error;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use fvca_workload_admission::{Scope, Trust, read_bounded, verify};
use openssl::x509::X509;

fn check() -> Result<(), Box<dyn Error>> {
    let files = std::env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    let [scope, deployment, workload, bundle] = files.as_slice() else {
        return Err(io::Error::other(
            "usage: fvca-workload-admission POLICY DEPLOYMENT_CERT WORKLOAD_CERT PRIVATE_STAGING_DIRECTORY",
        ).into());
    };
    let scope: Scope = serde_json::from_slice(&read_bounded(scope, 1024 * 1024)?)?;
    let deployment = X509::from_pem(&read_bounded(deployment, 16 * 1024)?)?;
    let workload = X509::from_pem(&read_bounded(workload, 16 * 1024)?)?;
    let verified = verify(bundle, &Trust::new(scope, deployment, workload)?)?;
    println!(
        "FVCA_WORKLOAD_BYTES_VERIFIED {} {} {}",
        verified.service(),
        verified.digest(),
        verified.verity_root_hash()
    );
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
