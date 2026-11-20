#![forbid(unsafe_code)]

use std::alloc::System;
use std::io;
use std::process::ExitCode;

use fvca_initrd_bootstrap::{guest_boot::SERVICE_GUEST_UUID, invalid};
use fvca_libvirt_boundary::{Connection, RUNNING};

#[global_allocator]
static ALLOCATOR: System = System;

fn verify_guest() -> io::Result<()> {
    let connection = Connection::connect()?;
    let guest = connection
        .lookup(SERVICE_GUEST_UUID)?
        .ok_or_else(|| invalid("the Service Guest is missing from the trial boot"))?;
    if guest.state()? != RUNNING {
        return Err(invalid(
            "the Service Guest is not running in the trial boot",
        ));
    }
    guest.require_guest_agent()
}

fn main() -> ExitCode {
    if let Err(error) = fvca_allocator_binding::require_allocator()
        .and_then(|()| verify_guest())
        .and_then(|()| fvca_initrd_bootstrap::hypervisor_trial::record_health())
    {
        eprintln!("FVCA_TRIAL_HEALTH_REFUSED {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
