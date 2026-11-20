//! Take the socket handed to this service by systemd.

use std::env;
use std::fs;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

use rustix::io::{FdFlags, fcntl_setfd};
use rustix::net::{SocketType, sockopt};

use crate::{invalid, state};

pub(super) fn require_context(domain: &str) -> io::Result<()> {
    let context = state::read(Path::new("/proc/self/attr/current"), 256)?;
    let expected = format!("system_u:system_r:{domain}:s0");
    let context = std::str::from_utf8(&context).map_err(io::Error::other)?;
    let enforcing = state::read(Path::new("/sys/fs/selinux/enforce"), 8)?;
    if context.trim_end_matches(['\0', '\n']) != expected
        || std::str::from_utf8(&enforcing)
            .map_err(io::Error::other)?
            .trim_end()
            != "1"
    {
        return Err(invalid(
            "management requires its enforcing SELinux service domain",
        ));
    }
    Ok(())
}

pub(super) fn take(name: &str) -> io::Result<OwnedFd> {
    take_stream(name, true)
}

pub(super) fn take_connected(name: &str) -> io::Result<OwnedFd> {
    take_stream(name, false)
}

fn take_stream(name: &str, listening: bool) -> io::Result<OwnedFd> {
    if env::var("LISTEN_PID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        != Some(std::process::id())
        || env::var("LISTEN_FDS").as_deref() != Ok("1")
        || env::var("LISTEN_FDNAMES").as_deref() != Ok(name)
        || !fs::metadata("/proc/self/fd/3")?.file_type().is_socket()
    {
        return Err(invalid(
            "management requires its one registered activation socket",
        ));
    }
    // systemd transfers descriptor 3 to this process without a Rust owner.
    // Startup consumes it once after checking the process, name and count.
    let socket = unsafe { OwnedFd::from_raw_fd(3) };
    fcntl_setfd(&socket, FdFlags::CLOEXEC)?;
    if sockopt::socket_type(&socket)? != SocketType::STREAM
        || sockopt::socket_acceptconn(&socket)? != listening
    {
        return Err(invalid(
            "management activation descriptor has the wrong stream state",
        ));
    }
    Ok(socket)
}
