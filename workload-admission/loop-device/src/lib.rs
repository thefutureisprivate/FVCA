#![deny(unsafe_op_in_unsafe_fn)]

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

// Linux UAPI include/uapi/linux/loop.h. This crate targets the x86-64 Guest kernel.
const LOOP_CTL_GET_FREE: libc::c_ulong = 0x4c82;
const LOOP_CONFIGURE: libc::c_ulong = 0x4c0a;
const LO_FLAGS_READ_ONLY: u32 = 1;
const LO_FLAGS_AUTOCLEAR: u32 = 4;
const SECTOR_SIZE: u64 = 512;

#[repr(C)]
struct LoopInfo64 {
    device: u64,
    inode: u64,
    rdevice: u64,
    offset: u64,
    size_limit: u64,
    number: u32,
    encrypt_type: u32,
    encrypt_key_size: u32,
    flags: u32,
    file_name: [u8; 64],
    crypt_name: [u8; 64],
    encrypt_key: [u8; 32],
    init: [u64; 2],
}

#[repr(C)]
struct LoopConfig {
    fd: u32,
    block_size: u32,
    info: LoopInfo64,
    reserved: [u64; 8],
}

const _: () = {
    assert!(size_of::<LoopInfo64>() == 232);
    assert!(size_of::<LoopConfig>() == 304);
    assert!(std::mem::offset_of!(LoopInfo64, flags) == 52);
    assert!(std::mem::offset_of!(LoopConfig, info) == 8);
};

pub struct ReadOnlyLoop {
    path: PathBuf,
    // Retain the open block device until dm-verity acquires its own reference.
    _device: File,
}

impl ReadOnlyLoop {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn open_device(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

/// Expose only one verified file interval. Closing the last kernel holder releases it.
pub fn attach(backing: &File, offset: u64, size: u64) -> io::Result<ReadOnlyLoop> {
    let metadata = backing.metadata()?;
    if !metadata.is_file()
        || size == 0
        || !offset.is_multiple_of(SECTOR_SIZE)
        || !size.is_multiple_of(SECTOR_SIZE)
        || offset
            .checked_add(size)
            .is_none_or(|end| end > metadata.len())
    {
        return Err(io::Error::other(
            "invalid verified workload device interval",
        ));
    }

    let control = open_device(Path::new("/dev/loop-control"))?;
    let control_meta = control.metadata()?;
    if !control_meta.file_type().is_char_device() || control_meta.rdev() != libc::makedev(10, 237) {
        return Err(io::Error::other("expected the kernel loop control device"));
    }
    let config = LoopConfig {
        fd: backing.as_raw_fd().try_into().map_err(io::Error::other)?,
        block_size: SECTOR_SIZE as u32,
        info: LoopInfo64 {
            device: 0,
            inode: 0,
            rdevice: 0,
            offset,
            size_limit: size,
            number: 0,
            encrypt_type: 0,
            encrypt_key_size: 0,
            flags: LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR,
            file_name: [0; 64],
            crypt_name: [0; 64],
            encrypt_key: [0; 32],
            init: [0; 2],
        },
        reserved: [0; 8],
    };
    for _ in 0..16 {
        // SAFETY: The validated control fd is live and LOOP_CTL_GET_FREE takes no argument.
        let number = unsafe { libc::ioctl(control.as_raw_fd(), LOOP_CTL_GET_FREE) };
        if number < 0 {
            return Err(io::Error::last_os_error());
        }
        let path = PathBuf::from(format!("/dev/loop{number}"));
        let device = open_device(&path)?;
        let metadata = device.metadata()?;
        if !metadata.file_type().is_block_device()
            || metadata.rdev() != libc::makedev(7, number as u32)
        {
            return Err(io::Error::other("unexpected kernel loop device"));
        }
        // SAFETY: Both fds are live. The kernel copies the repr(C) input structure
        // within this call, and AUTOCLEAR ties the mapping lifetime to open holders.
        if unsafe { libc::ioctl(device.as_raw_fd(), LOOP_CONFIGURE, &raw const config) } == 0 {
            return Ok(ReadOnlyLoop {
                path,
                _device: device,
            });
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EBUSY) {
            return Err(error);
        }
    }
    Err(io::Error::other(
        "no free workload loop device could be claimed",
    ))
}
