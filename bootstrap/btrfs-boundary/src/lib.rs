//! Read the Btrfs inode flags that govern checksums and CoW.

use std::ffi::{c_int, c_ulong};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

// x86-64 Linux UAPI BTRFS_IOC_TREE_SEARCH, using a 4096-byte search buffer.
const TREE_SEARCH: c_ulong = 0xd000_9411;
const INODE_ITEM: u32 = 1;
const NODATASUM_OR_NODATACOW: u64 = 3;

#[repr(C)]
struct Key {
    tree_id: u64,
    min_objectid: u64,
    max_objectid: u64,
    min_offset: u64,
    max_offset: u64,
    min_transid: u64,
    max_transid: u64,
    min_type: u32,
    max_type: u32,
    items: u32,
    unused: u32,
    reserved: [u64; 4],
}

#[repr(C)]
struct Search {
    key: Key,
    buffer: [u8; 3992],
}

const _: () = assert!(size_of::<Search>() == 4096);

unsafe extern "C" {
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
}

pub fn require_cow_and_checksums(file: &File) -> io::Result<()> {
    let inode = file.metadata()?.ino();
    let mut search = Search {
        key: Key {
            tree_id: 0,
            min_objectid: inode,
            max_objectid: inode,
            min_offset: 0,
            max_offset: 0,
            min_transid: 0,
            max_transid: u64::MAX,
            min_type: INODE_ITEM,
            max_type: INODE_ITEM,
            items: 1,
            unused: 0,
            reserved: [0; 4],
        },
        buffer: [0; 3992],
    };
    // The fd is borrowed from a live File. The kernel writes only to Search.
    if unsafe { ioctl(file.as_raw_fd(), TREE_SEARCH, &mut search as *mut Search) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let word = |offset: usize| u64::from_ne_bytes(search.buffer[offset..offset + 8].try_into().unwrap());
    let kind = u32::from_ne_bytes(search.buffer[24..28].try_into().unwrap());
    let length = u32::from_ne_bytes(search.buffer[28..32].try_into().unwrap());
    if search.key.items != 1 || word(8) != inode || word(16) != 0 || kind != INODE_ITEM || length < 72 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Btrfs did not return the requested inode item"));
    }
    // The native-endian search header is 32 bytes, followed by the packed
    // little-endian inode item. Its flags are at byte offset 64.
    let flags = u64::from_le_bytes(search.buffer[96..104].try_into().unwrap());
    if flags & NODATASUM_OR_NODATACOW != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Btrfs inode disables CoW or data checksums"));
    }
    Ok(())
}
