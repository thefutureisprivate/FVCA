//! Narrow x86-64 Linux UAPI for the selected Btrfs storage profile.

use std::ffi::{CStr, c_char, c_int, c_uint, c_ulong};
use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

// x86-64 Linux UAPI BTRFS_IOC_TREE_SEARCH, using a 4096-byte search buffer.
const TREE_SEARCH: c_ulong = 0xd000_9411;
const INODE_ITEM: u32 = 1;
const NODATASUM_OR_NODATACOW: u64 = 3;
const SNAP_CREATE_V2: c_ulong = 0x5000_9417;
const SUBVOL_CREATE_V2: c_ulong = 0x5000_9418;
const SNAP_DESTROY_V2: c_ulong = 0x5000_943f;
const SYNC: c_ulong = 0x9408;
const FICLONE: c_ulong = 0x4004_9409;
const RENAME_NOREPLACE: c_uint = 1;
const RENAME_EXCHANGE: c_uint = 2;
const GET_SUBVOL_INFO: c_ulong = 0x81f8_943c;
const SPACE_INFO: c_ulong = 0xc010_9414;
const FS_INFO: c_ulong = 0x8400_941f;
const DEV_INFO: c_ulong = 0xd000_941e;
const READ_ONLY: u64 = 1 << 1;
const ROOT_READ_ONLY: u64 = 1;
const RAID1: u64 = 1 << 4;
const SPACE_GLOBAL_RESERVE: u64 = 1 << 49;
const MIB: u64 = 1024 * 1024;

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

#[repr(C)]
struct SnapshotArgs {
    source_fd: i64,
    transid: u64,
    flags: u64,
    unused: [u64; 4],
    name: [u8; 4040],
}

#[repr(C)]
struct SubvolumeInfo {
    tree_id: u64,
    name: [u8; 256],
    parent_id: u64,
    dir_id: u64,
    generation: u64,
    flags: u64,
    uuid: [u8; 16],
    parent_uuid: [u8; 16],
    received_uuid: [u8; 16],
    other: [u64; 20],
}

#[repr(C)]
struct FsInfo {
    max_id: u64,
    num_devices: u64,
    uuid: [u8; 16],
    other: [u64; 124],
}

#[repr(C)]
struct DevInfo {
    id: u64,
    uuid: [u8; 16],
    allocated: u64,
    total: u64,
    filesystem: [u8; 16],
    other: [u64; 505],
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Space {
    flags: u64,
    total: u64,
    used: u64,
}

#[repr(C)]
struct Spaces {
    slots: u64,
    count: u64,
    entries: [Space; 8],
}

const _: () = assert!(size_of::<Search>() == 4096);
const _: () = assert!(size_of::<SnapshotArgs>() == 4096);
const _: () = assert!(size_of::<SubvolumeInfo>() == 504);
const _: () = assert!(size_of::<FsInfo>() == 1024);
const _: () = assert!(size_of::<DevInfo>() == 4096);

unsafe extern "C" {
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    fn renameat2(old_dir: c_int, old_name: *const c_char, new_dir: c_int, new_name: *const c_char,
                 flags: c_uint) -> c_int;
}

#[derive(Debug, PartialEq, Eq)]
pub struct Subvolume {
    pub id: u64,
    pub uuid: String,
    pub parent_uuid: String,
    pub read_only: bool,
}

fn uuid(bytes: [u8; 16]) -> String {
    let value = u128::from_be_bytes(bytes);
    format!("{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        value >> 96, (value >> 80) & 0xffff, (value >> 64) & 0xffff,
        (value >> 48) & 0xffff, value & 0xffff_ffff_ffff)
}

pub fn subvolume(file: &File) -> io::Result<Subvolume> {
    if !file.metadata()?.is_dir() || file.metadata()?.ino() != 256 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "expected a Btrfs subvolume root"));
    }
    let mut info = SubvolumeInfo {
        tree_id: 0, name: [0; 256], parent_id: 0, dir_id: 0, generation: 0, flags: 0,
        uuid: [0; 16], parent_uuid: [0; 16], received_uuid: [0; 16], other: [0; 20],
    };
    // This fd and the fixed-size output structure remain live during the call.
    if unsafe { ioctl(file.as_raw_fd(), GET_SUBVOL_INFO, &mut info as *mut SubvolumeInfo) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if info.tree_id < 256 || info.uuid == [0; 16] || info.received_uuid != [0; 16] {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected Btrfs subvolume identity"));
    }
    Ok(Subvolume { id: info.tree_id, uuid: uuid(info.uuid), parent_uuid: uuid(info.parent_uuid),
                   read_only: info.flags & ROOT_READ_ONLY != 0 })
}

pub fn snapshot_read_only(source: &File, destination: &File, name: &str) -> io::Result<()> {
    volume_by_name(SNAP_CREATE_V2, i64::from(source.as_raw_fd()), destination, name, READ_ONLY)
}

pub fn create_subvolume(destination: &File, name: &str) -> io::Result<()> {
    volume_by_name(SUBVOL_CREATE_V2, 0, destination, name, 0)
}

pub fn remove_capture_snapshot(parent: &File) -> io::Result<()> {
    // The only deletion target exposed by this boundary is the fixed capture
    // member relative to its already verified parent directory.
    volume_by_name(SNAP_DESTROY_V2, 0, parent, "snapshot", 0)
}

pub fn sync(pool: &File) -> io::Result<()> {
    // BTRFS_IOC_SYNC takes no payload and commits the filesystem transaction.
    if unsafe { ioctl(pool.as_raw_fd(), SYNC, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn volume_by_name(request: c_ulong, source_fd: i64, destination: &File, name: &str, flags: u64) -> io::Result<()> {
    if name.is_empty() || name.len() > 255 || name.starts_with('.') ||
        !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid Btrfs subvolume name"));
    }
    let mut args = SnapshotArgs {
        source_fd, transid: 0, flags, unused: [0; 4], name: [0; 4040],
    };
    args.name[..name.len()].copy_from_slice(name.as_bytes());
    // Both descriptors and the NUL-terminated UAPI name outlive the ioctl.
    if unsafe { ioctl(destination.as_raw_fd(), request, &args as *const SnapshotArgs) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn reflink(source: &File, destination: &File) -> io::Result<()> {
    // FICLONE takes the source descriptor as a scalar int, not a pointer.
    if unsafe { ioctl(destination.as_raw_fd(), FICLONE, source.as_raw_fd()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn place_subvolume(old_dir: &File, old_name: &CStr, new_dir: &File, new_name: &CStr, exchange: bool) -> io::Result<()> {
    for name in [old_name, new_name] {
        if name.to_bytes().is_empty() || name.to_bytes().starts_with(b".") || name.to_bytes().contains(&b'/') {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "expected a direct subvolume name"));
        }
    }
    let flags = if exchange { RENAME_EXCHANGE } else { RENAME_NOREPLACE };
    // Both directory descriptors and both names are live for the atomic operation.
    if unsafe { renameat2(old_dir.as_raw_fd(), old_name.as_ptr(), new_dir.as_raw_fd(), new_name.as_ptr(), flags) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn filesystem(pool: &File) -> io::Result<FsInfo> {
    let mut info = FsInfo { max_id: 0, num_devices: 0, uuid: [0; 16], other: [0; 124] };
    // The fixed-size result layouts are from the Linux Btrfs UAPI.
    if unsafe { ioctl(pool.as_raw_fd(), FS_INFO, &mut info as *mut FsInfo) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if info.uuid == [0; 16] || info.num_devices != 2 {
        return Err(io::Error::other("the capture pool requires two Btrfs mirror members"));
    }
    Ok(info)
}

pub fn filesystem_uuid(pool: &File) -> io::Result<String> {
    Ok(uuid(filesystem(pool)?.uuid))
}

pub struct Headroom {
    pub data: u64,
    pub metadata: u64,
    pub system: u64,
    pub unallocated: u64,
}

impl Headroom {
    pub fn affords(&self, data: u64, metadata: u64) -> bool {
        // Shared unallocated bytes can fund future allocations once across
        // both mirror members. Reserve space for system chunks and repair.
        let deficit = data.saturating_sub(self.data)
            .saturating_add(metadata.saturating_sub(self.metadata))
            .saturating_add((16 * MIB).saturating_sub(self.system));
        deficit <= self.unallocated.saturating_sub(32 * MIB)
    }
}

pub fn headroom(pool: &File) -> io::Result<Headroom> {
    let info = filesystem(pool)?;
    let fsid = uuid(info.uuid);
    let mut unallocated = u64::MAX;
    let mut devices = 0;
    for entry in fs::read_dir(format!("/sys/fs/btrfs/{fsid}/devinfo"))? {
        let entry = entry?;
        let id = entry.file_name().to_str().and_then(|name| name.parse().ok())
            .ok_or_else(|| io::Error::other("invalid Btrfs device ID"))?;
        let mut device = DevInfo { id, uuid: [0; 16], allocated: 0, total: 0, filesystem: [0; 16], other: [0; 505] };
        // DEV_INFO returns one device into the caller's 4096-byte buffer.
        if unsafe { ioctl(pool.as_raw_fd(), DEV_INFO, &mut device as *mut DevInfo) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if device.filesystem != info.uuid || device.total == 0 || device.allocated > device.total {
            return Err(io::Error::other("unexpected Btrfs mirror device"));
        }
        unallocated = unallocated.min(device.total - device.allocated);
        devices += 1;
    }
    if devices != 2 || info.num_devices != devices {
        return Err(io::Error::other("the capture pool requires two Btrfs mirror members"));
    }
    let [data, metadata, system] = raid1_free_space(pool)?;
    Ok(Headroom { data, metadata, system, unallocated })
}

pub fn require_raid1_profiles(pool: &File) -> io::Result<()> {
    raid1_free_space(pool).map(|_| ())
}

fn raid1_free_space(pool: &File) -> io::Result<[u64; 3]> {
    let mut spaces = Spaces {
        slots: 8,
        count: 0,
        entries: [Space::default(); 8],
    };
    // SPACE_INFO takes a 16-byte header followed by slots records. The advertised
    // slot count is exactly the capacity of the inline array.
    if unsafe { ioctl(pool.as_raw_fd(), SPACE_INFO, &mut spaces as *mut Spaces) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if spaces.count > spaces.slots || spaces.slots != 8 {
        return Err(io::Error::other("unexpected Btrfs space profile count"));
    }

    let mut free = [None; 3];
    for entry in &spaces.entries[..spaces.count as usize] {
        if entry.flags == SPACE_GLOBAL_RESERVE {
            continue;
        }
        let index = match entry.flags ^ RAID1 {
            1 => 0, // DATA
            4 => 1, // METADATA
            2 => 2, // SYSTEM
            _ => {
                return Err(io::Error::other(
                    "expected only Btrfs RAID1 allocation profiles",
                ));
            }
        };
        if entry.used > entry.total || free[index].replace(entry.total - entry.used).is_some() {
            return Err(io::Error::other(
                "invalid or duplicate Btrfs RAID1 allocation profile",
            ));
        }
    }
    let [Some(data), Some(metadata), Some(system)] = free else {
        return Err(io::Error::other("incomplete Btrfs RAID1 space accounting"));
    };
    Ok([data, metadata, system])
}

pub fn require_capture_space(pool: &File, data: u64) -> io::Result<()> {
    if !headroom(pool)?.affords(data, 64 * MIB) {
        return Err(io::Error::other("insufficient mirrored Btrfs data, metadata or system headroom for capture"));
    }
    Ok(())
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
