//! Narrow x86-64 Linux UAPI for the selected Btrfs storage profile.

use std::ffi::{CStr, OsStr, c_char, c_int, c_uint, c_ulong};
use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

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
const GET_DEV_STATS: c_ulong = 0xc408_9434;
const SCRUB: c_ulong = 0xc400_941b;
const DEV_REPLACE: c_ulong = 0xca28_9435;
const BALANCE_V2: c_ulong = 0xc400_9420;
const BALANCE_PROGRESS: c_ulong = 0x8400_9422;
const READ_ONLY: u64 = 1 << 1;
const ROOT_READ_ONLY: u64 = 1;
const RAID1: u64 = 1 << 4;
const DUP: u64 = 1 << 5;
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
    reserved: [u64; 377],
    path: [u8; 1024],
}

#[repr(C)]
struct ReplaceArgs {
    command: u64,
    result: u64,
    device_or_state: u64,
    mode_or_progress: u64,
    source_name_or_counters: [u8; 1025],
    target_name: [u8; 1025],
    padding: [u8; 6],
    reserved: [u64; 64],
}

#[repr(C)]
struct BalanceArgs {
    flags: u64,
    state: u64,
    filters: [[u64; 17]; 3],
    counts: [u64; 3],
    reserved: [u64; 72],
}
#[repr(C)]
struct DevStats {
    id: u64,
    count: u64,
    flags: u64,
    values: [u64; 5],
    reserved: [u64; 121],
}

#[repr(C)]
struct ScrubArgs {
    id: u64,
    start: u64,
    end: u64,
    flags: u64,
    progress: [u64; 15],
    reserved: [u64; 109],
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
const _: () = assert!(size_of::<DevStats>() == 1032);
const _: () = assert!(size_of::<ScrubArgs>() == 1024);
const _: () = assert!(size_of::<ReplaceArgs>() == 2600);
const _: () = assert!(size_of::<BalanceArgs>() == 1024);

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

fn filesystem(pool: &File, members: u64) -> io::Result<FsInfo> {
    let mut info = FsInfo { max_id: 0, num_devices: 0, uuid: [0; 16], other: [0; 124] };
    // The fixed-size result layouts are from the Linux Btrfs UAPI.
    if unsafe { ioctl(pool.as_raw_fd(), FS_INFO, &mut info as *mut FsInfo) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if info.uuid == [0; 16] || info.num_devices != members {
        return Err(io::Error::other("unexpected Btrfs filesystem or device count"));
    }
    Ok(info)
}

pub fn filesystem_uuid(pool: &File) -> io::Result<String> {
    Ok(uuid(filesystem(pool, 2)?.uuid))
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

fn devices(pool: &File, info: &FsInfo) -> io::Result<Vec<DevInfo>> {
    let expected = info.num_devices as usize;
    let mut devices = Vec::with_capacity(expected);
    for entry in fs::read_dir(format!("/sys/fs/btrfs/{}/devinfo", uuid(info.uuid)))? {
        let entry = entry?;
        if devices.len() == expected {
            return Err(io::Error::other("unexpected Btrfs device count"));
        }
        let id = entry.file_name().to_str().and_then(|name| name.parse().ok())
            .filter(|&id| id != 0)
            .ok_or_else(|| io::Error::other("invalid Btrfs device ID"))?;
        devices.push(device_info(pool, id, info.uuid)?);
    }
    devices.sort_unstable_by_key(|device| device.id);
    if devices.len() != expected {
        return Err(io::Error::other("Btrfs device list is incomplete"));
    }
    Ok(devices)
}

fn device_info(pool: &File, id: u64, fsid: [u8; 16]) -> io::Result<DevInfo> {
    let mut device = DevInfo {
        id, uuid: [0; 16], allocated: 0, total: 0, filesystem: [0; 16], reserved: [0; 377], path: [0; 1024],
    };
    // DEV_INFO returns one device into the caller's 4096-byte buffer.
    if unsafe { ioctl(pool.as_raw_fd(), DEV_INFO, &mut device as *mut DevInfo) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if device.id != id || device.filesystem != fsid || device.uuid == [0; 16] || device.total == 0
        || device.allocated > device.total {
        return Err(io::Error::other("unexpected Btrfs mirror device"));
    }
    Ok(device)
}

pub struct ReplacementMember {
    pub uuid: String,
    pub bytes: u64,
    pub path: Option<PathBuf>,
}

pub fn replacement_member(pool: &File, fsid: &str, id: u64, replacing: bool) -> io::Result<ReplacementMember> {
    // An unfinished replacement adds the reserved device ID zero to FS_INFO.
    let info = filesystem(pool, if replacing { 3 } else { 2 })?;
    if uuid(info.uuid) != fsid {
        return Err(io::Error::other("Btrfs replacement pool has an unexpected filesystem identity"));
    }
    let device = device_info(pool, id, info.uuid)?;
    let path = CStr::from_bytes_until_nul(&device.path).map_err(io::Error::other)?.to_bytes();
    Ok(ReplacementMember {
        uuid: uuid(device.uuid),
        bytes: device.total,
        path: (!path.is_empty()).then(|| PathBuf::from(OsStr::from_bytes(path))),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplacementState {
    NeverStarted,
    Started,
    Finished,
    Canceled,
    Suspended,
}

fn replace_ioctl(pool: &File, command: u64, missing: u64, target: &[u8]) -> io::Result<ReplaceArgs> {
    let mut request = ReplaceArgs {
        command, result: u64::MAX, device_or_state: missing, mode_or_progress: 0,
        source_name_or_counters: [0; 1025], target_name: [0; 1025], padding: [0; 6], reserved: [0; 64],
    };
    if target.len() >= request.target_name.len() {
        return Err(io::Error::other("Btrfs replacement target path exceeds the kernel limit"));
    }
    request.target_name[..target.len()].copy_from_slice(target);
    // The ioctl uses the same fixed buffer for start parameters and status.
    if unsafe { ioctl(pool.as_raw_fd(), DEV_REPLACE, &mut request as *mut ReplaceArgs) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if request.result != 0 {
        return Err(io::Error::other(format!("Btrfs replacement result {}", request.result)));
    }
    Ok(request)
}

pub fn start_missing_replacement(pool: &File, missing: u64, target: &CStr) -> io::Result<()> {
    if missing == 0 || target.to_bytes().is_empty() {
        return Err(io::Error::other("Btrfs replacement requires an absent device ID and a target"));
    }
    replace_ioctl(pool, 0, missing, target.to_bytes()).map(|_| ())
}

pub fn replacement_status(pool: &File) -> io::Result<(ReplacementState, u64, u64)> {
    let result = replace_ioctl(pool, 1, 0, &[])?;
    let state = match result.device_or_state {
        0 => ReplacementState::NeverStarted,
        1 => ReplacementState::Started,
        2 => ReplacementState::Finished,
        3 => ReplacementState::Canceled,
        4 => ReplacementState::Suspended,
        _ => return Err(io::Error::other("unknown Btrfs replacement state")),
    };
    // Status puts the timestamps first in the shared source-name field.
    let counters = result.source_name_or_counters;
    let writes = u64::from_ne_bytes(counters[16..24].try_into().map_err(io::Error::other)?);
    let reads = u64::from_ne_bytes(counters[24..32].try_into().map_err(io::Error::other)?);
    Ok((state, writes, reads))
}

pub fn repair_single_allocations(pool: &File) -> io::Result<()> {
    const TYPES: u64 = 7;
    const RESUME: u64 = 1 << 4;
    let mut policy = [0; 17];
    policy[0] = 1 << 48; // BTRFS_AVAIL_ALLOC_BIT_SINGLE
    policy[7] = RAID1;
    policy[8] = 1 | (1 << 8) | (1 << 9); // PROFILES, CONVERT, SOFT
    let filters = [policy; 3];
    let mut observed = BalanceArgs { flags: 0, state: 0, filters: [[0; 17]; 3], counts: [0; 3], reserved: [0; 72] };
    // A paused balance can only be resumed with this operation's exact filters.
    let flags = if unsafe { ioctl(pool.as_raw_fd(), BALANCE_PROGRESS, &mut observed as *mut BalanceArgs) } < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotConnected {
            return Err(error);
        }
        TYPES
    } else {
        if observed.flags & !RESUME != TYPES || observed.filters != filters || observed.state != 0 {
            return Err(io::Error::other("a different or active Btrfs balance prevents mirror repair"));
        }
        RESUME
    };
    let mut request = BalanceArgs { flags, state: 0, filters, counts: [0; 3], reserved: [0; 72] };
    // BALANCE_V2 takes a fixed set of data, metadata and system filters.
    if unsafe { ioctl(pool.as_raw_fd(), BALANCE_V2, &mut request as *mut BalanceArgs) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn mirror_devices(pool: &File, info: &FsInfo) -> io::Result<[DevInfo; 2]> {
    devices(pool, info)?.try_into().map_err(|_| io::Error::other("expected two Btrfs mirror members"))
}

pub fn headroom(pool: &File) -> io::Result<Headroom> {
    let [first, second] = mirror_devices(pool, &filesystem(pool, 2)?)?;
    let unallocated = (first.total - first.allocated).min(second.total - second.allocated);
    let [data, metadata, system] = raid1_space(pool)?.map(|space| space.total - space.used);
    Ok(Headroom { data, metadata, system, unallocated })
}

pub struct DeviceHealth {
    pub id: u64,
    pub physical_bytes: u64,
    pub allocated_bytes: u64,
    pub write_errors: u64,
    pub read_errors: u64,
    pub flush_errors: u64,
    pub corruption_errors: u64,
    pub generation_errors: u64,
}

impl DeviceHealth {
    fn read(pool: &File, device: DevInfo) -> io::Result<Self> {
        let mut stats = DevStats { id: device.id, count: 5, flags: 0, values: [0; 5], reserved: [0; 121] };
        // The buffer matches the x86-64 UAPI. Zero flags request a read without resetting counters.
        if unsafe { ioctl(pool.as_raw_fd(), GET_DEV_STATS, &mut stats as *mut DevStats) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if stats.id != device.id || stats.count != 5 || stats.flags != 0 {
            return Err(io::Error::other("invalid Btrfs device statistics"));
        }
        let [write_errors, read_errors, flush_errors, corruption_errors, generation_errors] = stats.values;
        Ok(Self { id: device.id, physical_bytes: device.total, allocated_bytes: device.allocated,
            write_errors, read_errors, flush_errors, corruption_errors, generation_errors })
    }
}

pub struct SpaceUsage {
    pub total: u64,
    pub used: u64,
}

pub struct MirrorHealth {
    pub filesystem_uuid: String,
    pub data: SpaceUsage,
    pub metadata: SpaceUsage,
    pub system: SpaceUsage,
    pub members: [DeviceHealth; 2],
}

pub fn mirror_health(pool: &File) -> io::Result<MirrorHealth> {
    let info = filesystem(pool, 2)?;
    let [first, second] = mirror_devices(pool, &info)?;
    let members = [DeviceHealth::read(pool, first)?, DeviceHealth::read(pool, second)?];
    let [data, metadata, system] = raid1_space(pool)?;
    Ok(MirrorHealth { filesystem_uuid: uuid(info.uuid), data, metadata, system, members })
}

pub fn require_raid1_profiles(pool: &File) -> io::Result<()> {
    raid1_space(pool).map(|_| ())
}

fn raid1_space(pool: &File) -> io::Result<[SpaceUsage; 3]> {
    space_usage(pool, [RAID1; 3])
}

fn space_usage(pool: &File, profiles: [u64; 3]) -> io::Result<[SpaceUsage; 3]> {
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

    let mut usage = [const { None }; 3];
    for entry in &spaces.entries[..spaces.count as usize] {
        if entry.flags == SPACE_GLOBAL_RESERVE {
            continue;
        }
        let index = [1, 4, 2].into_iter().zip(profiles)
            .position(|(kind, profile)| entry.flags == kind | profile)
            .ok_or_else(|| io::Error::other("Btrfs allocation profile differs from the selected role"))?;
        let selected = SpaceUsage { total: entry.total, used: entry.used };
        if entry.used > entry.total || usage[index].replace(selected).is_some() {
            return Err(io::Error::other(
                "invalid or duplicate Btrfs allocation profile",
            ));
        }
    }
    let [Some(data), Some(metadata), Some(system)] = usage else {
        return Err(io::Error::other("incomplete Btrfs space accounting"));
    };
    Ok([data, metadata, system])
}

pub fn scrub_members(pool: &File, fsid: &str, hypervisor: bool) -> io::Result<Vec<u64>> {
    let (count, profiles) = if hypervisor { (2, [RAID1; 3]) } else { (1, [0, DUP, DUP]) };
    let info = filesystem(pool, count)?;
    if uuid(info.uuid) != fsid {
        return Err(io::Error::other("Btrfs scrub mount differs from verified boot selection"));
    }
    space_usage(pool, profiles)?;
    Ok(devices(pool, &info)?.into_iter().map(|device| device.id).collect())
}

#[derive(Default)]
pub struct ScrubProgress {
    pub data_bytes: u64,
    pub metadata_bytes: u64,
    pub no_checksum_blocks: u64,
    pub corrected_errors: u64,
    pub uncorrectable_errors: u64,
    pub allocation_errors: u64,
}

pub fn scrub(pool: &File, id: u64) -> (ScrubProgress, io::Result<()>) {
    let mut args = ScrubArgs {
        id, start: 0, end: u64::MAX, flags: 0, progress: [0; 15], reserved: [0; 109],
    };
    // The ioctl has one fixed output buffer and returns partial progress on interruption.
    let result = if unsafe { ioctl(pool.as_raw_fd(), SCRUB, &mut args as *mut ScrubArgs) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    };
    let progress = ScrubProgress {
        data_bytes: args.progress[2],
        metadata_bytes: args.progress[3],
        no_checksum_blocks: args.progress[7],
        corrected_errors: args.progress[12],
        uncorrectable_errors: args.progress[11],
        allocation_errors: args.progress[10],
    };
    (progress, result)
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
