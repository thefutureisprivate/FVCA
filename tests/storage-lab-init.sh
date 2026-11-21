#!/usr/bin/bash
# Init process for the disposable provisioning and recovery guest.
set -Eeuo pipefail
shopt -s nullglob
export PATH=/usr/bin
export LC_ALL=C
trap 'printf "FVCA_STORAGE_LAB_FAILED at line %s\n" "$LINENO"; poweroff -f' ERR

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /run

# The host embeds public fixture identities and a random test-only passphrase.
. /lab-ids
. /guest-ids
marker=FVCA-PERSISTENCE-CHECK-c34ffdad562f4ddc
a=/dev/mapper/fvca-test-a
b=/dev/mapper/fvca-test-b

require_disk() {
    local name=$1
    local expected=$2
    for _ in {1..30}; do
        [[ -b "/dev/$name" ]] && break
        sleep 0.1
    done
    [[ $(<"/sys/block/$name/serial") == "$expected" ]]
}

partition_disk() {
    printf 'label: gpt\nunit: sectors\n\nstart=2048,type=%s,uuid=%s\n' "$3" "$2" | sfdisk "$1"
}

format_member() {
    local device=$1
    local identity=$2
    local mapper=$3
    local protection_options=()
    if [[ "$protection" == luks2-xts-hmac-sha256 ]]; then
        protection_options=(--cipher aes-xts-plain64 --integrity hmac-sha256 --sector-size 4096)
    fi
    partition_disk "$device" "${identity%,*}" ca7d7ccb-63ed-4c53-861c-1742536059cc
    cryptsetup luksFormat --type=luks2 --uuid="${identity#*,}" --batch-mode \
        --pbkdf=argon2id --pbkdf-memory=65536 --pbkdf-parallel=1 --iter-time=50 \
        "${protection_options[@]}" --key-file=/storage.key "${device}1"
    cryptsetup open --type=luks2 --key-file=/storage.key "${device}1" "$mapper"
}

write_marker() {
    chmod 0700 /mnt
    printf '%s\n' "$marker" > /mnt/marker
    sync
}

verify_mirror() {
    local profile
    for profile in data metadata system; do
        local allocated=(/sys/fs/btrfs/"$filesystem_uuid"/allocation/"$profile"/*/)
        if [[ ${#allocated[@]} != 1 || ${allocated[0]} != */raid1/ ]]; then
            printf 'Unexpected Btrfs %s allocations: %s\n' "$profile" "${allocated[*]}" >&2
            return 1
        fi
    done
}

report_superblock_location() {
    local mapper=$1 side=$2
    local layout start sectors target source offset tags mode count block_size interleave buffer journal rest
    layout=$(dmsetup table "${mapper}_dif")
    read -r start sectors target source offset tags mode count block_size interleave buffer journal rest <<< "$layout"
    [[ "$start" == 0 && "$target" == integrity && "$mode" == J && "$tags" == 32 ]]
    [[ "$block_size" == block_size:4096 && "$interleave" == interleave_sectors:32768 ]]
    [[ "$journal" =~ ^journal_sectors:[1-9][0-9]*$ ]]
    # The first run follows the 4 KiB integrity superblock and journal.
    # Its 32-byte tags cover 4 KiB blocks across 32768 512-byte sectors.
    local tag_area=$(( 32768 / 8 * 32 / 512 ))
    local btrfs_primary=$(( 65536 / 512 ))
    printf 'FVCA_INTEGRITY_LAB_SUPERBLOCK_%s %d\n' "$side" \
        "$((offset + 8 + ${journal#journal_sectors:} + tag_area + btrfs_primary))"
}

provision() {
    local destination
    require_disk vda fvca-lab-a
    require_disk vdb fvca-lab-b
    require_disk vdc fvca-lab-guest-seed
    format_member /dev/vda "$member_a" fvca-test-a
    format_member /dev/vdb "$member_b" fvca-test-b
    mkfs.btrfs -q -U "$filesystem_uuid" --data raid1 --metadata raid1 "$a" "$b"
    mount -t btrfs -o "nodev,nosuid,noexec,datacow,datasum,compress=no,skip_balance,device=$b" "$a" /mnt
    verify_mirror
    write_marker
    if [[ "${1:-}" == commissioning ]]; then
        mkdir -m0700 /mnt/guest-commissioning
        destination=/mnt/guest-commissioning/seed.raw
    else
        mkdir -m0700 /mnt/vms
        btrfs subvolume create /mnt/vms/service-guest
        chmod 0700 /mnt/vms/service-guest
        destination=/mnt/vms/service-guest/data.raw
    fi
    (
        umask 077
        cp --sparse=always --reflink=never /dev/vdc "$destination"
        if [[ -d /management ]]; then
            mkdir -m0700 /mnt/management
            cp /management/tls.crt /management/tls.key /mnt/management/
            echo FVCA_STORAGE_LAB_MANAGEMENT_STAGED
        fi
    )
    sync
    umount /mnt
    if [[ "$protection" == luks2-xts-hmac-sha256 ]]; then
        report_superblock_location fvca-test-a a
        report_superblock_location fvca-test-b b
    fi
    cryptsetup close fvca-test-b
    cryptsetup close fvca-test-a
    if [[ "${1:-}" == commissioning ]]; then
        echo FVCA_STORAGE_LAB_COMMISSIONING_SEED_READY
    else
        echo FVCA_STORAGE_LAB_PROVISIONED
    fi
}

plain_b() {
    require_disk vda fvca-lab-b
    protection=development-luks2 format_member /dev/vda "$member_b" fvca-test-b
    cryptsetup close fvca-test-b
    echo FVCA_STORAGE_LAB_PLAIN_MEMBER_BUILT
}

check_bad_sectors() {
    local side
    for side in a b; do
        require_disk "vd$side" "fvca-lab-$side"
        cryptsetup open --readonly --type=luks2 --key-file=/storage.key "/dev/vd${side}1" "fvca-test-$side"
        if dd if="/dev/mapper/fvca-test-$side" of=/dev/null bs=4096 skip=16 count=1 iflag=direct 2>/run/read-error; then
            return 1
        fi
        local error
        error=$(</run/read-error)
        printf '%s\n' "$error"
        [[ "$error" == *'Input/output error'* || "$error" == *'Invalid or incomplete multibyte or wide character'* ]]
        [[ "$error" == *'0+0 records in'* && "$error" == *'0+0 records out'* ]]
        cryptsetup close "fvca-test-$side"
    done
    echo FVCA_STORAGE_LAB_BAD_SECTORS_REJECTED
}

crash_check() {
    require_disk vda fvca-lab-a
    require_disk vdb fvca-lab-b
    cryptsetup open --type=luks2 --key-file=/storage.key /dev/vda1 fvca-test-a
    cryptsetup open --type=luks2 --key-file=/storage.key /dev/vdb1 fvca-test-b
    mount -t btrfs -o "nodev,nosuid,noexec,device=$b" "$a" /mnt
    verify_mirror
    [[ $(</mnt/marker) == "$marker" ]]
    if [[ "$1" == write ]]; then
        printf '%s\n' "$marker" > /mnt/flushed-before-crash
        sync -f /mnt
        dd if=/dev/zero of=/mnt/interrupted bs=1M count=32 oflag=direct status=none
        echo FVCA_STORAGE_LAB_UNFLUSHED_WRITE
        while :; do
            dd if=/dev/zero of=/mnt/interrupted bs=1M count=32 oflag=direct status=none
        done
    fi
    [[ $(</mnt/flushed-before-crash) == "$marker" ]]
    btrfs scrub start -B /mnt
    umount /mnt
    cryptsetup close fvca-test-b
    cryptsetup close fvca-test-a
    echo FVCA_STORAGE_LAB_CRASH_RECOVERED
}

recover() {
    local member=$1
    require_disk vda "fvca-lab-$member"
    printf '%s' wrong-lab-passphrase > /run/wrong
    if cryptsetup open --type=luks2 --test-passphrase --key-file=/run/wrong /dev/vda1; then
        return 1
    fi
    [[ ! -e "$a" ]]
    cryptsetup open --readonly --type=luks2 --key-file=/storage.key /dev/vda1 fvca-test-a
    mount -t btrfs -o ro,degraded,rescue=nologreplay,nodev,nosuid,noexec "$a" /mnt
    [[ $(</mnt/marker) == "$marker" ]]
    verify_mirror
    umount /mnt
    cryptsetup close fvca-test-a
    printf 'FVCA_STORAGE_DEGRADED_READ_OK %s\n' "$member"
}

replace() {
    recover a
    require_disk vdb fvca-lab-replacement
    format_member /dev/vdb "$replacement_b" fvca-test-b
    cryptsetup open --type=luks2 --key-file=/storage.key /dev/vda1 fvca-test-a
    mount -t btrfs -o rw,degraded,nodev,nosuid,noexec "$a" /mnt
    # The fixture creates the first mapping as device 1 and the second as 2.
    btrfs replace start -B 2 "$b" /mnt
    umount /mnt
    mount -t btrfs -o "nodev,nosuid,noexec,device=$b" "$a" /mnt
    # A writable degraded mount can allocate SINGLE chunks even without an
    # application writer. Restore full redundancy before admitting the pool.
    btrfs balance start -dconvert=raid1,soft -mconvert=raid1,soft /mnt
    umount /mnt
    mount -t btrfs -o "nodev,nosuid,noexec,device=$b" "$a" /mnt
    [[ $(</mnt/marker) == "$marker" ]]
    verify_mirror
    btrfs scrub start -B /mnt
    umount /mnt
    cryptsetup close fvca-test-b
    cryptsetup close fvca-test-a
    echo FVCA_STORAGE_REBUILD_OK
}

provision_guest() {
    require_disk vda fvca-lab-guest
    partition_disk /dev/vda "$guest_partition" 0fc63daf-8483-4772-8e79-3d69d8477de4
    mkfs.btrfs -q -U "$guest_filesystem" --data single --metadata "$1" /dev/vda1
    mount -t btrfs -o nodev,nosuid,noexec /dev/vda1 /mnt
    write_marker
    umount /mnt
    echo FVCA_GUEST_BTRFS_LAB_PROVISIONED
}

provision_nocow() {
    require_disk vda fvca-lab-a
    require_disk vdb fvca-lab-b
    cryptsetup open --type=luks2 --key-file=/storage.key /dev/vda1 fvca-test-a
    cryptsetup open --type=luks2 --key-file=/storage.key /dev/vdb1 fvca-test-b
    mount -t btrfs -o "nodev,nosuid,noexec,device=$b" "$a" /mnt
    [[ $(</mnt/marker) == "$marker" ]]
    local disk=/mnt/vms/service-guest/data.raw
    mv "$disk" /mnt/original.raw
    (
        umask 077
        : > "$disk"
        chattr +C "$disk"
        cp --sparse=always --reflink=never /mnt/original.raw "$disk"
    )
    rm /mnt/original.raw
    sync
    umount /mnt
    cryptsetup close fvca-test-b
    cryptsetup close fvca-test-a
    echo FVCA_STORAGE_LAB_NOCOW_PROVISIONED
}

cmdline=$(</proc/cmdline)
case "$cmdline" in
    *' fvca.lab=guest') provision_guest dup ;;
    *' fvca.lab=guest-wrong-profile') provision_guest single ;;
    *' fvca.lab=provision') modprobe dm-crypt; provision ;;
    *' fvca.lab=commissioning') modprobe dm-crypt; provision commissioning ;;
    *' fvca.lab=plain-b') modprobe dm-crypt; plain_b ;;
    *' fvca.lab=authenticated-read-error') modprobe dm-crypt; check_bad_sectors ;;
    *' fvca.lab=crash-write') modprobe dm-crypt; crash_check write ;;
    *' fvca.lab=crash-recover') modprobe dm-crypt; crash_check recover ;;
    *' fvca.lab=nocow') modprobe dm-crypt; provision_nocow ;;
    *' fvca.lab=replace') modprobe dm-crypt; replace ;;
    *' fvca.lab=verify') modprobe dm-crypt; recover replacement ;;
    *) false ;;
esac

sync
poweroff -f
