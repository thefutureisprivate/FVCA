#!/usr/bin/bash
# Init process for the disposable provisioning and recovery guest.
set -euo pipefail
export PATH=/usr/bin
trap 'printf "FVCA_STORAGE_LAB_FAILED at line %s\n" "$LINENO"; poweroff -f' ERR

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /run
modprobe raid1
modprobe dm-crypt

# The host embeds the public test UUIDs and a random test-only passphrase.
. /lab-ids
marker=FVCA-PERSISTENCE-CHECK-c34ffdad562f4ddc
array=/dev/md0
volume=/dev/mapper/fvca-test

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
    printf 'label: gpt\nunit: sectors\n\nstart=2048,type=A19D880F-05FC-4D3B-A006-743F0F84911E,uuid=%s\n' \
        "$2" | sfdisk "$1"
}

provision() {
    require_disk vda fvca-lab-a
    require_disk vdb fvca-lab-b
    partition_disk /dev/vda "$member_a"
    partition_disk /dev/vdb "$member_b"
    mdadm --create "$array" --metadata=1.2 --uuid="$raid" --level=1 --raid-devices=2 \
        --bitmap=internal --run /dev/vda1 /dev/vdb1
    mdadm --wait "$array"
    cryptsetup luksFormat --type=luks2 --uuid="$luks" --batch-mode \
        --pbkdf=argon2id --pbkdf-memory=65536 --pbkdf-parallel=1 --iter-time=50 \
        --key-file=/storage.key "$array"
    cryptsetup open --type=luks2 --key-file=/storage.key "$array" fvca-test
    mkfs.ext4 -q -U "$filesystem" "$volume"
    mount -t ext4 -o nodev,nosuid,noexec "$volume" /mnt
    chmod 0700 /mnt
    printf '%s\n' "$marker" > /mnt/marker
    sync
    umount /mnt
    cryptsetup close fvca-test
    echo FVCA_STORAGE_LAB_PROVISIONED
}

recover() {
    local member=$1
    require_disk vda "fvca-lab-$member"
    mdadm --assemble --config=/dev/null --uuid="$raid" --readonly --run "$array" /dev/vda1
    [[ $(</sys/block/md0/md/degraded) == 1 ]]
    printf '%s' wrong-lab-passphrase > /run/wrong
    if cryptsetup open --type=luks2 --test-passphrase --key-file=/run/wrong "$array"; then
        return 1
    fi
    [[ ! -e "$volume" ]]
    cryptsetup open --readonly --type=luks2 --key-file=/storage.key "$array" fvca-test
    mount -t ext4 -o ro,noload,nodev,nosuid,noexec "$volume" /mnt
    [[ $(</mnt/marker) == "$marker" ]]
    umount /mnt
    cryptsetup close fvca-test
    printf 'FVCA_STORAGE_DEGRADED_READ_OK %s\n' "$member"
}

case "$(< /proc/cmdline)" in
    *' fvca.lab=provision') provision ;;
    *' fvca.lab=replace')
        recover a
        require_disk vdb fvca-lab-replacement
        partition_disk /dev/vdb "$member_b"
        mdadm --readwrite "$array"
        mdadm --add "$array" /dev/vdb1
        mdadm --wait "$array"
        [[ $(</sys/block/md0/md/degraded) == 0 ]]
        echo FVCA_STORAGE_REBUILD_OK
        ;;
    *' fvca.lab=verify') recover b ;;
    *) false ;;
esac

mdadm --stop "$array"
sync
poweroff -f
