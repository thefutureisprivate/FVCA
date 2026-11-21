#!/usr/bin/bash
# Provision and recover fresh file-backed disks in an isolated KVM guest.
set -euo pipefail
umask 077

protection=development-luks2
if [[ "${1:-}" == --authenticated ]]; then
    protection=luks2-xts-hmac-sha256
    shift
fi
if [[ $# -lt 1 || $# -gt 3 || "$1" == *,* ]]; then
    echo 'Usage: tests/storage-lab.sh [--authenticated] NEW_OUTPUT_DIRECTORY [GUEST_SEED_DISK [MIRROR_MEMBER_BYTES]]' >&2
    exit 2
fi
guest_seed=
member_size=$((384 * 1024 * 1024))
if [[ $# -ge 2 ]]; then
    guest_seed=$(realpath -e -- "$2")
    if [[ ! -f "$guest_seed" || "$guest_seed" == *,* ]]; then
        echo 'The Guest seed must be a regular disk image with a comma-free path' >&2
        exit 2
    fi
    seed_bytes=$(stat -c %s -- "$guest_seed")
    if (( seed_bytes == 0 || seed_bytes % 512 != 0 )); then
        echo 'The Guest seed must be a nonempty, sector-aligned raw image' >&2
        exit 2
    fi
    # Leave the same Btrfs repair headroom as the empty fixture.
    member_size=$((seed_bytes + member_size))
fi
member_alignment=512
if [[ "$protection" == luks2-xts-hmac-sha256 ]]; then
    # Allow for the LUKS header, integrity journal and tags on each member.
    member_alignment=4096
    member_size=$(( (member_size + 64 * 1024 * 1024 + (member_size + 126) / 127 + 4095) / 4096 * 4096 ))
fi
if [[ $# == 3 ]]; then
    if [[ ! "$3" =~ ^[1-9][0-9]{0,11}$ ]] || (( $3 < member_size || $3 % member_alignment != 0 )); then
        echo 'Mirror member size must be sector-aligned bytes with enough headroom for the Guest seed' >&2
        exit 2
    fi
    member_size=$3
fi
tests=$(cd -- "$(dirname -- "$0")" && pwd)
mkdir -- "$1"
output=$(realpath -- "$1")
if [[ "$output" == *,* ]]; then
    echo 'The resolved output path must be comma-free' >&2
    exit 2
fi
kernel=$(uname -r)
modules="/usr/lib/modules/$kernel"
root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT

mkdir -p "$root"/{usr/{bin,lib64},proc,sys,dev,run,mnt,etc}
mkdir -p "$root$modules"
ln -s usr/bin "$root/bin"
ln -s usr/lib "$root/lib"
ln -s usr/lib64 "$root/lib64"
install -m755 "$tests/storage-lab-init.sh" "$root/init"
replacement=6dfe4168-65d6-4500-99f7-448214356652,02fe6c37-70be-4215-9872-4a41221fca18
sed "s/^protection=.*/protection=$protection/" "$tests/host-storage.conf" > "$output/host-storage.conf"
tail -n +3 "$output/host-storage.conf" > "$root/lab-ids"
printf 'replacement_b=%s\n' "$replacement" >> "$root/lab-ids"
sed "s/^member_b=.*/member_b=$replacement/" "$output/host-storage.conf" > "$output/replacement-storage.conf"
sed -n -e 's/^partition=/guest_partition=/p' -e 's/^filesystem_uuid=/guest_filesystem=/p' \
    "$tests/guest-storage.conf" > "$root/guest-ids"
printf '%s' "$(openssl rand -hex 32)" > "$output/storage.key"
install -m400 "$output/storage.key" "$root/storage.key"

binaries=(bash btrfs chattr chmod cp cryptsetup mkdir mkfs.btrfs modprobe mount mv poweroff rm sfdisk sleep sync umount)
modules_to_copy=(dm_crypt)
if [[ "$protection" == luks2-xts-hmac-sha256 ]]; then
    binaries+=(dd dmsetup)
    modules_to_copy+=(dm_integrity authenc hmac xts)
fi
for name in "${binaries[@]}"; do
    binary=$(realpath "$(command -v "$name")")
    install -m755 "$binary" "$root/usr/bin/$name"
    while IFS= read -r dependency; do
        install -m755 "$dependency" "$root/usr/lib64/${dependency##*/}"
    done < <(ldd "$binary" | awk '/=> \// {print $3} /^[[:space:]]*\/.* \(/ {print $1}')
done
for module in "${modules_to_copy[@]}"; do
    while read -r action path; do
        if [[ "$action" == insmod ]]; then
            install -D -m644 "$path" "$root$modules/${path##*/modules/$kernel/}"
        fi
    done < <(modprobe --show-depends "$module")
done
cp "$modules"/modules.* "$root$modules/"
(
    cd "$root"
    find . -print0 | cpio --quiet -0 -o -H newc --owner=0:0 | gzip -1
) > "$output/lab.cpio.gz"
rm -rf -- "$root"
trap - EXIT

boot() {
    local mode=$1
    shift
    local command=(qemu-system-x86_64 -machine q35 -accel kvm -cpu host -m 1024 -smp 2
        -display none -monitor none -no-reboot -nic none -serial "file:$output/$mode.log" \
        -kernel "$modules/vmlinuz" -initrd "$output/lab.cpio.gz" \
        -append "rdinit=/init console=ttyS0 quiet fvca.lab=$mode" "$@")
    if [[ "$mode" == crash-write ]]; then
        "${command[@]}" &
        local guest=$! observed=no
        for _ in {1..450}; do
            if [[ -f "$output/$mode.log" ]] && grep -aq FVCA_STORAGE_LAB_UNFLUSHED_WRITE "$output/$mode.log"; then
                observed=yes
                break
            fi
            kill -0 "$guest" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "$guest" 2>/dev/null || true
        local status=0
        wait "$guest" 2>/dev/null || status=$?
        [[ "$observed" == yes && "$status" == 137 ]]
    else
        timeout 60s "${command[@]}"
    fi
    if grep -q FVCA_STORAGE_LAB_FAILED "$output/$mode.log"; then
        return 1
    fi
}

truncate -s "$member_size" "$output/member-a.raw" "$output/member-b.raw" "$output/replacement.raw"
truncate -s 384M "$output/guest-data.raw" "$output/guest-wrong-profile.raw"
boot guest \
    -drive "if=none,id=guest,format=raw,file=$output/guest-data.raw" -device virtio-blk-pci,drive=guest,serial=fvca-lab-guest
grep -q FVCA_GUEST_BTRFS_LAB_PROVISIONED "$output/guest.log"
boot guest-wrong-profile \
    -drive "if=none,id=guest,format=raw,file=$output/guest-wrong-profile.raw" -device virtio-blk-pci,drive=guest,serial=fvca-lab-guest
grep -q FVCA_GUEST_BTRFS_LAB_PROVISIONED "$output/guest-wrong-profile.log"

boot provision \
    -drive "if=none,id=a,format=raw,file=$output/member-a.raw" -device virtio-blk-pci,drive=a,serial=fvca-lab-a \
    -drive "if=none,id=b,format=raw,file=$output/member-b.raw" -device virtio-blk-pci,drive=b,serial=fvca-lab-b \
    -drive "if=none,id=guest,format=raw,readonly=on,file=${guest_seed:-$output/guest-data.raw}" -device virtio-blk-pci,drive=guest,serial=fvca-lab-guest-seed
grep -q FVCA_STORAGE_LAB_PROVISIONED "$output/provision.log"

if [[ "$protection" == luks2-xts-hmac-sha256 ]]; then
    truncate -s "$member_size" "$output/plain-member-b.raw"
    boot plain-b \
        -drive "if=none,id=b,format=raw,file=$output/plain-member-b.raw" -device virtio-blk-pci,drive=b,serial=fvca-lab-b
    grep -q FVCA_STORAGE_LAB_PLAIN_MEMBER_BUILT "$output/plain-b.log"

    python3 - "$output" <<'PY'
import json
from pathlib import Path
import re
import subprocess
import sys

root = Path(sys.argv[1])
provision = (root / "provision.log").read_text()
for side in ("a", "b"):
    original = root / f"member-{side}.raw"
    damaged = root / f"damaged-member-{side}.raw"
    subprocess.run(["cp", "--reflink=auto", "--sparse=always", "--", original, damaged], check=True)
    partition, = json.loads(subprocess.check_output(["sfdisk", "--json", original]))["partitiontable"]["partitions"]
    relative = re.search(rf"^FVCA_INTEGRITY_LAB_SUPERBLOCK_{side} ([0-9]+)$", provision, re.M)
    if relative is None:
        raise ValueError("missing authenticated Btrfs superblock placement evidence")
    sector = int(relative[1])
    if not 0 < sector < partition["size"] - 8:
        raise ValueError("Btrfs superblock is outside the fixture partition")
    with damaged.open("r+b") as disk:
        disk.seek((partition["start"] + sector) * 512)
        original_byte = disk.read(1)[0]
        disk.seek(-1, 1)
        disk.write(bytes([original_byte ^ 1]))
PY
    boot authenticated-read-error \
        -drive "if=none,id=a,format=raw,file=$output/damaged-member-a.raw" -device virtio-blk-pci,drive=a,serial=fvca-lab-a \
        -drive "if=none,id=b,format=raw,file=$output/damaged-member-b.raw" -device virtio-blk-pci,drive=b,serial=fvca-lab-b
    grep -q FVCA_STORAGE_LAB_BAD_SECTORS_REJECTED "$output/authenticated-read-error.log"

    for side in a b; do
        cp --reflink=auto --sparse=always "$output/member-$side.raw" "$output/crash-member-$side.raw"
    done
    crash_disks=(
        -drive "if=none,id=a,format=raw,cache=none,file=$output/crash-member-a.raw" -device virtio-blk-pci,drive=a,serial=fvca-lab-a
        -drive "if=none,id=b,format=raw,cache=none,file=$output/crash-member-b.raw" -device virtio-blk-pci,drive=b,serial=fvca-lab-b
    )
    boot crash-write "${crash_disks[@]}"
    boot crash-recover "${crash_disks[@]}"
    grep -q FVCA_STORAGE_LAB_CRASH_RECOVERED "$output/crash-recover.log"
fi

for member in a b; do
    cp --reflink=auto --sparse=always "$output/member-$member.raw" "$output/nocow-$member.raw"
done
boot nocow \
    -drive "if=none,id=a,format=raw,file=$output/nocow-a.raw" -device virtio-blk-pci,drive=a,serial=fvca-lab-a \
    -drive "if=none,id=b,format=raw,file=$output/nocow-b.raw" -device virtio-blk-pci,drive=b,serial=fvca-lab-b
grep -q FVCA_STORAGE_LAB_NOCOW_PROVISIONED "$output/nocow.log"

cp --reflink=auto --sparse=always "$output/member-a.raw" "$output/surviving-member.raw"
boot replace \
    -drive "if=none,id=a,format=raw,file=$output/surviving-member.raw" -device virtio-blk-pci,drive=a,serial=fvca-lab-a \
    -drive "if=none,id=b,format=raw,file=$output/replacement.raw" -device virtio-blk-pci,drive=b,serial=fvca-lab-replacement
grep -q 'FVCA_STORAGE_DEGRADED_READ_OK a' "$output/replace.log"
grep -q FVCA_STORAGE_REBUILD_OK "$output/replace.log"

boot verify \
    -drive "if=none,id=b,format=raw,file=$output/replacement.raw" -device virtio-blk-pci,drive=b,serial=fvca-lab-replacement
grep -q 'FVCA_STORAGE_DEGRADED_READ_OK replacement' "$output/verify.log"

# Present the old GPT UUID over a different LUKS2 volume to test the two
# independent boundaries in the signed member identity.
cp --reflink=auto --sparse=always "$output/replacement.raw" "$output/wrong-luks.raw"
original_b=$(sed -n 's/^member_b=\([^,]*\),.*$/\1/p' "$tests/host-storage.conf")
sfdisk --part-uuid "$output/wrong-luks.raw" 1 "$original_b" >/dev/null

if LC_ALL=C grep -aFq 'FVCA-PERSISTENCE-CHECK-c34ffdad562f4ddc' \
    "$output/member-a.raw" "$output/member-b.raw" "$output/replacement.raw"; then
    echo 'Plaintext fixture found on an encrypted member' >&2
    exit 1
fi
printf 'Storage fixture passed provisioning, degraded recovery, and replacement in %s\n' "$output"
