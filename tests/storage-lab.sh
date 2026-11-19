#!/usr/bin/bash
# Provision and recover fresh file-backed disks in an isolated KVM guest.
set -euo pipefail
umask 077

if [[ $# != 1 || "$1" == *,* ]]; then
    echo 'Usage: tests/storage-lab.sh NEW_OUTPUT_DIRECTORY' >&2
    exit 2
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
tail -n +3 "$tests/host-storage.conf" > "$root/lab-ids"
printf 'replacement_b=%s\n' "$replacement" >> "$root/lab-ids"
sed "s/^member_b=.*/member_b=$replacement/" "$tests/host-storage.conf" > "$output/replacement-storage.conf"
sed -n -e 's/^partition=/guest_partition=/p' -e 's/^filesystem_uuid=/guest_filesystem=/p' \
    "$tests/guest-storage.conf" > "$root/guest-ids"
printf '%s' "$(openssl rand -hex 32)" > "$output/storage.key"
install -m400 "$output/storage.key" "$root/storage.key"

for name in bash btrfs chattr chmod cp cryptsetup mkdir mkfs.btrfs modprobe mount mv poweroff rm sfdisk sleep sync umount; do
    binary=$(realpath "$(command -v "$name")")
    install -m755 "$binary" "$root/usr/bin/$name"
    while IFS= read -r dependency; do
        install -m755 "$dependency" "$root/usr/lib64/${dependency##*/}"
    done < <(ldd "$binary" | awk '/=> \// {print $3} /^[[:space:]]*\/.* \(/ {print $1}')
done
for module in dm_crypt; do
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

boot() {
    local mode=$1
    shift
    timeout 60s qemu-system-x86_64 -machine q35 -accel kvm -cpu host -m 1024 -smp 2 \
        -display none -monitor none -no-reboot -nic none -serial "file:$output/$mode.log" \
        -kernel "$modules/vmlinuz" -initrd "$output/lab.cpio.gz" \
        -append "rdinit=/init console=ttyS0 quiet fvca.lab=$mode" "$@"
    if grep -q FVCA_STORAGE_LAB_FAILED "$output/$mode.log"; then
        return 1
    fi
}

truncate -s 384M "$output/member-a.raw" "$output/member-b.raw" "$output/replacement.raw" \
    "$output/guest-data.raw" "$output/guest-wrong-profile.raw"
boot guest \
    -drive "if=none,id=guest,format=raw,file=$output/guest-data.raw" -device virtio-blk-pci,drive=guest,serial=fvca-lab-guest
grep -q FVCA_GUEST_BTRFS_LAB_PROVISIONED "$output/guest.log"
boot guest-wrong-profile \
    -drive "if=none,id=guest,format=raw,file=$output/guest-wrong-profile.raw" -device virtio-blk-pci,drive=guest,serial=fvca-lab-guest
grep -q FVCA_GUEST_BTRFS_LAB_PROVISIONED "$output/guest-wrong-profile.log"

boot provision \
    -drive "if=none,id=a,format=raw,file=$output/member-a.raw" -device virtio-blk-pci,drive=a,serial=fvca-lab-a \
    -drive "if=none,id=b,format=raw,file=$output/member-b.raw" -device virtio-blk-pci,drive=b,serial=fvca-lab-b \
    -drive "if=none,id=guest,format=raw,readonly=on,file=$output/guest-data.raw" -device virtio-blk-pci,drive=guest,serial=fvca-lab-guest-seed
grep -q FVCA_STORAGE_LAB_PROVISIONED "$output/provision.log"

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
