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
tail -n +3 "$tests/host-storage.conf" > "$root/lab-ids"
printf '%s' "$(openssl rand -hex 32)" > "$output/storage.key"
install -m400 "$output/storage.key" "$root/storage.key"

for name in bash chmod cryptsetup mdadm mkfs.ext4 modprobe mount poweroff sfdisk sleep sync umount; do
    binary=$(realpath "$(command -v "$name")")
    install -m755 "$binary" "$root/usr/bin/$name"
    while IFS= read -r dependency; do
        install -m755 "$dependency" "$root/usr/lib64/${dependency##*/}"
    done < <(ldd "$binary" | awk '/=> \// {print $3} /^[[:space:]]*\/.* \(/ {print $1}')
done
for module in raid1 dm_crypt; do
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

truncate -s 256M "$output/member-a.raw" "$output/member-b.raw" "$output/replacement.raw"
boot provision \
    -drive "if=none,id=a,format=raw,file=$output/member-a.raw" -device virtio-blk-pci,drive=a,serial=fvca-lab-a \
    -drive "if=none,id=b,format=raw,file=$output/member-b.raw" -device virtio-blk-pci,drive=b,serial=fvca-lab-b
grep -q FVCA_STORAGE_LAB_PROVISIONED "$output/provision.log"

cp --reflink=auto --sparse=always "$output/member-a.raw" "$output/surviving-member.raw"
boot replace \
    -drive "if=none,id=a,format=raw,file=$output/surviving-member.raw" -device virtio-blk-pci,drive=a,serial=fvca-lab-a \
    -drive "if=none,id=b,format=raw,file=$output/replacement.raw" -device virtio-blk-pci,drive=b,serial=fvca-lab-replacement
grep -q 'FVCA_STORAGE_DEGRADED_READ_OK a' "$output/replace.log"
grep -q FVCA_STORAGE_REBUILD_OK "$output/replace.log"

boot verify \
    -drive "if=none,id=b,format=raw,file=$output/replacement.raw" -device virtio-blk-pci,drive=b,serial=fvca-lab-b
grep -q 'FVCA_STORAGE_DEGRADED_READ_OK b' "$output/verify.log"

if LC_ALL=C grep -aFq 'FVCA-PERSISTENCE-CHECK-c34ffdad562f4ddc' \
    "$output/member-a.raw" "$output/member-b.raw" "$output/replacement.raw"; then
    echo 'Plaintext fixture found on an encrypted member' >&2
    exit 1
fi
printf 'Storage fixture passed provisioning, degraded recovery, and replacement in %s\n' "$output"
