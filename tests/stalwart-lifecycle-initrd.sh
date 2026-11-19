#!/usr/bin/bash
# Extend a disposable development initramfs with shell-free lifecycle checks.
set -euo pipefail
umask 077
if [[ $# != 2 ]]; then
    echo 'Run tests/stalwart-lifecycle-initrd.sh GUEST_INITRAMFS NEW_INITRAMFS' >&2
    exit 2
fi
tests=$(cd -- "$(dirname -- "$0")" && pwd)
source=$1
output=$2
tree=$(mktemp -d)
trap 'rm -rf -- "$tree"' EXIT
conf=usr/lib/systemd/system/fvca-activate-oci-runtime.service.d
fvca=usr/lib/fvca
mkdir -p "$tree/$conf" "$tree/$fvca"
install -m644 "$tests/stalwart-lifecycle.service" "$tree/$fvca/stalwart-lifecycle.service"
cat > "$tree/$conf/90-workload-lifecycle.conf" <<'UNIT'
[Service]
ExecStartPost=/usr/bin/cp /usr/lib/fvca/stalwart-lifecycle.service /run/systemd/system/stalwart-lifecycle.service
ExecStartPost=/usr/bin/ln -s ../stalwart-lifecycle.service /run/systemd/system/fvca-base-ready.service.requires/stalwart-lifecycle.service
UNIT
chmod 644 "$tree/$conf/90-workload-lifecycle.conf"
archive="$tree/initrd.cpio"
zstd -dc "$source" > "$archive"
(cd "$tree" && printf '%s\0' "$conf" "$conf/90-workload-lifecycle.conf" "$fvca/stalwart-lifecycle.service" \
    | cpio --quiet -o -0 -A -F "$archive" -H newc --owner=0:0)
zstd --quiet -3 "$archive" -o "$output"
