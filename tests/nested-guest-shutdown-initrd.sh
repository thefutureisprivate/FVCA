#!/usr/bin/bash
# Add a shell-free Guest lifecycle test to a disposable development Hypervisor initramfs.
set -euo pipefail
umask 077
if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo 'Run tests/nested-guest-shutdown-initrd.sh HYPERVISOR_INITRAMFS NEW_INITRAMFS [shutdown|capture|live]' >&2
    exit 2
fi
tests=$(cd -- "$(dirname -- "$0")" && pwd)
source=$1
output=$2
tree=$(mktemp -d)
trap 'rm -rf -- "$tree"' EXIT
conf=usr/lib/systemd/system/fvca-activate-runtime.service.d
fvca=usr/lib/fvca
case "${3:-shutdown}" in
    shutdown) unit=fvca-qualify-guest-shutdown.service ;;
    capture) unit=fvca-qualify-stopped-capture.service ;;
    live) unit=fvca-qualify-live-capture.service ;;
    *) echo 'Unknown nested Guest qualification mode' >&2; exit 2 ;;
esac
mkdir -p "$tree/$conf" "$tree/$fvca"
install -m644 "$tests/$unit" "$tree/$fvca/$unit"
cat > "$tree/$conf/90-guest-shutdown.conf" <<UNIT
[Service]
ExecStartPost=/usr/bin/cp /usr/lib/fvca/$unit /run/systemd/system/$unit
ExecStartPost=/usr/bin/mkdir -p /run/systemd/system/fvca-base.target.wants
ExecStartPost=/usr/bin/ln -s ../$unit /run/systemd/system/fvca-base.target.wants/$unit
UNIT
chmod 644 "$tree/$conf/90-guest-shutdown.conf"
archive="$tree/initrd.cpio"
zstd -dc "$source" > "$archive"
(cd "$tree" && printf '%s\0' "$conf" "$conf/90-guest-shutdown.conf" "$fvca/$unit" \
    | cpio --quiet -o -0 -A -F "$archive" -H newc --owner=0:0)
zstd --quiet -3 "$archive" -o "$output"
