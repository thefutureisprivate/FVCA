#!/usr/bin/bash
# Add a shell-free lifecycle test to a disposable development initramfs.
set -euo pipefail
umask 077
if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo 'Run tests/nested-guest-shutdown-initrd.sh INPUT_INITRAMFS NEW_INITRAMFS [shutdown|capture|live|restore|online-trial|guest-trial|guest-trial-activation|security-deadline|guest-shutdown-refusal|withdrawn-replay]' >&2
    exit 2
fi
tests=$(cd -- "$(dirname -- "$0")" && pwd)
source=$1
output=$2
tree=$(mktemp -d)
trap 'rm -rf -- "$tree"' EXIT
fvca=usr/lib/fvca
tmpfiles=usr/lib/tmpfiles.d
mkdir -p "$tree/$fvca" "$tree/$tmpfiles"
case "${3:-shutdown}" in
    shutdown) unit=fvca-qualify-guest-shutdown.service ;;
    capture) unit=fvca-qualify-stopped-capture.service ;;
    live) unit=fvca-qualify-live-capture.service ;;
    restore) unit=fvca-qualify-guest-restore.service ;;
    online-trial) unit=fvca-qualify-online-trial.service ;;
    guest-trial) unit=fvca-qualify-guest-trial.service ;;
    guest-trial-activation) unit=fvca-qualify-guest-trial-activation.service ;;
    security-deadline) unit=fvca-qualify-security-deadline.service ;;
    withdrawn-replay) unit=fvca-qualify-withdrawn-trial.service ;;
    guest-shutdown-refusal) unit= ;;
    *) echo 'Unknown nested Guest qualification mode' >&2; exit 2 ;;
esac
rules="$tree/$tmpfiles/90-fvca-lifecycle-qualification.conf"
if [[ -n "$unit" ]]; then
    install -m644 "$tests/$unit" "$tree/$fvca/$unit"
    cat > "$rules" <<RULES
C /run/systemd/system/$unit 0644 0 0 - /$fvca/$unit
L /run/systemd/system/fvca-base.target.wants/$unit - - - - ../$unit
RULES
else
    cat > "$tree/$fvca/qualify-guest-shutdown-refusal.conf" <<'UNIT'
[Service]
ExecStart=
ExecStart=/usr/bin/qemu-ga --config=/usr/lib/fvca/qemu-guest-agent.conf --block-rpcs=guest-shutdown
UNIT
    chmod 644 "$tree/$fvca/qualify-guest-shutdown-refusal.conf"
    printf 'C /run/systemd/system/fvca-qemu-guest-agent.service.d/90-qualification.conf 0644 0 0 - /%s/qualify-guest-shutdown-refusal.conf\n' "$fvca" > "$rules"
fi
chmod 644 "$rules"
archive="$tree/initrd.cpio"
zstd -dc "$source" > "$archive"
(cd "$tree" && find "$fvca" "$tmpfiles" -type f -print0 | sort -z \
    | cpio --quiet -o -0 -A -F "$archive" -H newc --owner=0:0)
zstd --quiet -3 "$archive" -o "$output"
