#!/usr/bin/bash
# Add observation units and a shorter refresh timer to a disposable Guest initramfs.
set -euo pipefail
umask 077
if [[ $# != 2 || -e "$2" ]]; then
    echo 'Run tests/workload-permit-initrd.sh GUEST_INITRAMFS NEW_INITRAMFS' >&2
    exit 2
fi

tree=$(mktemp -d)
trap 'rm -rf -- "$tree"' EXIT
initrd_dropin=usr/lib/systemd/system/fvca-activate-oci-runtime.service.d
fixture=usr/lib/fvca/permit-lab
mkdir -p "$tree/$initrd_dropin" "$tree/$fixture"
cat > "$tree/$initrd_dropin/90-permit-lab.conf" <<'UNIT'
[Service]
ExecStartPost=/usr/bin/systemd-tmpfiles --create /usr/lib/fvca/permit-lab/tmpfiles.conf
StandardError=journal+console
UNIT
cat > "$tree/$fixture/tmpfiles.conf" <<'UNIT'
d /run/systemd/system/fvca-workload-start.service.wants 0755 root root -
d /run/systemd/system/fvca-workload-update.timer.d 0755 root root -
d /run/systemd/journald.conf.d 0755 root root -
C /run/systemd/journald.conf.d/90-permit-lab.conf 0644 root root - /usr/lib/fvca/permit-lab/90-journal.conf
C /run/systemd/system/fvca-permit-lab-alive.timer 0644 root root - /usr/lib/fvca/permit-lab/fvca-permit-lab-alive.timer
C /run/systemd/system/fvca-permit-lab-alive.service 0644 root root - /usr/lib/fvca/permit-lab/fvca-permit-lab-alive.service
C /run/systemd/system/fvca-permit-lab-stopped.timer 0644 root root - /usr/lib/fvca/permit-lab/fvca-permit-lab-stopped.timer
C /run/systemd/system/fvca-permit-lab-stopped.service 0644 root root - /usr/lib/fvca/permit-lab/fvca-permit-lab-stopped.service
C /run/systemd/system/fvca-workload-update.timer.d/90-refresh.conf 0644 root root - /usr/lib/fvca/permit-lab/90-refresh.conf
L /run/systemd/system/fvca-workload-start.service.wants/fvca-permit-lab-alive.timer - - - - ../fvca-permit-lab-alive.timer
L /run/systemd/system/fvca-workload-start.service.wants/fvca-permit-lab-stopped.timer - - - - ../fvca-permit-lab-stopped.timer
UNIT
cat > "$tree/$fixture/90-journal.conf" <<'UNIT'
[Journal]
ForwardToConsole=yes
MaxLevelConsole=info
TTYPath=/dev/console
UNIT
cat > "$tree/$fixture/90-refresh.conf" <<'UNIT'
[Timer]
OnActiveSec=
OnActiveSec=70s
RandomizedDelaySec=0
AccuracySec=1s
UNIT
cat > "$tree/$fixture/fvca-permit-lab-alive.timer" <<'UNIT'
[Timer]
OnActiveSec=53s
AccuracySec=1s
UNIT
cat > "$tree/$fixture/fvca-permit-lab-alive.service" <<'UNIT'
[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl is-active --quiet fvca-workload-payload.service
ExecStart=/usr/bin/echo FVCA_PERMIT_LAB_ACTIVE_AFTER_EXPIRY
StandardOutput=journal+console
UNIT
cat > "$tree/$fixture/fvca-permit-lab-stopped.timer" <<'UNIT'
[Timer]
OnActiveSec=122s
AccuracySec=1s
UNIT
cat > "$tree/$fixture/fvca-permit-lab-stopped.service" <<'UNIT'
[Service]
Type=oneshot
ExecStart=/usr/bin/echo FVCA_PERMIT_LAB_CHECK_STOPPED
ExecStart=/usr/bin/systemctl show --value --property=ActiveState fvca-workload-payload.service
ExecStart=/usr/bin/echo FVCA_PERMIT_LAB_RESTART_ATTEMPT
ExecStart=-/usr/bin/systemctl start fvca-workload-payload.service
ExecStart=/usr/bin/systemctl show --value --property=ActiveState fvca-workload-payload.service
ExecStart=/usr/bin/echo FVCA_PERMIT_LAB_RESTART_CHECKED
StandardOutput=journal+console
UNIT
chmod 755 "$tree/$initrd_dropin" "$tree/$fixture"
chmod 644 "$tree/$initrd_dropin/90-permit-lab.conf" "$tree/$fixture/"*
archive="$tree/initrd.cpio"
zstd -dc -- "$1" > "$archive"
(
    cd "$tree"
    printf '%s\0' "$initrd_dropin" "$initrd_dropin/90-permit-lab.conf" "$fixture" "$fixture/"* |
        cpio --quiet -o -0 -A -F "$archive" -H newc --owner=0:0
)
zstd --quiet -3 "$archive" -o "$2"
