#!/usr/bin/bash
# Add the read-only message check to a disposable signed Guest initramfs.
set -euo pipefail
umask 077
stage=false
trial=false
if [[ ${1:-} == --workload-trial ]]; then
    stage=true
    trial=true
    shift
elif [[ ${1:-} == --workload-stage ]]; then
    stage=true
    shift
fi
if [[ $# != 3 || -e "$2" ]]; then
    echo 'Run tests/stalwart-mail-initrd.sh [--workload-stage|--workload-trial] GUEST_INITRAMFS NEW_INITRAMFS STALWART_MAIL_LAB' >&2
    exit 2
fi
tests=$(cd -- "$(dirname -- "$0")" && pwd)
tree=$(mktemp -d)
trap 'rm -rf -- "$tree"' EXIT
conf=usr/lib/systemd/system/fvca-activate-oci-runtime.service.d
fvca=usr/lib/fvca
mkdir -p "$tree/$conf" "$tree/$fvca"
install -m600 "$3/imap.curl" "$tree/$fvca/stalwart-lab-imap.curl"
( cd "$3" && sha256sum -- mail.eml ) > "$tree/$fvca/stalwart-lab-mail.sha256"
install -m644 "$tests/stalwart-mail-fetch.service" "$tests/stalwart-mail-verify.service" "$tree/$fvca/"
cat > "$tree/$conf/90-stalwart-mail.conf" <<'UNIT'
[Service]
ExecStartPost=/usr/bin/mkdir -m 0700 -p /run/fvca/stalwart-mail
ExecStartPost=/usr/bin/cp /usr/lib/fvca/stalwart-lab-imap.curl /run/fvca/stalwart-mail/imap.curl
ExecStartPost=/usr/bin/cp /usr/lib/fvca/stalwart-lab-mail.sha256 /run/fvca/stalwart-mail/mail.sha256
ExecStartPost=/usr/bin/cp /usr/lib/fvca/stalwart-mail-fetch.service /usr/lib/fvca/stalwart-mail-verify.service /run/systemd/system/
ExecStartPost=/usr/bin/mkdir -p /run/systemd/system/fvca-base-ready.service.requires
ExecStartPost=/usr/bin/ln -s ../stalwart-mail-verify.service /run/systemd/system/fvca-base-ready.service.requires/stalwart-mail-verify.service
UNIT
files=("$conf" "$conf/90-stalwart-mail.conf" "$fvca/stalwart-lab-imap.curl"
    "$fvca/stalwart-lab-mail.sha256" "$fvca/stalwart-mail-fetch.service" "$fvca/stalwart-mail-verify.service")
if "$stage"; then
    # Apply the Guest policy to the offline fixture under its own SELinux policy.
    cat >> "$tree/$conf/90-stalwart-mail.conf" <<'UNIT'
ExecStartPost=/usr/bin/mkdir -p /run/systemd/system/fvca-stage-workload.service.d
ExecStartPost=/usr/bin/cp /usr/lib/fvca/stalwart-lab-stage-label.conf /run/systemd/system/fvca-stage-workload.service.d/
UNIT
    cat > "$tree/$fvca/stalwart-lab-stage-label.conf" <<'UNIT'
[Service]
ExecStartPre=/usr/bin/chcon -R system_u:object_r:fvca_workload_stage_t:s0 /run/fvca/guest-data/workload-updates
UNIT
    chmod 644 "$tree/$fvca/stalwart-lab-stage-label.conf"
    files+=("$fvca/stalwart-lab-stage-label.conf")
fi
if "$trial"; then
    printf '%s\n' 'ExecStart=/usr/bin/systemctl --no-block start fvca-trial-workload.service' \
        >> "$tree/$fvca/stalwart-mail-verify.service"
    cat >> "$tree/$conf/90-stalwart-mail.conf" <<'UNIT'
ExecStartPost=/usr/bin/mkdir -p /run/systemd/system/fvca-trial-workload.service.d
ExecStartPost=/usr/bin/cp /usr/lib/fvca/stalwart-lab-trial-data.conf /run/systemd/system/fvca-trial-workload.service.d/
ExecStartPost=/usr/bin/cp /usr/lib/fvca/stalwart-lab-trial-data.service /run/systemd/system/
UNIT
    cat > "$tree/$fvca/stalwart-lab-trial-data.conf" <<'UNIT'
[Service]
ExecStopPost=/usr/bin/systemctl --no-block start stalwart-lab-trial-data.service
UNIT
    cat > "$tree/$fvca/stalwart-lab-trial-data.service" <<'UNIT'
[Unit]
Description=Check a retained write after the Stalwart workload trial
After=fvca-trial-workload.service

[Service]
Type=oneshot
NoNewPrivileges=yes
MemoryDenyWriteExecute=yes
ExecStart=/usr/bin/podman --remote=false exec fvca-workload-payload /bin/sh -c 'if test -f /var/lib/stalwart/.fvca-trial-write; then echo FVCA_TRIAL_WRITE_RETAINED; fi'
StandardOutput=journal+console
StandardError=journal+console
UNIT
    chmod 644 "$tree/$fvca"/stalwart-lab-trial-data.{conf,service}
    files+=("$fvca/stalwart-lab-trial-data.conf" "$fvca/stalwart-lab-trial-data.service")
fi
chmod 644 "$tree/$conf/90-stalwart-mail.conf"
archive="$tree/initrd.cpio"
zstd -dc "$1" > "$archive"
(
    cd "$tree"
    printf '%s\0' "${files[@]}" | cpio --quiet -o -0 -A -F "$archive" -H newc --owner=0:0
)
zstd --quiet -3 "$archive" -o "$2"
