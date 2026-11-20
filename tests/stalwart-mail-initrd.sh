#!/usr/bin/bash
# Add the read-only message check to a disposable signed Guest initramfs.
set -euo pipefail
umask 077
if [[ $# != 3 || -e "$2" ]]; then
    echo 'Run tests/stalwart-mail-initrd.sh GUEST_INITRAMFS NEW_INITRAMFS STALWART_MAIL_LAB' >&2
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
chmod 644 "$tree/$conf/90-stalwart-mail.conf"
archive="$tree/initrd.cpio"
zstd -dc "$1" > "$archive"
(
    cd "$tree"
    printf '%s\0' "$conf" "$conf/90-stalwart-mail.conf" "$fvca/stalwart-lab-imap.curl" \
        "$fvca/stalwart-lab-mail.sha256" "$fvca/stalwart-mail-fetch.service" "$fvca/stalwart-mail-verify.service" \
        | cpio --quiet -o -0 -A -F "$archive" -H newc --owner=0:0
)
zstd --quiet -3 "$archive" -o "$2"
