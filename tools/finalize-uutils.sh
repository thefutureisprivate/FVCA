#!/usr/bin/bash
set -euo pipefail

staging="$BUILDROOT/usr/lib/fvca/uutils"
while IFS= read -r path; do
    [[ "$path" =~ ^/usr/(s?bin|libexec/coreutils)/[^/]+$ ]]
    [[ "${path##*/}" != . && "${path##*/}" != .. ]]
    rm -f -- "$BUILDROOT$path"
done < "$staging/gnu-paths"

mv -- "$staging/echo" "$staging/sha256sum" "$staging/true" "$BUILDROOT/usr/bin/"
for applet in chcon cp; do
    if [[ -f "$staging/$applet" ]]; then
        mv -- "$staging/$applet" "$BUILDROOT/usr/bin/"
    fi
done
rm -- "$staging/gnu-paths"
rmdir -- "$staging"
