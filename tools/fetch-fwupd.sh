#!/usr/bin/bash
set -euo pipefail
umask 077

project_dir=$(cd -- "$(dirname -- "$0")/.." && pwd)
source "$project_dir/tools/fwupd-source.env"
cache="$project_dir/build/fwupd-source"
mkdir -p -- "$cache"
name="fwupd-$fwupd_version.tar.xz"
source_archive="$cache/$name"

verify_archive() {
    printf '%s  %s\n' "$fwupd_sha256" "$1" | sha256sum --check --strict
}

if [[ -f "$source_archive" ]]; then
    verify_archive "$source_archive"
    exit
fi

work=$(mktemp -d "$cache/.download.XXXXXXXX")
trap 'rm -r -- "$work"' EXIT
mkdir -m 700 "$work/gnupg"
release="https://github.com/fwupd/fwupd/releases/download/$fwupd_version"
curl --fail --silent --show-error --location --proto '=https' --max-time 120 \
    "$release/$name" --output "$work/$name"
verify_archive "$work/$name"
curl --fail --silent --show-error --location --proto '=https' --max-time 30 \
    "$release/$name.asc" --output "$work/$name.asc"
curl --fail --silent --show-error --location --proto '=https' --max-time 30 \
    https://github.com/hughsie.gpg --output "$work/signer.asc"
gpg --homedir "$work/gnupg" --batch --import "$work/signer.asc"
gpg --homedir "$work/gnupg" --batch --status-fd 1 --verify "$work/$name.asc" "$work/$name" |
    awk -v signer="$fwupd_signer" '$2 == "VALIDSIG" && $3 == signer { valid=1 } END { exit !valid }'
mv -- "$work/$name" "$source_archive"
