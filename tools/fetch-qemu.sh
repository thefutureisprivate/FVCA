#!/usr/bin/bash
set -euo pipefail
umask 077

project_dir=$(cd -- "$(dirname -- "$0")/.." && pwd)
source "$project_dir/tools/qemu-source.env"
cache="$project_dir/build/qemu-source"
mkdir -p "$cache"
source_archive="$cache/qemu-$qemu_version.tar.xz"

if [[ -f "$source_archive" ]]; then
    printf '%s  %s\n' "$qemu_sha256" "$source_archive" | sha256sum --check --strict
    exit
fi

download=$(mktemp "$cache/.download.XXXXXXXX")
trap 'rm -f -- "$download"' EXIT
curl --fail --silent --show-error --location --proto '=https' --max-time 180 \
    "https://download.qemu.org/qemu-$qemu_version.tar.xz" --output "$download"
printf '%s  %s\n' "$qemu_sha256" "$download" | sha256sum --check --strict
mv -- "$download" "$source_archive"
