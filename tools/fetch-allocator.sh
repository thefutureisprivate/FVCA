#!/usr/bin/bash
set -euo pipefail
umask 077

project_dir=$(cd -- "$(dirname -- "$0")/.." && pwd)
source "$project_dir/tools/allocator-source.env"
cache="$project_dir/build/allocator-upstream"
mkdir -p "$cache"
source_archive="$cache/hardened_malloc-$allocator_version.tar.gz"

if [[ -f "$source_archive" ]]; then
    printf '%s  %s\n' "$allocator_sha256" "$source_archive" | sha256sum --check
    exit
fi

download=$(mktemp "$cache/.download.XXXXXXXX")
trap 'rm -f "$download"' EXIT
curl --fail --silent --show-error --location --proto '=https' --max-time 60 \
    "https://codeload.github.com/GrapheneOS/hardened_malloc/tar.gz/$allocator_revision" \
    --output "$download"
printf '%s  %s\n' "$allocator_sha256" "$download" | sha256sum --check
mv -- "$download" "$source_archive"
