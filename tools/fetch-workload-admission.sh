#!/usr/bin/bash
set -euo pipefail
umask 077

project_dir=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"
mkdir -p build
lock=$(sha256sum workload-admission/Cargo.lock)
vendor="build/workload-admission-vendor/${lock%% *}"
[[ ! -d "$vendor" ]] || exit 0
mkdir -p build/workload-admission-vendor
candidate=$(mktemp -d build/.workload-vendor.XXXXXXXX)
trap 'rm -rf "$candidate"' EXIT
cargo vendor --locked --versioned-dirs --manifest-path workload-admission/Cargo.toml "$candidate/vendor" > /dev/null
mv --no-target-directory --no-clobber "$candidate/vendor" "$vendor"
