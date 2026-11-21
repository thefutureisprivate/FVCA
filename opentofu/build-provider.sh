#!/usr/bin/bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    printf 'usage: %s MIRROR_DIRECTORY\n' "$0" >&2
    exit 2
fi

mirror=$(realpath -m -- "$1")
source_dir=$(dirname -- "$(realpath -- "${BASH_SOURCE[0]}")")/provider
export GOTOOLCHAIN=local GOENV=off GOWORK=off GOFLAGS=
if [[ $(go env GOVERSION) != go1.27.4 ]]; then
    printf 'FVCA provider 0.7.0 requires Go 1.27.4.\n' >&2
    exit 1
fi

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cd "$source_dir"
binary=terraform-provider-fvca_v0.7.0
GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0 go build \
    -mod=readonly -trimpath -buildvcs=false -ldflags='-buildid=' -o "$work/$binary" .

directory="$mirror/registry.opentofu.org/thefutureisprivate/fvca"
mkdir -p -- "$directory"
python3 -B - "$work/$binary" "$directory/terraform-provider-fvca_0.7.0_linux_amd64.zip" <<'PY'
import os
from pathlib import Path
import sys
from tempfile import NamedTemporaryFile
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

binary, output = map(Path, sys.argv[1:])
entry = ZipInfo(binary.name)
entry.create_system = 3
entry.external_attr = 0o100755 << 16
with NamedTemporaryFile(dir=output.parent, delete=False) as temporary:
    path = Path(temporary.name)
    try:
        with ZipFile(temporary, "w") as archive:
            archive.writestr(entry, binary.read_bytes(), compress_type=ZIP_DEFLATED)
        temporary.flush()
        os.fsync(temporary.fileno())
        os.link(path, output)
    finally:
        path.unlink()
print(output)
PY
