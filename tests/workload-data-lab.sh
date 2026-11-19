#!/usr/bin/bash
# Create disposable Service Guest data disks for the verified and tampered boot cases.
set -euo pipefail
umask 077

if [[ $# != 3 ]]; then
    echo 'Run tests/workload-data-lab.sh GUEST_DATA_TEMPLATE AUTHORIZED_BUNDLE NEW_OUTPUT_DIRECTORY' >&2
    exit 2
fi
template=$1
bundle=$2
output=$3
tests=$(cd -- "$(dirname -- "$0")" && pwd)
selection="$tests/guest-storage.conf"
partition=$(sed -n 's/^partition=//p' "$selection")
filesystem=$(sed -n 's/^filesystem_uuid=//p' "$selection")
geometry=$(sfdisk --json "$template" | jq -er --arg partition "$partition" '
    .partitiontable
    | select(.label == "gpt" and .sectorsize == 512 and (.partitions | length) == 1)
    | .partitions[0] | select((.uuid | ascii_downcase) == $partition)
    | [.start, .size] | @tsv
')
read -r start size <<< "$geometry"
mkdir -- "$output"
temporary=$(mktemp -d "$output/.workload-fixtures.XXXXXXXX")
trap 'rm -rf -- "$temporary"' EXIT

for name in approved tampered; do
    tree="$temporary/$name-tree"
    install -dm700 "$tree/workload"
    for file in authorization.json authorization.p7s deployment.json deployment.p7s derivation.json launch.json publisher-proof.json workload.raw; do
        cp --reflink=auto -- "$bundle/$file" "$tree/workload/$file"
    done
    chmod 700 "$tree"
    chcon -R system_u:object_r:var_lib_t:s0 -- "$tree"
    if [[ "$name" == tampered ]]; then
        # Change exactly one byte inside the first data partition.
        python3 - "$tree/workload/workload.raw" <<'PY'
import sys

with open(sys.argv[1], "r+b") as artifact:
    offset = 1024 * 1024
    artifact.seek(offset)
    byte = artifact.read(1)
    if len(byte) != 1:
        raise ValueError("expected a complete workload disk")
    artifact.seek(offset)
    artifact.write(bytes([byte[0] ^ 1]))
PY
    fi
    image="$temporary/$name-filesystem.raw"
    truncate -s "$((size * 512))" "$image"
    podman unshare mkfs.btrfs --quiet --force --nodiscard --data single --metadata single \
        --uuid "$filesystem" --rootdir "$tree" "$image"
    guest="$temporary/$name.raw"
    cp --reflink=auto --sparse=always -- "$template" "$guest"
    dd if="$image" of="$guest" bs=1M oflag=seek_bytes seek="$((start * 512))" conv=notrunc status=none
    mv -- "$guest" "$output/$name.raw"
done
