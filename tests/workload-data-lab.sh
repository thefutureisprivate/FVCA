#!/usr/bin/bash
# Create disposable Service Guest data disks for the verified and tampered boot cases.
set -euo pipefail
umask 077

if [[ $# -lt 3 || $# -gt 4 ]]; then
    echo 'Run tests/workload-data-lab.sh GUEST_DATA_TEMPLATE AUTHORIZED_BUNDLE NEW_OUTPUT_DIRECTORY [STALWART_MAIL_LAB]' >&2
    exit 2
fi
template=$1
bundle=$2
output=$3
mail_lab=${4:-}
if [[ -n "$mail_lab" ]]; then
    ownership=$(jq -er '
        select(.service == "stalwart")
        | .id_map
        | select(.size > 2000 and (.uid_base | type) == "number" and (.gid_base | type) == "number")
        | "\(.uid_base + 2000):\(.gid_base + 2000)"
    ' "$bundle/deployment.json")
    IFS=: read -r payload_uid payload_gid <<< "$ownership"
    test -s "$mail_lab/mail.eml"
    config_name=$(printf '%s' /etc/stalwart | sha256sum)
    data_name=$(printf '%s' /var/lib/stalwart | sha256sum)
    config_name=${config_name%% *}
    data_name=${data_name%% *}
fi
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
trap 'podman unshare rm -rf -- "$temporary"' EXIT

for name in approved tampered; do
    tree="$temporary/$name-tree"
    install -dm700 "$tree/workload"
    for file in authorization.json authorization.p7s deployment.json deployment.p7s derivation.json launch.json publisher-proof.json workload.raw; do
        cp --reflink=auto -- "$bundle/$file" "$tree/workload/$file"
    done
    chmod 700 "$tree"
    builder=(podman unshare)
    if [[ -n "$mail_lab" && "$name" == approved ]]; then
        payload="$tree/payload/stalwart"
        mkdir -m700 -- "$tree/payload" "$payload"
        podman unshare cp -r --no-preserve=ownership,context -- "$mail_lab/config" "$payload/$config_name"
        podman unshare cp -r --no-preserve=ownership,context -- "$mail_lab/data" "$payload/$data_name"
        # Give mkfs the actual Guest ownership without requiring those IDs in
        # the workstation's subordinate ID allocation.
        builder+=(unshare --user --map-users=0:0:1 "--map-users=$payload_uid:1:1"
                  --map-groups=0:0:1 "--map-groups=$payload_gid:1:1"
                  bash -euc 'chown -R "$1" -- "$2" "$3"; shift 3; exec "$@"'
                  bash "$ownership" "$payload/$config_name" "$payload/$data_name")
    fi
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
    "${builder[@]}" mkfs.btrfs --quiet --force --nodiscard --data single --metadata dup \
        --uuid "$filesystem" --rootdir "$tree" "$image"
    guest="$temporary/$name.raw"
    cp --reflink=auto --sparse=always -- "$template" "$guest"
    dd if="$image" of="$guest" bs=1M oflag=seek_bytes seek="$((start * 512))" conv=notrunc status=none
    mv -- "$guest" "$output/$name.raw"
done
