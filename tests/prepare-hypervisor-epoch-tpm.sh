#!/usr/bin/bash
set -euo pipefail
umask 077
if [[ $# != 2 && $# != 3 ]]; then
  echo "Usage: $0 ENROLLED_SOFTWARE_TPM_STATE NEW_OUTPUT_DIRECTORY [DISPOSABLE_AUTHORITY_KEY]" >&2
  exit 2
fi
base=$(realpath -e -- "$1")
fixture_key=
if [[ $# == 3 ]]; then
  fixture_key=$(realpath -e -- "$3")
fi
if [[ ! -f "$base/tpm2-00.permall" || -S "$base/socket" ]]; then
  echo 'Expected a stopped software TPM state' >&2
  exit 2
fi
mkdir -m 700 -- "$2"
lab=$(realpath -e -- "$2")
temp=$(mktemp -d /tmp/fvca-epoch-enroll.XXXXXXXX)
pid=
stop() {
  if [[ -n "$pid" ]]; then
    kill "$pid"
    wait "$pid" || true
    pid=
  fi
}
trap 'stop; rm -rf -- "$temp"' EXIT
cp -a -- "$base" "$temp/provisioning"
cd "$temp"
export TPM2TOOLS_TCTI="swtpm:path=$temp/tpm.sock"
index=0x01504656
authority=0x80000000
start() {
  swtpm socket --tpm2 --tpmstate "dir=$temp/provisioning" --server "type=unixio,path=$temp/tpm.sock" \
    --ctrl "type=unixio,path=$temp/tpm.sock.ctrl" --flags not-need-init,startup-clear >> "$lab/swtpm.log" 2>&1 &
  pid=$!
  for _ in {1..60}; do [[ -S "$temp/tpm.sock" ]] && break; sleep 0.1; done
  [[ -S "$temp/tpm.sock" ]]
}
load_key() {
  # The stopped fixture restarts with an empty transient object table. Keep this exact key loaded.
  tpm2_loadexternal -C o -G ecc -u "$lab/authority.pem" -c authority.ctx -n authority.name >/dev/null
  tpm2_readpublic -c "$authority" -n loaded.name -f tss -o "$lab/authority.tpm2b" >/dev/null
  cmp authority.name loaded.name
}
session() {
  tpm2_startauthsession --policy-session -g sha256 -S "$1.ctx"
  tpm2_policysigned -S "$1.ctx" -c "$authority" -g sha256 -q "$lab/policy-reference.bin" \
    -x -t 300 --cphash-input command.hash --raw-data "$1.message"
}
authorize() {
  tpm2_policysigned -S "$1.ctx" -c "$authority" -g sha256 -q "$lab/policy-reference.bin" \
    -x -t 300 --cphash-input command.hash -s "$2" -f ecdsa
}
increment() {
  tpm2_policycommandcode -S "$1.ctx" TPM2_CC_NV_Increment
  tpm2_sessionconfig "$1.ctx" --disable-continuesession
  tpm2_nvincrement "$index" -C "$index" -P "session:$1.ctx"
}

(printf 'hex:'; openssl rand -hex 32) > owner.secret
if [[ -n "$fixture_key" ]]; then
  openssl pkey -in "$fixture_key" -out authority.key
else
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out authority.key
fi
openssl pkey -in authority.key -pubout -out "$lab/authority.pem"
printf 'FVCA-HYPERVISOR-FLOOR-1\0' > "$lab/policy-reference.bin"
openssl rand 16 >> "$lab/policy-reference.bin"
start
tpm2_changeauth -c owner file:owner.secret
load_key
tpm2_startauthsession -g sha256 -S trial.ctx
tpm2_policysigned -S trial.ctx -c "$authority" -g sha256 -q "$lab/policy-reference.bin"
tpm2_policycommandcode -S trial.ctx -L nv.policy TPM2_CC_NV_Increment
tpm2_flushcontext trial.ctx
tpm2_nvdefine "$index" -C o -P file:owner.secret -g sha256 -s 8 \
  -a 'authread|policywrite|nt=counter|no_da' -L nv.policy
if tpm2_nvincrement "$index" -C "$index" > "$lab/direct-write.log" 2>&1; then
  echo 'counter allowed an unauthorized write' >&2
  exit 1
fi
od -An -tx1 -v nv.policy | tr -d ' \n' > "$lab/policy.sha256"
stop
cp -a -- "$temp/provisioning" "$lab/uninitialized"

start
load_key
tpm2_nvincrement "$index" -C "$index" --cphash command.hash
session initial
openssl dgst -sha256 -sign authority.key -out initial.signature initial.message
authorize initial initial.signature
increment initial
tpm2_nvread "$index" -C "$index" -s 8 -o "$lab/floor-one"
stop
cp -a -- "$temp/provisioning" "$lab/counter-one"

start
load_key
# Initialization sets WRITTEN in the public area and changes the NV Name used in cpHash.
tpm2_nvincrement "$index" -C "$index" --cphash command.hash
session next
session competing
openssl dgst -sha256 -sign authority.key -out next.signature next.message
if authorize competing next.signature > "$lab/competing-session.log" 2>&1; then
  echo 'a competing session accepted the authorized session signature' >&2
  exit 1
fi
tpm2_flushcontext competing.ctx
authorize next next.signature
increment next
if tpm2_nvincrement "$index" -C "$index" -P session:next.ctx > "$lab/consumed-session.log" 2>&1; then
  echo 'the consumed session incremented the counter again' >&2
  exit 1
fi
session replay
if authorize replay next.signature > "$lab/replayed-signature.log" 2>&1; then
  echo 'a fresh session accepted the consumed session signature' >&2
  exit 1
fi
tpm2_flushcontext replay.ctx
tpm2_nvread "$index" -C "$index" -s 8 -o "$lab/floor-two"
stop
cp -a -- "$temp/provisioning" "$lab/counter-two"

python3 - "$lab" <<'PY'
from pathlib import Path
from sys import argv
root = Path(argv[1])
first, second = [int.from_bytes((root / f"floor-{name}").read_bytes(), "big") for name in ("one", "two")]
if first == 0 or second != first + 1:
    raise ValueError(f"unexpected TPM counter values {first} and {second}")
digest = (root / "policy.sha256").read_text(encoding="ascii")
for name, epoch in (("one", first), ("two", second)):
    (root / f"epoch-{name}.conf").write_text(
        f"FVCA-HYPERVISOR-EPOCH-1\nepoch={epoch}\npolicy_sha256={digest}\n", encoding="ascii"
    )
print(f"TPM accepted one nonce-bound increment from {first} to {second} and refused competing and replayed approvals")
PY
