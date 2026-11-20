#!/usr/bin/bash
set -euo pipefail
umask 077
if [[ $# != 2 ]]; then
  echo "Usage: $0 ENROLLED_SOFTWARE_TPM_STATE NEW_OUTPUT_DIRECTORY" >&2
  exit 2
fi
base=$(realpath -e -- "$1")
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
handle=0x01504656
start() {
  swtpm socket --tpm2 --tpmstate "dir=$temp/provisioning" --server "type=unixio,path=$temp/tpm.sock" \
    --ctrl "type=unixio,path=$temp/tpm.sock.ctrl" --flags not-need-init,startup-clear >> "$lab/swtpm.log" 2>&1 &
  pid=$!
  for _ in {1..60}; do [[ -S "$temp/tpm.sock" ]] && break; sleep 0.1; done
  [[ -S "$temp/tpm.sock" ]]
}
openssl rand -out owner.secret 32
openssl ecparam -name prime256v1 -genkey -noout -out authorize.key
openssl pkey -in authorize.key -pubout -out authorize.pub
printf 'fvca-hypervisor-release-floor-v1' > reference
start
tpm2_changeauth -c owner file:owner.secret
load_key() {
  tpm2_loadexternal -C o -G ecc -u authorize.pub -c authority.ctx -n authority.name >/dev/null
}
load_key
tpm2_startauthsession -S build.ctx
tpm2_policyauthorize -S build.ctx -n authority.name -q reference >/dev/null
tpm2_policycommandcode -S build.ctx -L nv.policy TPM2_CC_NV_Increment >/dev/null
tpm2_flushcontext build.ctx
tpm2_nvdefine "$handle" -C o -P file:owner.secret -g sha256 -s 8 \
  -a 'authread|policywrite|nt=counter|no_da' -L nv.policy
if tpm2_nvincrement "$handle" -C "$handle" > "$lab/direct-write.log" 2>&1; then
  echo 'counter allowed an unauthorized write' >&2
  exit 1
fi
od -An -tx1 -v nv.policy | tr -d ' \n' > "$lab/policy.sha256"
stop
cp -a -- "$temp/provisioning" "$lab/uninitialized"
start
load_key
authorize() {
  local command=$1
  tpm2_startauthsession -S build.ctx
  "$command" build.ctx -L approved.policy
  tpm2_flushcontext build.ctx
  cat approved.policy reference > signed.message
  openssl dgst -sha256 -sign authorize.key -out approved.signature signed.message
  tpm2_verifysignature -c authority.ctx -g sha256 -m signed.message -s approved.signature -f ecdsa -t approved.ticket
  tpm2_startauthsession --policy-session -S execute.ctx
  "$command" execute.ctx
  tpm2_policyauthorize -S execute.ctx -n authority.name -q reference -i approved.policy -t approved.ticket
  tpm2_policycommandcode -S execute.ctx TPM2_CC_NV_Increment
  tpm2_nvincrement "$handle" -C "$handle" -P session:execute.ctx
  tpm2_flushcontext execute.ctx
}
initial() { local session=$1; shift; tpm2_policynvwritten -S "$session" "$@" c; }
next() { local session=$1; shift; tpm2_policynv -S "$session" -C "$handle" -i before.bin "$@" "$handle" eq; }
read_counter() {
  tpm2_nvread "$handle" -C "$handle" -s 8 -o "$1"
}
authorize initial
tpm2_nvreadpublic "$handle"
read_counter before.bin
cp before.bin "$lab/floor-one"
stop
cp -a -- "$temp/provisioning" "$lab/counter-one"
start
load_key
authorize next
read_counter "$lab/floor-two"
tpm2_startauthsession --policy-session -S stale.ctx
if next stale.ctx > "$lab/stale-policy.log" 2>&1; then
  echo 'stale NV comparison unexpectedly passed' >&2
  exit 1
fi
tpm2_flushcontext stale.ctx
read_counter after.bin
cmp after.bin "$lab/floor-two"
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
print(f"TPM policy counter advanced from {first} to {second}")
PY
