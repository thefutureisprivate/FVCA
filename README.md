# Fedora Verified Compute Appliance

The first implementation milestone is a shared x86-64 development boot image for the VM-only Hypervisor and OCI Service Guest described in FVCA design v0.4.3. The Fedora 45 mkosi build produces a disk with a signed Unified Kernel Image (UKI), a read-only EROFS root, a dm-verity hash tree, and a detached root hash signature in its own GPT partition. The UKI embeds the expected root hash and execution policy. A Rust initramfs entrypoint loads dm-verity with signature enforcement before systemd attaches the global BPF execution policy. The kernel verifies the detached signature during root activation. Systemd closes the initramfs trust window after switch-root. [systemd execution policy](https://www.freedesktop.org/software/systemd/man/262/systemd-system.conf.html#RestrictFileSystemAccess=)

The image uses a boot-status target and volatile `/var`. It disables automatic extension and additional GPT partition discovery. Build workers run Fedora's package scripts before removing shells, login tools and maintenance hooks from the base and initramfs. Both trees must pass an audit for prohibited commands, executable scripts, setuid/setgid files and file capabilities. Emergency and rescue targets report `FVCA_BOOT_FAILED` on the console. Both roles use Btrfs for mutable data. Service Guest runtime and workload qualification, physical TPM qualification, attestation and release authorization remain pending.

The design draws on AOS's use of signed UKIs and integrity-protected disk images. [Amutable Foundations technical overview](https://amutable.com/blog/amutable-foundations-technical-overview)

## Build and verify

Use a Fedora 45 x86-64 build machine or disposable VM. Install `mkosi`, `mkosi-system-deps`, `systemd-ukify`, `sbsigntools`, `mtools`, `openssl`, `util-linux-core`, `erofs-utils`, and `veritysetup` on the builder. The development recipe uses the Fedora release and updates repositories with RPM signature verification. The build overlays pin the Rust, Cargo and GCC packages and build the local Rust crates with `cargo --frozen` and networking disabled. The two package manifests record the resolved OS packages. Release builds will need pinned package inputs throughout.

```sh
umask 077
./tools/fetch-allocator.sh
mkosi genkey  # First build only. Keep mkosi.key private.
mkosi build
(cd build && sha256sum -c fvca-dev-base.SHA256SUMS)
python3 tools/verify-base.py build/fvca-dev-base.raw mkosi.crt
```

The QEMU procedure uses one enrolled development certificate for both signing purposes. Production signer separation remains pending. The off-node verifier accepts a separate root-signing certificate with `--verity-certificate`. It reads the policy in the signed UKI and verifies the detached signature and dm-verity data from the actual disk image. The disk, split UKI, root hash and package manifests are in `build/`.

The package manifests record what the builder installed before file pruning. `python3 tools/audit-os-tree.py PATH` runs the content audit without changing an extracted tree. Preserve file modes and extended attributes when extracting the EROFS root for this check.

Both images build hardened_malloc 14 from a digest-checked source archive, run its upstream tests, and retain the allocator license and build record under `/usr/share`. The build uses the upstream default profile with a fixed `x86-64` compiler target and the upstream GCC 16 header fix. The verified `/etc/ld.so.preload` selects the library for eligible programs. The Rust bootstrap and both copies of systemd have a mandatory loader dependency on the library. The Rust bootstrap and the readiness service check resolved allocator symbols. `vm.max_map_count = 1048576` is the development setting for allocator qualification. [hardened_malloc 14](https://github.com/GrapheneOS/hardened_malloc/releases/tag/14)

The builder compiles Fedora's pinned targeted SELinux policy offline with the FVCA initramfs module. It embeds the root labels in EROFS before dm-verity signing. The Rust bootstrap labels the unpacked CPIO with the contexts from the signed UKI before systemd loads the embedded policy. The policy denies unknown kernel permissions. A Rust check requires SELinux enforcing mode and the expected `init_t` domain for PID 1 before mounting the verified root and again before reporting readiness.

## Boot in QEMU

Install `qemu-system-x86-core`, `edk2-ovmf`, and `python3-virt-firmware`. Enroll the development certificate in a disposable OVMF variable store and start the image with disk snapshots and no network adapter. Use `-accel tcg -cpu max` if KVM is unavailable.

```sh
ovmf=/usr/share/edk2/ovmf
owner=a5c059a1-94e4-4aa7-87b5-ab155c2bf072
virt-fw-vars --input "$ovmf/OVMF_VARS.fd" --output build/fvca-vars.fd \
  --secure-boot --set-pk "$owner" mkosi.crt --add-kek "$owner" mkosi.crt \
  --add-db "$owner" mkosi.crt

qemu-system-x86_64 -machine q35,smm=on -accel kvm -cpu host -m 2048 \
  -global driver=cfi.pflash01,property=secure,value=on \
  -drive if=pflash,format=raw,readonly=on,file="$ovmf/OVMF_CODE.secboot.fd" \
  -drive if=pflash,format=raw,snapshot=on,file=build/fvca-vars.fd \
  -drive if=virtio,format=raw,snapshot=on,file=build/fvca-dev-base.raw \
  -nographic -nic none -no-reboot
```

The serial console prints `FVCA_DEV_BASE_READY` after the boot gate verifies UEFI Secure Boot, the read-only EROFS root on `/dev/mapper/root`, SELinux enforcement and allocator binding and allocation. Press Ctrl+A, then X to exit QEMU.

## Exercise the execution policy

```sh
mkosi --profile=exec-check --output-dir=build/exec-check build
```

Use the same QEMU command with `build/exec-check/fvca-dev-exec-check.raw` as the boot disk. The development test runs from the verified root after switch-root. It checks its allocator binding and requires permission denials for anonymous RX and RWX mappings, an RW-to-RX transition, and execution of a copied binary from `/run`. The console prints `FVCA_EXEC_CHECK_PASSED` before `FVCA_DEV_BASE_READY` when all checks pass. The probe is built only in the qualification profile.

## Open Build Service

[`obs/project.conf`](obs/project.conf) is the starting configuration for a dedicated native mkosi image repository. OBS still needs a verified worker package set, a source service pinned to a reviewed Git revision, and a staging-signing configuration. Keep production signing separate from OBS candidate builds. The local build uses development keys and keeps them outside Git. [OBS mkosi build documentation](https://openbuildservice.org/help/manuals/obs-user-guide/cha-obs-package-formats#sec-obs-mkosi)

## Hypervisor runtime candidate

The separate mkosi recipe builds `vm-runtime.raw`, a signed EROFS system extension. It contains QEMU, the modular libvirt QEMU, log and lock daemons, the selected OVMF firmware and restic. The VMM is built offline from the pinned upstream QEMU release and the build checks that KVM is its only accelerator. The development appliance uses private UNIX sockets for libvirt and requires SELinux confinement for QEMU processes. The build strips Fedora's automatic service hooks and management commands before signing, records the exact core root hash in the extension and checks the shared package versions. [QEMU release archive and signing key](https://www.qemu.org/download/)

Prepare a fresh base input from the verified development disk, and use a separate development certificate for the runtime. Keep the private key in the ignored build directory.

```sh
umask 077
./tools/fetch-qemu.sh
python3 tools/verify-base.py build/fvca-dev-base.raw mkosi.crt \
  --extract-root build/vm-runtime-base
openssl req -x509 -newkey rsa:3072 -noenc -days 365 \
  -subj '/CN=FVCA development VM runtime/' \
  -keyout build/vm-runtime-signing.key -out build/vm-runtime-signing.crt
mkosi -C vm-runtime build
python3 tools/verify-vm-runtime.py build/vm-runtime/vm-runtime.raw \
  build/vm-runtime-signing.crt build/vm-runtime-base
```

Keep the `.manifest` and checksum files next to both images. Prepare a new build input and rebuild the extension when selecting a different core. [mkosi system extension build guide](https://github.com/systemd/mkosi/blob/v26/docs/sysext.md)

## Boot the composed Hypervisor in QEMU

The Hypervisor profile builds a role-specific initramfs. The assembler verifies the core and the runtime with their respective certificates, then signs a UKI containing the approved core and runtime root hashes. It authorizes the verified runtime hash with the existing development verity key for the disposable VM. The output disk carries the original verified core and a new ESP boot file.

```sh
mkosi --profile=hypervisor --output-dir=build/hypervisor-profile build
python3 tools/compose-hypervisor.py \
  --core build/fvca-dev-base.raw \
  --runtime build/vm-runtime/vm-runtime.raw \
  --initrd build/hypervisor-profile/initrd.cpio.zst \
  --boot-certificate mkosi.crt --boot-key mkosi.key \
  --runtime-certificate build/vm-runtime-signing.crt \
  --output build/hypervisor-profile/fvca-dev-hypervisor.raw
```

Use the QEMU command above with `build/hypervisor-profile/fvca-dev-hypervisor.raw` as the boot disk. Pass the runtime as a second drive with `-drive if=virtio,format=raw,readonly=on,file=build/vm-runtime/vm-runtime.raw`. Use Intel KVM with VMX exposed to the appliance for this test. The appliance disables nested virtualization for its own guests. The initramfs activates the selected signed verity mapping and mounts an overlay made from two read-only layers before switch-root.

The readiness probe runs `qemu-img` from the composed `/usr` and exercises a diskless, networkless q35 VM through the private libvirt socket. It requires an sVirt MCS label, the dedicated QEMU UID, seccomp, no-new-privileges, zero effective capabilities, and a private mount namespace. The console prints `FVCA_LIBVIRT_LIFECYCLE_OK` after the VM starts, suspends, resumes, and stops. Booting a signed Service Guest and production release authorization remain separate qualification targets.

## Development Hypervisor storage

The Hypervisor assembler accepts `--storage tests/host-storage.conf` for the disposable storage fixture. The UKI signs both GPT partition identities and the expected native RAID1, LUKS2 and Btrfs identities. The initramfs requires both selected partitions on separate disks and disables automatic RAID assembly. It checks the assembled array and the LUKS header before requesting the operator passphrase on the console.

The development image gates readiness on a single-device Btrfs mount at `/run/fvca/host-data` with `nodev,nosuid,noexec`. RAID1 supplies physical redundancy below LUKS2. The Btrfs root directory must be owned by root with mode `0700`. This volume holds mutable data. Physical TPM qualification, independent boot slots, the appliance recovery environment, and authenticated mutable-state protections remain pending.

On a Fedora KVM test machine with `mdadm`, `cryptsetup`, `btrfs-progs` and `cpio` installed, the fixture creates fresh file-backed disks and tests single-member recovery and replacement. The recovery mount suppresses Btrfs log replay while inspecting either member. Build the Hypervisor as above with the fixture selection added to the assembler command, then run the integration checks against the signed disk and its matching runtime. [Btrfs recovery mount options](https://btrfs.readthedocs.io/en/latest/ch-mount-options.html)

```sh
tests/storage-lab.sh build/host-storage-lab
python3 tests/check-storage.py \
  --disk build/hypervisor-profile/fvca-dev-hypervisor.raw \
  --runtime build/vm-runtime/vm-runtime.raw \
  --variables build/fvca-vars.fd \
  --lab build/host-storage-lab --output build/host-storage-checks
```

### Development TPM and PIN unlock

The TPM storage selection uses `unlock=tpm2-pin` and a final `token=INDEX,SHA256` line containing the SHA-256 of the exact `cryptsetup token export` output. Give the assembler this manifest with `--storage`, the export with `--tpm-token`, and a separate RSA signing key with `--pcr-key`. The assembler checks the enrollment's SHA-256 PCR bank, direct PCRs 7, 12 and 13, signed PCR 11, policy reference `fvca-host-storage`, and Argon2id-protected PIN. It signs PCR 11 only for the `enter-initrd` phase. The signed initramfs checks and opens the same private copy of the LUKS2 header in token-only mode. [systemd-cryptenroll](https://www.freedesktop.org/software/systemd/man/262/systemd-cryptenroll.html)

In the disposable enrollment environment, use the target firmware and its Secure Boot keys. A measured systemd initramfs applies the `os-separator` event automatically. A minimal lab initramfs must apply that same event to PCRs 7, 12 and 13 before enrollment. Preserve the separate recovery credential. [systemd PCR phase and separator](https://www.freedesktop.org/software/systemd/man/262/systemd-pcrphase.service.html)

With the fixture mirror assembled at `/dev/md0`, supply the fixture recovery key and the public half of the separate PCR signing key. The example exports the first token on a fresh fixture.

```sh
systemd-cryptenroll /dev/md0 --unlock-key-file=storage.key \
  --tpm2-device=/dev/tpmrm0 --tpm2-with-pin=yes \
  --tpm2-pcrs=7:sha256+12:sha256+13:sha256 --tpm2-public-key=pcr-public.pem \
  --tpm2-public-key-pcrs=11 --tpm2-public-key-policyref=fvca-host-storage
cryptsetup token export --token-id=0 /dev/md0 > token.json
sha256sum token.json
```

The lab check takes `--firmware` for the measured Secure Boot firmware, `--variables` for its enrolled variables, `--tpm-state` for the enrolled software TPM, and `--pin-file` for the disposable 24-hex-character PIN. It exercises the signed Hypervisor with the correct PIN, wrong PIN, unrelated TPM, extra measured command line, and absent TPM.

The Hypervisor initramfs omits systemd's stock NvPCR definitions. The storage PCR authority authorizes only LUKS2 unsealing. Future TPM-backed release state requires its own initialization policy.

The shared SELinux policy switches Fedora's PCR measurement domain to enforcing. Both the initramfs and the core verify the domain against the policy loaded in the kernel. On a measured boot, systemd prepares the root-only, separately labeled log at `/run/log/systemd/tpm2-measure.log` before the first userspace PCR measurements.

## Development Service Guest storage

The Service Guest uses one ordinary virtual Btrfs data partition. Its signed development UKI contains the selected partition and filesystem UUIDs from `tests/guest-storage.conf`. The boot gate requires that exact single-device filesystem and mounts it at `/run/fvca/guest-data` with `nodev,nosuid,noexec`. The signed EROFS image continues to provide the verified OS root for both roles.

```sh
mkosi --profile=service-guest-storage --output-dir=build/service-guest-storage build
python3 tests/check-storage.py --guest \
  --disk build/service-guest-storage/fvca-dev-service-guest.raw \
  --variables build/fvca-vars.fd --lab build/host-storage-lab \
  --output build/guest-storage-checks
```

Boot `build/service-guest-storage/fvca-dev-service-guest.raw` with the common QEMU command and attach the fixture as a second drive with `-drive if=virtio,format=raw,snapshot=on,file=build/host-storage-lab/guest-data.raw`. The console reports `FVCA_GUEST_DATA_ACTIVE` before readiness. This storage-only profile also provides the verified core for the composed Service Guest.

## Development Service Guest OCI runtime

The `service-guest-storage` build supplies the Guest core and its container SELinux policy. The separate `oci-runtime.raw` image contains Podman, Quadlet, crun, conmon, Netavark, Aardvark DNS, catatonit and restic. Its allowlist excludes systemd generators, API sockets, service units and host mount configuration. The signed core fixes crun as the runtime, rejects registry pulls and keeps Podman metadata on volatile storage. The Guest mounts its Btrfs data outside the engine's storage.

Build against the exact prepared Guest core. The assembler verifies the separate OCI runtime signer, the core binding and the additive payload before it signs the Guest UKI.

```sh
umask 077
bash tools/fetch-workload-admission.sh
mkosi --profile=service-guest-storage --output-dir=build/service-guest-storage build
python3 tools/verify-base.py build/service-guest-storage/fvca-dev-service-guest.raw mkosi.crt \
  --extract-root build/service-guest-runtime-base
openssl req -x509 -newkey rsa:3072 -noenc -days 365 \
  -subj '/CN=FVCA development OCI runtime/' \
  -keyout build/oci-runtime-signing.key -out build/oci-runtime-signing.crt
mkosi -C oci-runtime build
mkosi --profile=service-guest-runtime --output-dir=build/service-guest-runtime-initrd build
python3 tools/compose-service-guest.py \
  --core build/service-guest-storage/fvca-dev-service-guest.raw \
  --runtime build/oci-runtime/oci-runtime.raw \
  --initrd build/service-guest-runtime-initrd/initrd.cpio.zst \
  --boot-certificate mkosi.crt --boot-key mkosi.key \
  --runtime-certificate build/oci-runtime-signing.crt \
  --output build/service-guest-runtime-initrd/fvca-dev-service-guest.raw
python3 tests/check-storage.py \
  --disk build/service-guest-runtime-initrd/fvca-dev-service-guest.raw \
  --oci-runtime build/oci-runtime/oci-runtime.raw --variables build/fvca-vars.fd \
  --lab build/host-storage-lab --output build/service-guest-runtime-checks
```

The development boot check initializes Podman with crun, VFS and SELinux, runs crun, and renders a fixed Quadlet `Rootfs=` fixture. The integration test requires Btrfs and the selected runtime, and checks rejection of absent and duplicated runtime disks. A separate signed EROFS lab workload exercised start, exec, health checks, restart and stop with an enforcing SELinux container label. Workload admission, network and resource qualification, and Stalwart acceptance remain open. [Podman Quadlet documentation](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)

## Off-node Stalwart workload derivation

The [Stalwart source policy](policy/workloads/stalwart-v1.1.1.json) pins the repository, publisher workflow identity and issuer, signed OCI index, and selected Linux amd64 manifest. It also fixes the expected numeric identity and the two application volume destinations. Derivation verifies the publisher with Cosign v3.1.4, checks descriptor sizes and hashes, and validates the ordered layers and their expanded diff IDs. The rootless worker receives the checked blobs and conversion tools through a private input mount. It unpacks with pinned `umoci` in a network-disabled container and emits an unsigned EROFS image and verity tree. [Sigstore verification](https://docs.sigstore.dev/cosign/verifying/verify/) · [umoci](https://github.com/opencontainers/umoci)

The deterministic recipe supplies the mount points Podman needs on a read-only root, strips set-ID bits and file capabilities, and records the exact changes. It preserves the OCI entrypoint, command, environment, resolved UID/GID, working directory, stop signal, health command and volume destinations in the launch definition. The source policy authorizes conversion. The deployment record authorizes one Guest and launch definition.

Prepare the exact source and worker on the off-node Fedora builder with rootless Podman, Skopeo, Cosign v3.1.4, `jq`, `sfdisk`, `veritysetup` and OpenSSL installed.

```sh
umask 077
mkdir -p build/stalwart-input build/workload-worker-context
policy=policy/workloads/stalwart-v1.1.1.json
repo=$(jq -r .repository "$policy")
index=$(jq -r .index "$policy")
manifest=$(jq -r .manifest "$policy")
skopeo inspect --raw "docker://$repo@$index" > build/stalwart-input/publisher-index.json
skopeo copy --preserve-digests "docker://$repo@$manifest" oci:build/stalwart-input/amd64.oci:source
podman build --platform linux/amd64 -t localhost/fvca-workload-worker:45 \
  -f tools/workload-worker.Containerfile build/workload-worker-context
worker=$(podman image inspect --format '{{.Id}}' localhost/fvca-workload-worker:45)
worker=sha256:${worker#sha256:}
python3 tools/derive-workload.py --policy "$policy" \
  --source-index build/stalwart-input/publisher-index.json --layout build/stalwart-input/amd64.oci \
  --cosign "$(command -v cosign)" --worker-image "$worker" --output build/stalwart-candidate
```

Review `derivation.json` and `launch.json`, then have the deployment authority sign the exact deployment document as detached DER CMS. The `fvca-workload-deployment-v1` document contains these fields.

| Fields | Approval scope |
| --- | --- |
| `schema`, `role`, `guest`, `service` | Schema version, `service-guest`, assigned Guest identity and service |
| `source_index`, `manifest`, `provenance`, `launch` | Exact index digest, platform digest, `PUBLISHER_VERIFIED`, and launch digest from the reviewed derivation |
| `valid_from`, `expires`, `security_epoch`, `revocation_id` | Unix timestamps, positive epoch and revocation UUID |
| `id_map` | Approved subordinate `uid_base` and `gid_base`, each mapping a `size` of 65536 IDs from container ID zero |
| `network`, `limits` | `none` for this offline profile, plus `memory_bytes`, `cpu_percent` and `pids` |

The workload-root authority uses a separate key. The authorizer verifies the deployment signature and validity period, verifies the publisher again, and reproduces the candidate byte for byte in a fresh worker before signing the output. The result includes `workload.raw`, the signed authorization and deployment, the launch definition, and the derivation and publisher evidence.

```sh
openssl cms -sign -binary -nocerts -noattr -outform DER -in build/deployment.json \
  -signer build/deployment.crt -inkey build/deployment.key -out build/deployment.p7s
python3 tools/authorize-workload.py --policy "$policy" \
  --source-index build/stalwart-input/publisher-index.json --layout build/stalwart-input/amd64.oci \
  --cosign "$(command -v cosign)" --worker-image "$worker" --candidate build/stalwart-candidate \
  --deployment build/deployment.json --deployment-signature build/deployment.p7s \
  --deployment-certificate build/deployment.crt --workload-key build/workload.key \
  --workload-certificate build/workload.crt --output build/stalwart-authorized
```

This off-node flow implements signed-only source admission. The optional unsigned permit mode and full Stalwart service acceptance remain open.

## Guest workload verifier

The Rust verifier checks both CMS signatures against separate signer certificates. It binds the exact deployment, derivation, publisher evidence, launch definition and raw image bytes, then checks both GPT tables and the signed dm-verity root hash. It checks the target Guest and service, validity period, minimum security epoch, revocation list and offline launch profile before returning the verified file descriptor and partition offsets.

The policy record contains `guest`, `service`, the reviewed `source_policy` SHA-256 digest from the derivation, `minimum_epoch` and `revoked` as a list of revocation UUIDs. The development CLI takes that record, the two public signer certificates and a private staging directory.

On Fedora 45 with Rust, Cargo and `openssl-devel`, fetch the locked dependencies before the offline build. The development test uses disposable signer keys, OpenSSL and `sfdisk` to exercise rejection paths.

```sh
cargo fetch --locked --manifest-path workload-admission/Cargo.toml
RUSTFLAGS=-Dwarnings cargo build --frozen --manifest-path workload-admission/Cargo.toml
python3 tests/check-workload-admission.py
workload-admission/target/debug/fvca-workload-admission \
  build/guest-workload-policy.json build/deployment.crt build/workload.crt build/stalwart-authorized
```

## Guest workload root activation

Supply `--workload-policy build/guest-workload-policy.json`, `--deployment-certificate build/deployment.crt` and `--workload-certificate build/workload.crt` to the Service Guest composer to embed one workload trust policy in the development UKI. The four signing keys for Secure Boot, the OCI runtime, deployment and workload authorization must be distinct. The signed initramfs enrolls the public workload certificate after checking the base and OCI runtime, then seals the kernel's `.dm-verity` keyring before switching root. [Amutable's upstream dm-verity keyring overview](https://amutable.com/blog/it-starts-upstream-kernel)

Place the contents of the authorized bundle in a root-owned `0700` directory named `workload` at the top level of the selected Guest Btrfs filesystem. With the signed policy enabled, the boot service checks the bundle, binds two read-only loop devices to the verified file descriptor and its root and hash offsets, and mounts the kernel-verified EROFS root at `/run/fvca/workload-image/root`. Activation fails closed if the signed inputs or the disk differ. The workload stays within its dedicated mount path. Its public key and seal do not have to be re-signed with the Secure Boot key.

For a disposable lab, run `tests/workload-data-lab.sh build/host-storage-lab/guest-data.raw build/stalwart-authorized build/workload-data-lab` on Fedora with Btrfs tools, `jq`, SELinux and rootless Podman. The resulting disks use the signed Guest storage identity and the `var_lib_t` SELinux type for staged data. Run `tests/check-storage.py --workload` with the composed disk, `--oci-runtime` and `--lab build/workload-data-lab`. It boots the approved bundle and a copy with one byte changed in `workload.raw`, using disk snapshots and the approved OVMF variable store.

The Guest mounts the root at boot. Protected updates and controller-backed freshness, the generated Quadlet, workload resource enforcement, and the complete Stalwart service lifecycle remain pending.
