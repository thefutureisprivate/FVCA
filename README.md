# Fedora Verified Compute Appliance

The FVCA design v0.4.4 defines a VM-only Hypervisor and an OCI Service Guest. Both development roles use a shared x86-64 boot image. The Fedora 45 mkosi build produces a disk with a signed Unified Kernel Image (UKI), a read-only EROFS root, a dm-verity hash tree, and a detached root hash signature in its own GPT partition. The UKI embeds the expected root hash and execution policy. A Rust initramfs entrypoint loads dm-verity with signature enforcement before systemd attaches the global BPF execution policy. The kernel verifies the detached signature during root activation. Systemd closes the initramfs trust window after switch-root. [systemd execution policy](https://www.freedesktop.org/software/systemd/man/262/systemd-system.conf.html#RestrictFileSystemAccess=)

The image uses a boot-status target and volatile `/var`. It disables automatic extension and additional GPT partition discovery. Build workers run Fedora's package scripts before removing shells, login tools and maintenance hooks from the base and initramfs. Both trees must pass an audit for prohibited commands, executable scripts, setuid/setgid files and file capabilities. Emergency and rescue targets report `FVCA_BOOT_FAILED` on the console. Both roles use Btrfs for mutable data. Physical TPM qualification, attestation and production release approval remain pending.

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

## Verify and stage a signed role release

`fvca-release-client` accepts an exact role release from a configured HTTPS or local TUF depot on the release or recovery workstation. Use an out-of-band trusted root and a separately authorized local selection record. Keep the TUF root and approved targets signing keys offline. Assign distinct Ed25519 keys to all four top-level TUF roles, and use consistent snapshots with SHA-256 and lengths at both metadata links. The client accepts timestamp metadata with up to 24 hours of remaining validity and snapshot metadata with up to seven days. Use a trusted clock and preserve the private metadata state across imports. [TUF specification](https://theupdateframework.github.io/specification/latest/) · [Amutable Quarry distribution](https://amutable.com/blog/distributing-images-quarry)

Publish a top-level target named `ROLE-EPOCH-release.json`. The Hypervisor tuple contains the composed boot disk, the VM runtime disk, and its authorized Guest boot disk. The Service Guest tuple contains the packed Guest boot disk holding the signed UKI, core and OCI runtime. Publish a qualification record as a separate target and include its digest and byte count in the manifest. Before signing targets, independently review the actual qualification evidence and verify the signed boot and runtime artifacts with the role's release authorities.

For example, the Service Guest manifest uses this shape. Replace the digest strings and lengths with the exact values of the reviewed release files.

```json
{
  "schema": "fvca-os-release-v1",
  "epoch": 19,
  "composition": {
    "role": "service-guest",
    "guest_boot": {"bytes": 587538944, "sha256": "GUEST_BOOT_SHA256"}
  },
  "qualification": {"bytes": 1024, "sha256": "QUALIFICATION_SHA256"}
}
```

The Hypervisor composition instead uses `role` set to `hypervisor` and requires `boot`, `vm_runtime` and `guest_boot` member records. Add `ROLE-EPOCH-boot.raw`, `ROLE-EPOCH-vm-runtime.raw`, `ROLE-EPOCH-guest-boot.raw` and `ROLE-EPOCH-qualification.json` targets as applicable. In the depot, use `metadata/` for the TUF role documents and `targets/` for hash-prefixed target files. Mount imported media with `nodev,nosuid,noexec` and keep it read-only for intake.

Keep the depot configuration and CA bundle under the intake operator's control alongside the trusted root. The release selection can specify only a role, epoch, manifest digest and byte budget. For HTTPS, configure a static origin with a trailing slash on the depot path, an absolute PEM CA bundle path and a deadline for fetching the complete release. The client verifies the server name against this CA bundle, connects directly to the configured origin and requires unencoded response bodies. Serve repository objects with HTTP 200 and missing objects with HTTP 404.

```json
{
  "transport": "https",
  "base_url": "https://updates.example.org/fvca/",
  "ca_file": "/etc/fvca/update-ca.pem",
  "deadline_seconds": 1800
}
```

For an offline depot, use `{"transport":"local","path":"/mnt/fvca/depot"}` in the depot configuration. Keep the same trusted TUF metadata state when moving between HTTPS and a local copy of the same repository.

Prepare a private state directory owned by the intake account with mode `0700`. In the trusted selection JSON, supply `role`, `epoch`, the independently authorized `minimum_epoch`, `manifest_sha256`, and `max_release_bytes` for the total logical size of the selected set. Supply the initial trusted root from verified configuration, and keep its bytes stable when the client advances the repository's trusted root through TUF rotation.

```sh
umask 077
cargo vendor --locked --versioned-dirs --manifest-path release-client/Cargo.toml \
  "$PWD/build/release-client-vendor" > build/release-client-cargo.toml
# Run the build below in a Fedora Rust 1.100 environment with networking disabled.
cargo build --frozen --release --manifest-path release-client/Cargo.toml \
  --config build/release-client-cargo.toml
release-client/target/release/fvca-release-client trusted-root.json depot.json intake-state selection.json
```

`FVCA_RELEASE_STAGED` names the complete verified tuple under `intake-state/staged/MANIFEST_SHA256`. Treat staged artifacts as inputs to the role's boot and installation verifiers. On-node activation and an independently protected on-node security epoch remain release gates.

Run `tests/check-release-intake.py` with Python TUF 7.0.1 and securesystemslib 1.6.0 with crypto support. Supply `--client`, `--hypervisor`, `--vm-runtime`, `--guest` and a new `--output` directory on the same filesystem as the three disposable lab images. The fixture signs a test depot with ephemeral keys and exercises staging, expiry, role and epoch mismatches, artifact corruption, and persistent metadata and root rollback checks.

Use the same Python environment for `tests/check-release-https.py --client FILE --fixture INTAKE_TEST_OUTPUT --output NEW_DIRECTORY`. It serves the signed fixtures over loopback TLS and checks CA and server-name validation, proxy and redirect handling, size and time bounds, recovery from an interrupted transfer, and persisted rollback checks.

### Prepare a file-backed A/B slot

Use a private `0700` Btrfs slot store per role. To provision the initial boot tuple, append `--initialize-slots SLOT_STORE` to the intake command. This creates `slot-a` in an empty store and verifies the same slot on retry. Use the existing role boot verifier when booting the installed images.

For an update, obtain the active slot record from the trusted boot controller and hold its boot-selection lease during preparation. The record identifies the booted slot and its exact release manifest. For example, an active slot A uses `{"slot":"a","epoch":17,"manifest_sha256":"ACTIVE_MANIFEST_SHA256"}` with its actual digest. Keep the active release eligible under the independently authorized epoch floor until the new release has passed trial boot.

```sh
release-client/target/release/fvca-release-client trusted-root.json depot.json inbox next-release.json \
  --prepare-inactive /srv/fvca/hypervisor-slots active-slot.json
```

The coordinator verifies the active tuple, then invokes systemd-sysupdate 262.1 with a private alternate root and an exact source digest from the TUF intake. It verifies the installed manifest and every member again, flushes the tuple, and publishes the inactive slot with an atomic directory rename. An identical retry verifies the existing inactive tuple. The active slot remains the recovery path throughout preparation. A forced stop before publication may leave a private `.prepare-*` directory, which can be removed after the installer exits.

This file-backed preparation works with the current Hypervisor and Service Guest bundles in the lab. The offline GPT installer below handles an already provisioned Hypervisor disk. Protected epoch advancement remains a release gate. [systemd-sysupdate transfer definitions](https://www.freedesktop.org/software/systemd/man/latest/sysupdate.d.html)

`tests/check-release-slots.py` uses the same Python TUF environment. Supply two matched `--active-boot`/`--active-guest` and `--next-boot`/`--next-guest` pairs, their `--vm-runtime`, the `--client`, and a new Btrfs `--output` directory on the images' filesystem. The fixture verifies both complete slots after a transfer interruption and after retrying and replacing the inactive tuple.

### Install a Hypervisor release into an inactive GPT slot

Run the release client from an offline maintenance system with both NVMe namespaces unused. Keep the verified recovery slot selected in firmware during installation. The client uses `sfdisk`, `mcopy`, and `sbverify` on the maintenance system. On Fedora, `glibc-gconv-extra` supplies the FAT code-page support that `mcopy` needs. Stage the recovery release into the same private state directory before requesting the update. Use an immutable seven-partition `boot.raw` for each TUF release and keep its separate runtime and Guest bundle targets. The composer can emit this exact reference at initial provisioning with `--immutable-output` alongside the combined disk.

Use `fvca-release-client --inspect-hypervisor-gpt DISK 4096` to obtain each disk record from the reviewed provisioned layout. Record absolute NVMe device paths or private disposable disk-image paths. In this example the active release is epoch 17 and the selected candidate has a higher epoch. Use the Secure Boot certificate approved for the two UKIs.

```json
{
  "schema": "fvca-hypervisor-gpt-install-v1",
  "sector_size": 4096,
  "boot_certificate": "/etc/fvca/secure-boot.pem",
  "active_epoch": 17,
  "active_manifest_sha256": "RECOVERY_MANIFEST_SHA256",
  "active": {"path": "/dev/disk/by-id/ACTIVE_NVME", "gpt_sha256": "ACTIVE_GPT_SHA256"},
  "inactive": {"path": "/dev/disk/by-id/INACTIVE_NVME", "gpt_sha256": "INACTIVE_GPT_SHA256"}
}
```

```sh
release-client/target/release/fvca-release-client trusted-root.json depot.json inbox next-release.json \
  --write-inactive-gpt reviewed-disks.json
```

The candidate must name the inactive slot's existing UUIDs and fit its allocated partitions. The ESP must match its allocated size. The client checks that the packed runtime and Guest bytes agree with the TUF release members. With exclusive access to both disks, it verifies their reviewed GPT fingerprints and reads back the active recovery EFI loader and payloads before writing. On the inactive disk it clears and flushes the ESP, writes and verifies the six payloads, then installs and verifies the approved ESP. It clears unused capacity inside the payload partitions. Both GPTs and both encrypted Host data partitions are preserved. A repeat verifies an already installed image and can resume an interrupted installation. Boot trial and promotion use their separate authorizations. [Linux exclusive block-device opens](https://man7.org/linux/man-pages/man2/open.2.html) · [util-linux GPT verification](https://github.com/util-linux/util-linux/blob/master/disk-utils/sfdisk.8.adoc)

`tests/check-hypervisor-gpt-install.py` uses the TUF fixture environment to test the same operation on copies of two provisioned disks. Its inputs include both immutable release images, their runtime and Guest targets, and a different runtime for the mixed-release refusal check. Use an inactive image with a payload partition larger than the corresponding candidate partition to exercise tail clearing.

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

The readiness probe runs `qemu-img` from the composed `/usr` and exercises a diskless, networkless q35 VM through the private libvirt socket. It requires an sVirt MCS label, the dedicated QEMU UID, seccomp, no-new-privileges, zero effective capabilities, and a private mount namespace. The console prints `FVCA_LIBVIRT_LIFECYCLE_OK` after the VM starts, suspends, resumes, and stops. Production release authorization still requires independent approval.

### Boot a self-contained Hypervisor GPT slot

Use the Hypervisor initramfs from the native mkosi recipe and pass `--gpt-slot UUID` to `tools/compose-hypervisor.py` with the approved Host storage selection and Guest boot bundle. Use a distinct slot UUID for each boot disk, including disks carrying identical release bytes. The composer writes a new GPT image with its own FAT32 ESP, core, VM runtime and Guest boot capsule. It checks the installed partition identities and bytes before publishing the image. Install `dosfstools` on the builder. The GPT and ESP default to 4 KiB logical sectors, which matches the target NVMe drives. For a device with 512-byte logical sectors, pass `--gpt-sector-size 512` and use `--sector-size 512` during qualification.

The signed UKI names the slot's exact partition UUIDs and carries the core verity signature. During boot the runtime activator checks that all seven partitions share one disk and that the mounted verity root uses the approved core partition pair. It then activates the explicitly selected VM runtime and Guest capsule with dm-verity. The Hypervisor opens the separately provisioned encrypted Btrfs mirror after the slot check. [systemd verity device selection](https://www.freedesktop.org/software/systemd/man/latest/systemd-veritysetup-generator.html) · [systemd GPT image construction](https://www.freedesktop.org/software/systemd/man/latest/systemd-repart.html)

Create two disposable slot images and test them using the Secure Boot variable store and development Btrfs mirror below.

```sh
python3 tests/check-hypervisor-gpt-slots.py \
  --first build/slot-a.raw --second build/slot-b.raw --variables build/fvca-vars.fd \
  --lab build/host-storage-lab --output build/gpt-slot-checks
```

The test attaches the boot images as virtual NVMe devices with the selected logical sector size. Compose its inputs with a recovery UKI or provide a seeded Guest and the matching Host storage profile. The test selects each slot with both disks attached and rejects duplicate locators or a tuple split across the two disks.

### Provision both Hypervisor NVMe images

Prepare two authenticated LUKS2 members of the same Btrfs RAID1 pool and provide `cryptsetup` on the build workstation. For an isolated test, run `tests/storage-lab.sh --authenticated NEW_LAB GUEST_DATA_RAW` with the approved Guest data image. When composing each GPT slot, add `--host-data-disk` with that slot's prepared member image and use the same signed `--storage` policy for both UKIs. Give each slot a distinct UUID. The member input must be a quiesced regular image with one GPT LUKS2 partition. The input defaults to 512-byte GPT sectors, and `--host-data-sector-size 4096` selects a 4Kn input. The output defaults to 4Kn independently of the input geometry. Pass `--gpt-disk-bytes` with the target's measured capacity to place the backup GPT at the correct final sector. The image keeps the partition sizes of its inputs and leaves unused capacity unallocated.

The assembler checks the member's GPT and LUKS2 UUIDs, authenticated LUKS2 metadata, and selected TPM token when applicable. It appends the exact encrypted bytes alongside the seven immutable partitions and verifies all eight by readback before publishing a private image. With `--immutable-output` it saves the same seven verified partitions in a separate file for the TUF release. The slot test detects the integrated layout and boots with just the two NVMe images. It checks Guest readiness with each boot slot selected and refuses ordinary startup when a required mirror member is absent or duplicated.

Keep the combined images private. They contain the encrypted data from the provisioning inputs. Use them for initial provisioning or authorized recovery. Use the separately staged immutable release for offline updates. Qualification on the target physical NVMes remains a release gate. [systemd GPT partition definitions](https://www.freedesktop.org/software/systemd/man/latest/repart.d.html)

### Exercise a one-shot Hypervisor trial and record health

Choose a fresh transaction UUID and distinct slot UUIDs. The two ESP UUIDs are derived from their respective slot UUIDs and the name `esp` with UUIDv5. Compose the candidate first with `--boot-trial-candidate FILE` using the policy below and a VM runtime built with the trial health recorder. Select the same signed Guest boot bundle on both slots and use ordinary Guest startup for the candidate.

```text
FVCA-HYPERVISOR-TRIAL-CANDIDATE-1
transaction=TRANSACTION_UUID
stable=000a,STABLE_ESP_UUID
candidate=000b,CANDIDATE_ESP_UUID
```

Obtain the candidate ESP starting LBA and length with `sfdisk --json --sector-size 4096 build/slot-b.raw`. Hash exactly the bytes in that partition. Use the signed dm-verity root hashes of the candidate core, candidate VM runtime and Guest boot bundle. Compose the stable slot with `--boot-trial FILE` to sign the following authorization into its UKI.

```text
FVCA-HYPERVISOR-TRIAL-2
transaction=TRANSACTION_UUID
stable=000a,STABLE_ESP_UUID
candidate=000b,CANDIDATE_ESP_UUID
candidate_esp_sha256=CANDIDATE_ESP_SHA256
candidate_esp_bytes=CANDIDATE_ESP_LENGTH_IN_BYTES
candidate_core=CANDIDATE_CORE_VERITY_ROOT
candidate_runtime=CANDIDATE_VM_RUNTIME_VERITY_ROOT
guest_bundle=GUEST_BOOT_BUNDLE_VERITY_ROOT
```

Enroll two active UEFI boot entries with short-form GPT device paths to `\EFI\BOOT\BOOTX64.EFI` and put the stable entry first in `BootOrder`. The Hypervisor checks `BootCurrent`, both boot entries and the candidate ESP after opening the encrypted Btrfs mirror. After flushing the transaction record, it invokes a confined writer that exclusively creates `BootNext` at a fixed path. It flushes a second record only after verifying `BootNext` by reading it back. Firmware consumes `BootNext` before starting the candidate. The original boot order remains in effect on subsequent resets. [UEFI Boot Manager](https://uefi.org/specs/UEFI/2.10/03_Boot_Manager.html)

Before launching the candidate's Guest, the initramfs checks the recorded stable authorization against the candidate UKI selection, actual boot entry and verified core, runtime and Guest roots. This check accounts for EFI filesystem metadata writes during boot. The initramfs records the candidate boot ID on Btrfs. After the base and Guest startup checks pass, the recorder checks the running Guest through libvirt and pings its Guest agent. It then writes `boot-trials/TRANSACTION_UUID.healthy` to the encrypted mirror. The stable slot reads back a matching record on return. This record is local readiness evidence.

The Fedora KVM lab test uses `python3-virt-firmware` to seed the entries in a private OVMF variable store. Its successful trial, interrupted trial and tamper cases use separate copies of the variable store and both Btrfs members. Use the same signed storage profile on both input slots and seed the mirror with matching Guest data.

```sh
python3 tests/check-hypervisor-trial.py \
  --stable build/slot-a.raw --candidate build/slot-b.raw --variables build/fvca-vars.fd \
  --lab build/host-storage-lab --transaction TRANSACTION_UUID --output build/gpt-trial-checks
```

The test checks that changing a candidate ESP byte leaves the stable slot bootable, that a healthy candidate records its boot ID and runtime, and that cutting power before readiness yields no health record. It also selects the candidate without arming a trial and checks that it refuses to start the Guest. Each armed candidate attempt returns through the original stable order on the next boot.

### Promote an independently approved Hypervisor trial

Pass the same `--boot-promotion-public-key PUBLIC_KEY_PEM` when composing the stable and candidate slots. Use a dedicated Ed25519 authority and keep its private key off the appliance. After the trial, review the exact health receipt and the recovery release. Capture the candidate disk's installed ESP after the trial so the approval covers any firmware writes during the trial.

```sh
python3 tools/sign-hypervisor-promotion.py \
  --trial stable-trial.txt --health TRANSACTION_UUID.healthy \
  --candidate candidate-after-trial.raw --stable-core STABLE_CORE_VERITY_ROOT \
  --stable-runtime STABLE_VM_RUNTIME_VERITY_ROOT --sign-key promotion.key \
  --output TRANSACTION_UUID.promotion
```

Place the packet in `boot-trials` on the authorized Host Btrfs mirror as a private `0600` root-owned file through the maintenance path. Boot the stable slot normally with the approved stable and candidate as the first two EFI entries. The verifier checks that the candidate trial pinned the same promotion authority. It compares the signature, exact readiness receipt, running stable roots, and installed candidate ESP with the approval. It checks all three candidate dm-verity trees on the approved GPT partitions before flushing the signed intent and swapping the first two EFI entries. The stable slot becomes the second entry. Later boots of the promoted candidate validate the durable signed intent and the booted composition. [Linux efivarfs documentation](https://docs.kernel.org/filesystems/efivarfs.html)

If the write is interrupted after the intent is flushed, the original stable order or the approved candidate-first order can boot using its existing authorization. A fresh trial is required to attempt another promotion after a consumed intent leaves the stable order in place. Application-specific validation, protected epoch advancement, physical qualification, and automatic reset after a stalled trial remain separate release requirements.

Run `tests/check-hypervisor-promotion.py` against two fresh 4Kn slot images signed with a disposable promotion authority. Supply the stable trial file, the stable core and VM runtime root hashes, a signed-Guest seeded mirror from `tests/storage-lab.sh`, and separate Ed25519 private keys for the approved and incorrect signers. The test writes the packet only to disposable Btrfs copies. It checks rejection of an incorrect signer, a candidate-first order without a durable approval, and candidate media corruption. It also checks that the promoted candidate and the retained stable entry can both reach Guest readiness.

## Development Hypervisor storage

The Hypervisor assembler accepts `--storage tests/host-storage.conf` for the disposable storage fixture. The signed `FVCA-HOST-STORAGE-4` record fixes the protection and unlock modes, the GPT and LUKS2 UUID of each member, and the shared Btrfs filesystem UUID. The initramfs checks both partitions and their LUKS2 identities before prompting on the console, then verifies that each decrypted mapping is backed by its authorized partition on a separate disk.

Btrfs mirrors data, metadata and system chunks across the two decrypted devices. The gate checks the actual devices and allocation profiles before enabling read-write access at `/run/fvca/host-data`. The mount uses `nodev,nosuid,noexec`, and the filesystem root must be owned by root with mode `0700`. Ordinary boot requires both authorized members. Physical TPM qualification, policy for degraded boot, and the appliance recovery environment remain pending.

On a Fedora KVM test machine with `cryptsetup`, `btrfs-progs`, `e2fsprogs` and `cpio` installed, the fixture creates fresh file-backed disks. It tests single-member recovery without Btrfs log replay and replaces the missing device with a freshly encrypted mapping. A writable degraded mount can allocate SINGLE chunks. The fixture restores those chunks to RAID1 in the isolated repair guest, then verifies every profile and scrubs the restored pool. Build the Hypervisor as above with the fixture selection added to the assembler command, then run the integration checks against the signed disk and its matching runtime. To qualify boot after replacement, compose a second UKI with the fixture's `replacement-storage.conf` and provide its disk as `--replacement-disk`. [Btrfs recovery mount options](https://btrfs.readthedocs.io/en/latest/ch-mount-options.html)

```sh
tests/storage-lab.sh build/host-storage-lab
python3 tests/check-storage.py \
  --disk build/hypervisor-profile/fvca-dev-hypervisor.raw \
  --runtime build/vm-runtime/vm-runtime.raw \
  --variables build/fvca-vars.fd \
  --lab build/host-storage-lab --output build/host-storage-checks
```

### Authenticated Hypervisor storage candidate

Run `tests/storage-lab.sh --authenticated build/host-integrity-lab` to provision fresh disposable members with `cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --integrity hmac-sha256 --sector-size 4096`. Use `--storage build/host-integrity-lab/host-storage.conf` when composing the Hypervisor. The signed record selects `protection=luks2-xts-hmac-sha256`. Use the generated replacement policy to compose the separately authorized replacement image.

The initramfs disables udev filesystem probing on the storage mappings. It confirms that rule took effect, reads the active kernel tables, and verifies the AES-XTS and HMAC-SHA256 crypt target, the 32-byte tags, and journaled dm-integrity beneath both members before probing Btrfs. It checks that each stack ends at its selected physical partition and emits `FVCA_HOST_STORAGE_AUTHENTICATED` only once both stacks pass. The profile keeps discards disabled and prevents a same-UUID ordinary LUKS2 member from satisfying the authenticated selection. [Linux dm-integrity](https://docs.kernel.org/admin-guide/device-mapper/dm-integrity.html) · [Linux dm-crypt](https://docs.kernel.org/admin-guide/device-mapper/dm-crypt.html)

The disposable fixture flips ciphertext beneath each member's primary Btrfs superblock and requires both decrypted reads to fail with zero bytes returned. It cuts VM power after a flushed record and subsequent writes, then verifies the retained record and scrubs the remounted pool. It also exercises single-member recovery and replacement. Use the same `tests/check-storage.py` command with the authenticated lab and its signed images to check Secure Boot activation, rejection of the plain member, and boot with the replacement. Physical NVMe interruption and performance qualification, TPM enrollment with this profile, and protected rollback state remain release gates.

### Development TPM and PIN unlock

The TPM storage selection uses `unlock=tpm2-pin`, followed by `token_a=INDEX,SHA256` and `token_b=INDEX,SHA256` after the filesystem identity. Each digest covers the exact `cryptsetup token export` output from that member. Give the assembler the manifest with `--storage`, the exports with `--tpm-token-a` and `--tpm-token-b`, and a separate RSA signing key with `--pcr-key`. The assembler checks each enrollment's SHA-256 PCR bank, direct PCRs 7, 12 and 13, signed PCR 11, policy reference `fvca-host-storage`, and Argon2id-protected PIN. It signs PCR 11 only for the `enter-initrd` phase. The signed initramfs verifies a private copy of each LUKS2 header and uses that copy for the corresponding token-only unlock. [systemd-cryptenroll](https://www.freedesktop.org/software/systemd/man/262/systemd-cryptenroll.html)

In the disposable enrollment environment, use the target firmware and its Secure Boot keys. A measured systemd initramfs applies the `os-separator` event automatically. A minimal lab initramfs must apply that same event to PCRs 7, 12 and 13 before enrollment. Preserve the separate recovery credential. [systemd PCR phase and separator](https://www.freedesktop.org/software/systemd/man/262/systemd-pcrphase.service.html)

In the disposable enrollment guest, enroll the two LUKS2 partitions individually. Supply the fixture recovery key and the public half of the separate PCR signing key. The example exports the first token on each fresh fixture member.

```sh
for member in a b; do
  partition="/dev/vd${member}1"
  systemd-cryptenroll "$partition" --unlock-key-file=storage.key \
    --tpm2-device=/dev/tpmrm0 --tpm2-with-pin=yes \
    --tpm2-pcrs=7:sha256+12:sha256+13:sha256 --tpm2-public-key=pcr-public.pem \
    --tpm2-public-key-pcrs=11 --tpm2-public-key-policyref=fvca-host-storage
  cryptsetup token export --token-id=0 "$partition" > "token-${member}.json"
  sha256sum "token-${member}.json"
done
```

The lab check takes `--firmware` for the measured Secure Boot firmware, `--variables` for its enrolled variables, `--tpm-state` for the enrolled software TPM, and `--pin-file` for the disposable 24-hex-character PIN. It exercises the signed Hypervisor with the correct PIN, wrong PIN, unrelated TPM, extra measured command line, and absent TPM.

The Hypervisor initramfs omits systemd's stock NvPCR definitions. The storage PCR authority authorizes only LUKS2 unsealing. Future TPM-backed release state requires its own initialization policy.

The shared SELinux policy switches Fedora's PCR measurement domain to enforcing. Both the initramfs and the core verify the domain against the policy loaded in the kernel. On a measured boot, systemd prepares the root-only, separately labeled log at `/run/log/systemd/tpm2-measure.log` before the first userspace PCR measurements.

## Development Service Guest storage

The Service Guest uses one ordinary virtual Btrfs data partition with data SINGLE and metadata and system DUP. Its signed development UKI contains the selected partition and filesystem UUIDs from `tests/guest-storage.conf`. The boot gate checks the device and its allocation profiles before mounting at `/run/fvca/guest-data` with `nodev,nosuid,noexec`. Both roles keep Btrfs CoW and checksums enabled. The signed EROFS image provides the verified OS root for both roles.

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

## Development Service Guest direct boot

The direct-boot bundle contains the kernel and initramfs extracted from its signed UKI, the exact command line, the fixed KVM machine definition, and the verified core and OCI runtime disks. A separate release authority signs the file digests and both verity root hashes. The supplied machine definition has read-only release disks, one writable raw data disk, and no mutable firmware or vTPM state. [QEMU direct Linux boot](https://www.qemu.org/docs/master/system/linuxboot.html)

The Guest compares its effective kernel command line to the embedded signed copy. Before starting systemd it checks kernel lockdown and module signature enforcement, enrolls the approved verity certificates, seals their keyring, and disables further module loading. The root verity setup uses the verified signature embedded in the initramfs. The direct KVM lab verifies the release signature and bound files off-node before launch.

With the core, OCI runtime and initramfs built as above, use a separate development release key.

```sh
umask 077
openssl req -x509 -newkey rsa:3072 -noenc -days 30 \
  -subj '/CN=FVCA development Guest release/' \
  -keyout build/guest-release.key -out build/guest-release.crt
python3 tools/compose-service-guest.py \
  --core build/service-guest-storage/fvca-dev-service-guest.raw \
  --runtime build/oci-runtime/oci-runtime.raw \
  --initrd build/service-guest-runtime-initrd/initrd.cpio.zst \
  --boot-certificate mkosi.crt --boot-key mkosi.key \
  --runtime-certificate build/oci-runtime-signing.crt \
  --release-key build/guest-release.key --release-certificate build/guest-release.crt \
  --direct-boot build/service-guest-direct
python3 tests/check-storage.py --guest --direct-boot build/service-guest-direct \
  --release-certificate build/guest-release.crt --lab build/host-storage-lab \
  --output build/service-guest-direct-checks
```

### Launch from the Hypervisor

Pack the Guest release into a read-only verity disk. Hypervisor composition verifies the Guest release with its own pinned signer, verifies the bundle disk under the Host verity authority, and records the exact bundle root and file digests in the signed Hypervisor UKI.

```sh
python3 tools/pack-guest-boot.py --bundle build/service-guest-direct \
  --release-certificate build/guest-release.crt \
  --verity-key mkosi.key --verity-certificate mkosi.crt \
  --output build/guest-boot.raw
python3 tools/compose-hypervisor.py \
  --core build/fvca-dev-base.raw --runtime build/vm-runtime/vm-runtime.raw \
  --initrd build/hypervisor-profile/initrd.cpio.zst \
  --boot-certificate mkosi.crt --boot-key mkosi.key \
  --runtime-certificate build/vm-runtime-signing.crt \
  --storage tests/host-storage.conf --guest-boot build/guest-boot.raw \
  --guest-release-certificate build/guest-release.crt \
  --output build/hypervisor-profile/fvca-dev-hypervisor-with-guest.raw
```

After unlocking both Host members, the Hypervisor mounts the selected Guest boot disk read-only and checks its authorized bytes before creating the VM through private libvirt. The registered VM uses a single Btrfs subvolume at `/run/fvca/host-data/vms/service-guest` with one private writable `data.raw`. The launcher checks the Btrfs CoW and data-checksum flags on the directory and disk. It exposes one disk attachment and keeps the pool directory private. The runtime checks that the libvirt management domain and the QEMU sVirt domain are enforcing in the loaded SELinux policy.

The Hypervisor verifies that the Guest agent answers a ping before reporting readiness. The agent runs in the Guest's SELinux policy on a fixed virtio-serial channel. Its verified configuration allows synchronization, ping, shutdown, freeze status, mount-list freeze, and thaw RPCs. SELinux confines freeze and thaw to the Btrfs mount at `/run/fvca/guest-data`. Shutdown requires a normal libvirt lifecycle event and confirmation that QEMU exited. The Hypervisor retains the disk attachment while the VM may still be using it. [QEMU Guest Agent configuration](https://www.qemu.org/docs/master/interop/qemu-ga.html) · [libvirt domain lifecycle events](https://libvirt.org/html/libvirt-libvirt-domain.html#virDomainEventStoppedDetailType)

`tests/storage-lab.sh` provisions that layout on disposable disks. On a KVM test machine that exposes Intel VMX to the outer Hypervisor VM, run the nested qualification with `--nested-guest`. The Host reports `FVCA_SERVICE_GUEST_READY` after the Guest reports its direct-boot policy, exact OCI runtime, and verified root readiness.

```sh
python3 tests/check-storage.py \
  --disk build/hypervisor-profile/fvca-dev-hypervisor-with-guest.raw \
  --runtime build/vm-runtime/vm-runtime.raw --variables build/fvca-vars.fd \
  --lab build/host-storage-lab --nested-guest build/guest-boot.raw \
  --output build/hypervisor-nested-guest-checks
```

For a disposable shutdown test, use `tests/nested-guest-shutdown-initrd.sh HYPERVISOR_INITRAMFS NEW_INITRAMFS` and pass the resulting archive to `compose-hypervisor.py --initrd`. Run the nested check with `--nested-guest-shutdown`. For a Guest that requires an authorized workload, supply its prepared Guest data disk as the second argument to `tests/storage-lab.sh`. The test waits for the orderly stop and checks that the raw disk attachment was released.

### Stopped Service Guest captures

Start `fvca-capture-stopped@CAPTURE_UUID.service` as a privileged Hypervisor operator using a fresh capture UUID. The coordinator holds a lease against a new Guest start, checks Btrfs mirror headroom for a full disk rewrite and retained release files, and saves the exact authorized Guest release once per bundle digest. It requests an orderly stop if the Guest is running. A Guest that was already stopped needs a matching receipt from its last verified shutdown.

The coordinator syncs the raw disk, writes the capture plan, and creates a read-only snapshot outside the Guest subvolume. It checks the Btrfs parent and snapshot IDs and publishes the sealed record before restarting a previously running Guest. It hashes the stable snapshot after restart and writes `CAPTURE_COMPLETE` only after validating the captured disk and retained release. The records are under `/run/fvca/host-data/captures/sets/CAPTURE_UUID`. Reusing the same UUID verifies and finalizes an existing snapshot. The capture remains available while the Guest runs.

For the nested capture test, prepare the shutdown fixture with the additional `capture` argument and run the nested checks with `--nested-guest-capture`. Use `tests/storage-lab.sh` with the prepared workload disk and a third argument of `2684354560` bytes per disposable mirror member. The test checks capture before restart, recovery of a sealed capture without its final manifest, and capture of a Guest left stopped.

### Live Service Guest captures

Start `fvca-capture-live@CAPTURE_UUID.service` as a privileged Hypervisor operator while the approved Guest is running and thawed. The coordinator checks the authorized release and running VM identity, reserves Btrfs space, and records the capture intent. The signed Guest definition ends the QEMU process on Guest reboot so recovery stays tied to the captured instance. The worker freezes the Guest Btrfs filesystem, pauses the VM through a manual disk-only snapshot, verifies that the writable disk is inactive, and seals a read-only Btrfs capture. The manifest records filesystem consistency.

The worker has a 20-second window. A separate recovery unit resumes the original VM, reactivates the disk through libvirt, thaws the filesystem, and checks the Guest agent. A systemd timer starts recovery at the deadline even if the capture service is still running. Unresolved recovery keeps the Guest operation lease visible at `/run/fvca/guest-live-active`. An operator can retry recovery with `fvca-live-recover@CAPTURE_UUID.service`. A blocked kernel or provider call can delay recovery. [libvirt manual storage snapshots](https://libvirt.org/formatsnapshot.html)

The coordinator validates and hashes the read-only snapshot after recovery. Running the capture service again with the same UUID can finalize an acknowledged seal. The nested test uses `tests/nested-guest-shutdown-initrd.sh` with the `live` argument and `tests/check-storage.py --nested-guest-live-capture` with the same disposable Btrfs lab as the stopped capture test.

### Cold-restore the registered Service Guest

Stop `fvca-service-guest.service` and start `fvca-restore-guest@CAPTURE_UUID.RESTORE_UUID.service` with a finalized capture UUID and a fresh restore UUID. The restore coordinator verifies the manifest, retained release, and sealed disk digest. It stages a writable Btrfs reflink with fresh file ownership, then atomically installs it in the registered VM slot. If the slot had a previous disk, the coordinator retains that subvolume under `/run/fvca/host-data/captures/restores/RESTORE_UUID/branch`.

The isolated Guest cold-boots with the currently authorized Guest bundle. The coordinator publishes a verified receipt after the ordinary Guest readiness check and confirms that the running instance owns the restored disk attachment. A rejected trial boot puts the previous volume back and leaves the Guest stopped. Reuse the same restore UUID to reconcile an interrupted transaction. The terminal receipt makes a duplicate request idempotent.

The nested restore test uses the `restore` fixture and `tests/check-storage.py --nested-guest-restore` with the stopped capture lab.

### Encrypted Service Guest backups

Provision a restic format 2 repository in a dedicated S3 bucket or prefix. Give the Hypervisor a repository password and S3 credentials scoped to that repository. Place them under `/run/fvca/host-data/backup-credentials` on the unlocked encrypted Host Btrfs pool. Set the directory to root:root mode `0700` and the `repository-password` and `s3-credentials` files to root:root mode `0400` or `0600`. The credentials file uses the AWS shared credentials format with a `[default]` profile, `aws_access_key_id`, `aws_secret_access_key`, and an optional `aws_session_token`, in that order. Keep an independently recoverable copy of the repository credentials with the recovery material.

Supply `--backup-policy` and `--backup-ca` when composing the Hypervisor for an authorized Guest. The CA file is a PEM trust bundle. The Hypervisor needs a route to the selected endpoint, whose certificate must cover its literal IP address. Use the repository ID from `restic cat config` in the policy. An empty `prefix=` selects the bucket root.

```text
FVCA-VM-BACKUP-1
endpoint=192.0.2.10:443
bucket=fvca-recovery
prefix=service-guest
region=us-east-1
repository=REPLACE_WITH_64_LOWERCASE_HEX_DIGITS
```

Start `fvca-backup-live@CAPTURE_UUID.service` to capture a running Guest or `fvca-backup-stopped@CAPTURE_UUID.service` to use an orderly stop. Upload begins after Guest recovery. The isolated worker authenticates the authorized repository, reads back the exact snapshot inventory and manifest, then returns the full snapshot ID. The coordinator records the result in `backup-REPOSITORY_ID` beside the finalized capture manifest. After an upload failure, retry with the same capture UUID and the same capture mode to reuse the sealed disk. The pending record identifies the sealed disk and its SHA-256 digest.

### Schedule Service Guest backups

Add `--backup-job FILE` when composing the signed ordinary Hypervisor UKI. The job uses live capture, the repository already registered by `--backup-policy`, and the local capture budget selected by `--retention-policy`. Choose the maximum recovery-point age and the interval to allow for detection, capture and upload time.

```text
FVCA-BACKUP-JOB-1
repository=REPLACE_WITH_64_LOWERCASE_HEX_DIGITS
interval_seconds=21600
retry_seconds=300
max_data_loss_seconds=28800
max_quiesce_seconds=15
restore_objective_seconds=14400
```

The signed quiescence budget sets when the live capture worker is fenced and the independent resume/thaw watchdog intervenes. A blocked kernel or provider call can extend recovery time. The restore objective is recorded with job status for comparison with restore qualification. [systemd timer options](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html)

`fvca-backup-health.timer` dispatches due work after boot and checks status every `retry_seconds` while the appliance is running. A successful scheduled upload sets the next interval using the capture time. Read `FVCA_BACKUP_JOB_STATUS` for the last verified scheduled snapshot, its age and any pending capture. Route `FVCA_BACKUP_JOB_ALERT` and failures of `fvca-backup-health.service` or `fvca-backup-scheduled.service` to monitoring. The health check reports a missed recovery point when the last verified scheduled capture is absent or older than `max_data_loss_seconds`, including during an upload. Off-node pack verification and restore qualification report their own outcomes.

The job saves its pending UUID on the encrypted Hypervisor Btrfs mirror before capture. A retry after reboot reuses the acknowledged sealed snapshot. The launcher journals the attached disk's Btrfs and inode identities before handing it to libvirt. After an abrupt shutdown it reclaims that exact disk once the previous VM, PID file and bind mount are gone. Clean-stop receipts still require an orderly Guest shutdown.

If an interrupted attempt ended before creating any snapshot and the Guest operation lease is clear, the job records that attempt as abandoned and allocates a new UUID. An unacknowledged snapshot is preserved for reconciliation. A verified S3 receipt remains eligible for age reporting after local expiry.

### Inventory and expire local captures

Start `fvca-capture-list.service` to log the local capture catalog or `fvca-capture-inspect@CAPTURE_UUID.service` to inspect one capture. Finalized entries report capture time, disk SHA-256, Btrfs snapshot UUID and pending backup status. Expired entries retain their manifest and backup receipt for reference.

To enable expiry, add `--retention-policy FILE` when composing the signed Hypervisor UKI. Use the repository ID already authorized in its backup policy. The optional `protect=` field accepts one capture UUID per line.

```text
FVCA-LOCAL-RETENTION-1
repository=REPLACE_WITH_64_LOWERCASE_HEX_DIGITS
keep_min=2
keep_max=7
max_age_seconds=604800
min_data_bytes=536870912
min_metadata_bytes=67108864
```

`fvca-capture-retention.timer` runs the policy periodically. Start `fvca-capture-retention.service` to run a pass immediately or `fvca-capture-expire@CAPTURE_UUID.service` to apply the same eligibility rules to one capture. A capture can expire when it reaches the age limit, the local count exceeds the target, or Btrfs falls below the required allocation headroom. The newest `keep_min` finalized local snapshots, protected UUIDs, unfinished restores, pending backups and captures without a matching backup receipt are kept. Those protections can leave the count above `keep_max`.

Headroom is measured from allocated data and metadata space and the unallocated capacity available on both mirror members. A pass can expire one capture solely because of space pressure. Later passes measure again as Btrfs reclaims unreferenced extents. Expiry durably journals the local snapshot removal so an interrupted pass can finish on retry. The capture UUID stays retired and its S3 backup remains available for an authorized recovery.

### Recover a Service Guest from S3

Provision and authorize a new encrypted Host Btrfs mirror. Authorize the Guest release that should boot on the recovery Hypervisor. Fence the source appliance before reusing its Guest identity. Use an independently retained receipt and manifest to approve the exact recovery set. Obtain the total logical byte count by summing the regular-file sizes in `restic ls --json FULL_SNAPSHOT_ID`. Include the raw disk, manifest, and all release members in that count.

Compose the recovery Hypervisor with the repository policy and CA above plus `--restore-authorization FILE`. Set the fields in this format using the independently retained records.

```text
FVCA-S3-RESTORE-1
identity=source-fenced
capture=CAPTURE_UUID
restore=NEW_RESTORE_UUID
repository=REPOSITORY_ID
snapshot=FULL_SNAPSHOT_ID
manifest_sha256=SHA256_OF_FINALIZED_MANIFEST
disk_sha256=SHA256_OF_RAW_GUEST_DISK
disk_bytes=RAW_GUEST_DISK_BYTES
total_bytes=TOTAL_RECOVERY_SET_BYTES
```

Place the repository password and a dedicated read-only S3 key in `/run/fvca/host-data/restore-credentials`, with the same filenames and ownership modes as the backup credentials. Pause repository maintenance during the recovery. The recovery worker uses read-only S3 operations, including snapshot listing and retrieval. The recovery UKI suppresses automatic Guest startup.

Start `fvca-restore-s3@CAPTURE_UUID.NEW_RESTORE_UUID.service`. The worker fetches the authorized snapshot into isolated staging and checks the manifest against its approved digest before downloading the large files. The coordinator verifies the complete release inventory and disk digest, then installs the disk through the cold-restore transaction. The isolated Guest boots with the release authorized by the recovery UKI. Reuse the same instance to reconcile an interrupted restore. Check the `verified` receipt in `/run/fvca/host-data/captures/restores/NEW_RESTORE_UUID` before authorizing service exposure.

### Verify and retain S3 recovery points off the appliance

Provision separate S3 identities for routine upload, read-only restore, off-node audit and off-node maintenance. Generate an IAM identity policy for each role using `python3 tools/s3-repository-iam.py --destination FILE --ca FILE ROLE`. Attach only the generated policy to each role. The upload identity can clean up restic locks. Snapshot, index and data deletion require the maintenance identity. The audit identity uses exclusive restic locks during a pack check. Keep maintenance credentials outside the appliance and pause read-only recovery during maintenance. Lab qualification used RustFS 1.0.0-rc.3 and restic 0.19.1. Qualify permissions on the selected endpoint. Object PUT can still replace an existing key. [IAM policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html) · [restic retention](https://restic.readthedocs.io/en/v0.19.1/060_forget.html)

On the maintenance machine, independently retain each `backup-REPOSITORY_ID` receipt and its `manifest` from a finalized Host capture. Authenticate the export through a trusted channel and keep it outside the S3 writer's control. Use `maintain-s3-repository.py ... enroll --receipt FILE --manifest FILE` to compare the exact stored manifest with this copy and persist it in the off-node SQLite ledger. Keep a protected, independent backup of the ledger. Repository entries without enrolled receipts never count toward the retention floor or qualify for expiry.

Create a JSON policy with the exact SHA-256 digests of the registered destination policy, trust bundle and restic executable. `protect` contains full, independently enrolled restic snapshot IDs. Sign the policy with the separate maintenance authority and pin its certificate in the maintenance account's configuration.

```json
{
  "schema": 1,
  "destination_sha256": "SHA256_OF_BACKUP_POLICY",
  "ca_sha256": "SHA256_OF_ENDPOINT_CA",
  "restic_sha256": "SHA256_OF_RESTIC_EXECUTABLE",
  "keep_min": 3,
  "max_expire": 8,
  "expire_after_seconds": 2592000,
  "max_backup_age_seconds": 86400,
  "bandwidth_kib": 32768,
  "operation_timeout_seconds": 43200,
  "protect": []
}
```

```sh
openssl cms -sign -binary -noattr -nocerts -outform DER \
  -signer maintenance.crt -inkey maintenance.key -in retention.json -out retention.p7s

audit=(python3 /opt/fvca/tools/maintain-s3-repository.py
  --policy /etc/fvca/retention.json --signature /etc/fvca/retention.p7s
  --authority /etc/fvca/maintenance.crt --destination /etc/fvca/destination.conf
  --ca /etc/fvca/s3-ca.pem --restic /usr/bin/restic --state /var/lib/fvca-s3
  --credentials /run/fvca-s3-audit)
"${audit[@]}" enroll --receipt ./verified-backup-receipt --manifest ./verified-capture-manifest
"${audit[@]}" verify
"${audit[@]}" retain
```

Run all commands as the off-node `fvca-s3` service account against the same private `0700` state directory. Credential directories use mode `0700` and contain private `repository-password` and `s3-credentials` files with the same formats as the appliance. The example service and daily timer in `ops/s3/` use `/etc/fvca/s3-audit` and `/var/lib/fvca-s3`. Configure monitoring for nonzero exits and missed runs. `verify` reads every pack and logs the coverage separately from recovery-point age and receipt inventory. Keep restore-drill logs separately. A full pack check downloads the repository's data, so set bandwidth and time limits to fit the job window. [restic repository integrity checks](https://restic.readthedocs.io/en/v0.19.1/045_working_with_repos.html)

`retain` previews eligible IDs using the original capture times in the ledger. For an authorized retention run, select the off-node maintenance credentials and run `retain --apply`. The tool requires the approved minimum of known recovery points and a fresh capture, verifies pack integrity, journals selected IDs, then calls restic forget and prune. A retry resumes the journaled set. Maintenance stops if an active snapshot disappears or a retired ID reappears. Schedule retention separately from independent copies and protect the full dependency set of any off-node copy.

### Keep an independent offline copy of a VM recovery point

On an off-node Fedora amd64 machine, mount operator-controlled Btrfs archive media. Give the archive account a private `0700` directory on the media with private `repository` and `receipts` subdirectories. Initialize `repository` as a fresh restic format 2 repository with its own strong password. Keep that password and a copy of the resulting archive receipts with independent recovery material. Keep the archive media and its credentials outside the appliance and S3 administration environments.

Add `"offline_archive": {"btrfs_uuid": "BTRFS_FILESYSTEM_UUID", "repository": "ARCHIVE_REPOSITORY_ID"}` to the signed maintenance policy. Obtain the filesystem UUID from the mounted Btrfs volume and the repository ID from `restic cat config`. Use the read-only `restore` S3 identity during the archive run. The archive command shares the receipt ledger lock with maintenance. Pause any source pruning or repacking operated outside that ledger while the read-only copy runs.

```sh
restic --repo /mnt/fvca-archive/repository --password-file /run/fvca-archive/password \
  init --repository-version 2

python3 /opt/fvca/tools/maintain-s3-repository.py \
  --policy /etc/fvca/retention.json --signature /etc/fvca/retention.p7s \
  --authority /etc/fvca/maintenance.crt --destination /etc/fvca/destination.conf \
  --ca /etc/fvca/s3-ca.pem --restic /usr/bin/restic --state /var/lib/fvca-s3 \
  --credentials /run/fvca-s3-read-only archive --snapshot "$source_snapshot" \
  --archive /mnt/fvca-archive --archive-password /run/fvca-archive/password
```

Archive each point by its full enrolled snapshot ID and record `FVCA_OFFLINE_ARCHIVED` in the off-node audit log. Restic re-encrypts the snapshot and every needed object, including data shared with older points. Publication requires a matching enrolled manifest, source and archive tree IDs, a full archive pack check, and a durable `receipts/SOURCE_SNAPSHOT_ID.json`. A retry of the same point reuses the existing copy and checks its receipt. Unmount and disconnect the media after a successful copy. Choose how often to attach and copy it according to the approved recovery-point age. Primary `retain --apply` has no archive deletion path. Manage archive capacity and any retirement under separate operator control using repository-aware maintenance. [restic snapshot copy and repository checks](https://restic.readthedocs.io/en/v0.19.1/045_working_with_repos.html)

During recovery, verify the media's repository ID and select the exact archive snapshot from the independently retained receipt. Run `restic check --read-data` on the offline repository and compare `restic dump ARCHIVE_SNAPSHOT_ID /manifest` with the receipt's manifest and SHA-256. To use the Hypervisor's [S3 recovery procedure](#recover-a-service-guest-from-s3), initialize a fresh isolated HTTPS S3 repository with new credentials and a new repository password. Use the installed restic executable with the new destination's approved CA and S3 options to `copy --from-repo local:/mnt/fvca-archive/repository --from-password-file FILE -- ARCHIVE_SNAPSHOT_ID` into that repository. Select the new full snapshot ID by the exact `original` (the primary source snapshot ID) and `tree` from the offline receipt in `restic snapshots --json`. Require one match and check the manifest digest again. Use the new repository and snapshot IDs plus the retained capture UUID and manifest/disk digests for the signed recovery authorization. Use an isolated Guest trial boot and check the application before restoring service exposure.

S3 Object Lock and provider version recovery require separate qualification.

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

## Guest workload launch

The Guest generates a private Quadlet from the authorized entrypoint, arguments, environment, health check, signal, identity and volume destinations. It starts the generated service only after systemd confirms the expected fragment and permitted OS defaults. Podman uses the verified rootfs read-only, with no network, no added capabilities, and the approved UID/GID mapping. The workload service applies the signed memory, CPU and PID budgets and waits for the approved health check before reporting ready. Each start or restart also requires an unexpired approval and the active verity mount. [Podman Quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)

The Guest keeps each declared persistent volume on Btrfs under `/run/fvca/guest-data/payload/<service>/<digest>`, where `digest` is the SHA-256 of the container mount destination. It creates missing volumes with the mapped workload owner and rejects ownership mismatches on existing data. The container receives only its declared volumes, with `nodev,nosuid,noexec` and a private SELinux label. Podman keeps the container log in volatile storage and caps its size.

For Stalwart lifecycle qualification, run `tests/stalwart-lifecycle-initrd.sh` with the development OCI initramfs and a new output file. Use that initramfs when composing the disposable Guest, then add `--stalwart-lifecycle` to the `tests/check-storage.py --workload` invocation. The fixture checks the health endpoint, UID/GID, SELinux label, resource settings, Btrfs file persistence across restart, and clean stop. Stalwart runs in its offline bootstrap mode. Controller-backed freshness and protected updates remain pending. [Stalwart bootstrap mode](https://stalw.art/docs/configuration/bootstrap-mode/)

### Configured Stalwart mail fixture

With the approved OCI image staged locally by digest, run `python3 tests/stalwart-mail-lab.py build/stalwart-mail-lab`. The disposable server uses an embedded SQLite store and binds to its container loopback. The fixture provisions a test account, submits a synthetic message over authenticated SMTP with pinned TLS, and records the exact bytes retrieved through IMAP with the same certificate pin. [Stalwart declarative deployment](https://stalw.art/docs/configuration/declarative-deployments/) · [Stalwart certificates](https://stalw.art/docs/server/tls/certificates/)

Pass `build/stalwart-mail-lab` as the fourth argument to `tests/workload-data-lab.sh` to seed the two signed Stalwart volume mappings on the Guest Btrfs disk. Run `bash tests/stalwart-mail-initrd.sh GUEST_INITRAMFS NEW_INITRAMFS build/stalwart-mail-lab`, then compose the disposable Guest with `NEW_INITRAMFS`. The fixture initramfs contains a synthetic mailbox credential. Use `--workload --stalwart-mail` with `tests/check-storage.py` to verify that the exact message is retrieved before Guest readiness. The workload image alteration check also runs.

To exercise S3 recovery, use the configured Guest and seeded disk in the stopped-backup procedure. Authorize that snapshot on a fresh encrypted Host Btrfs mirror, with the same signed Guest fixture. The restore receipt then requires the recovered Stalwart account and TLS configuration to serve the same message before Guest readiness. The nested KVM test exercised this path against a disposable Garage repository.

## Independent Stalwart application recovery

The off-node `fvca-stalwart-backup` tool creates an application-only recovery point from an approved clean-stopped VM capture. It verifies the capture manifest and complete raw disk digest, checks the Guest Btrfs partition and its checksums, and extracts the two approved Stalwart volumes. SQLite's backup API consolidates the database and its WAL into a standalone file. The application point contains that database, the approved configuration files and an inventory of their hashes. The Guest stays networkless during the workflow. [Stalwart backup procedure](https://stalw.art/docs/management/maintenance/backup/) · [SQLite backup API](https://sqlite.org/backup.html)

This profile covers the pinned single-node Stalwart workload with local SQLite and the Default blob store. Confirm that profile and account for each dependent file before approving a source. The signed configuration list includes `config.json` and any local certificate or key files the database references. Keep the temporary working directory and the restored configuration on independently protected storage. Use a separate restic format 2 application repository, repository secret and S3 identities. Keep the read-only recovery credentials and the application receipt independently of the VM copy.

Build the off-node tool using the workload crate's locked dependencies. Install Fedora's `btrfs-progs`, `util-linux` and SQLite CLI on the off-node worker. Supply the independently retained VM manifest and its matching raw disk using the selected stopped S3 backup or an equivalent verified export.

```sh
cargo build --release --locked --manifest-path workload-admission/Cargo.toml --bin fvca-stalwart-backup
openssl cms -sign -binary -noattr -nocerts -outform DER \
  -signer application-authority.crt -inkey application-authority.key \
  -in create.json -out create.p7s
fvca-stalwart-backup create.json create.p7s application-authority.crt ./writer \
  /usr/bin/restic s3-ca.pem ./private-work create data.raw vm-manifest application-receipt.json
```

The signed JSON has `schema` set to `fvca-stalwart-sqlite-inline-v1`. Its `endpoint` has `address` as a literal IP and port, `bucket`, `prefix`, `region`, the full `repository` ID, and `ca_sha256` and `restic_sha256` digests of the selected files. Set `timeout_seconds`, `bandwidth_kib` and `max_application_bytes` for the off-node worker. Under `operation`, set `action` to `create`, give the Guest `partition` and `filesystem` UUIDs, and list the exact `configuration` basenames. Its `source` object contains `vm_repository`, `vm_snapshot`, `vm_manifest_sha256` and `deployment_sha256`, all full lowercase SHA-256 values. Use the SHA-256 of the approved workload's exact `deployment.json`. Credential directories must be private and contain `repository-password` and `s3-credentials` as in the Hypervisor workflow.

For recovery, sign a policy with the same approved repository and an `operation` containing `action` set to `recover` plus the exact `snapshot`, `manifest_sha256` and `deployment_sha256` from the independently retained application receipt. Run with the dedicated read-only identity. Place the work and destination directories on the same protected filesystem so publication can use an atomic rename. The tool authenticates the manifest, verifies every member and checks SQLite integrity before publishing `NEW_DESTINATION/application`. Stage its `config` and `data` directories into the two approved Btrfs volume mappings of a fresh Guest with the current authorized workload and mapped ownership. Verify the application in isolation before exposing service endpoints.

```sh
fvca-stalwart-backup recover.json recover.p7s application-authority.crt ./reader \
  /usr/bin/restic s3-ca.pem ./private-work recover NEW_DESTINATION
```
