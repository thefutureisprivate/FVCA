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

Boot `build/service-guest-storage/fvca-dev-service-guest.raw` with the common QEMU command and attach the fixture as a second drive with `-drive if=virtio,format=raw,snapshot=on,file=build/host-storage-lab/guest-data.raw`. The console reports `FVCA_GUEST_DATA_ACTIVE` before readiness. The Service Guest OCI runtime and workload qualification are separate work.
