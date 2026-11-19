# Fedora Verified Compute Appliance

The first implementation milestone is a shared x86-64 development boot image for the VM-only Hypervisor and OCI Service Guest described in FVCA design v0.4.3. The Fedora 45 mkosi build produces a disk with a signed Unified Kernel Image (UKI), a read-only EROFS root, a dm-verity hash tree, and a detached root hash signature in its own GPT partition. The UKI embeds the expected root hash and execution policy. A Rust initramfs entrypoint loads dm-verity with signature enforcement before systemd attaches the global BPF execution policy. The kernel verifies the detached signature during root activation. Systemd closes the initramfs trust window after switch-root. [systemd execution policy](https://www.freedesktop.org/software/systemd/man/262/systemd-system.conf.html#RestrictFileSystemAccess=)

The image uses a boot-status target and volatile `/var`. It disables automatic extension and additional GPT partition discovery. Build workers run Fedora's package scripts before removing shells, login tools and maintenance hooks from the base and initramfs. Both trees must pass an audit for prohibited commands, executable scripts, setuid/setgid files and file capabilities. Emergency and rescue targets report `FVCA_BOOT_FAILED` on the console. The execution policy, SELinux domains and allocator still need qualification for role runtimes, extensions and workload roots. TPM attestation, release authorization and persistent storage remain pending.

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
