# Fedora Verified Compute Appliance

The FVCA design v0.4.5 defines a VM-only Hypervisor and an OCI Service Guest. Both development roles share an x86-64 image recipe. The Fedora 45 mkosi build produces a disk with a signed Unified Kernel Image (UKI), a read-only EROFS root, a dm-verity hash tree, and a detached root hash signature in its own GPT partition. The UKI embeds the expected root hash and execution policy. A Rust initramfs entrypoint loads dm-verity with signature enforcement before systemd attaches the global BPF execution policy. The kernel verifies the detached signature during root activation. Systemd closes the initramfs trust window after switch-root. [systemd execution policy](https://www.freedesktop.org/software/systemd/man/262/systemd-system.conf.html#RestrictFileSystemAccess=)

The image uses a boot-status target and volatile `/var`. It disables automatic extension and additional GPT partition discovery. Build workers run Fedora's package scripts before removing shells, login tools and maintenance hooks from the base and initramfs. Both trees must pass an audit for prohibited commands, executable scripts, setuid/setgid files and file capabilities. Emergency and rescue targets report `FVCA_BOOT_FAILED` on the console. Both roles use Btrfs for mutable data. Physical TPM qualification and production release approval remain pending.

The design draws on AOS's use of signed UKIs and integrity-protected disk images. [Amutable Foundations technical overview](https://amutable.com/blog/amutable-foundations-technical-overview)

## Build and verify

Use a Fedora 45 x86-64 build machine or disposable VM. Install `cargo`, `mkosi`, `mkosi-system-deps`, `systemd-ukify`, `sbsigntools`, `mtools`, `openssl`, `util-linux-core`, `erofs-utils`, and `veritysetup` on the builder. The development recipe uses the Fedora release and updates repositories with RPM signature verification. The build overlays pin the Rust, Cargo and GCC packages and build the local Rust crates with `cargo --frozen` and networking disabled. The two package manifests record the resolved OS packages. Release builds will need pinned package inputs throughout.

```sh
umask 077
./tools/fetch-allocator.sh
cargo vendor --locked --versioned-dirs --manifest-path uutils/Cargo.toml build/uutils-vendor/sources
mkosi genkey  # First build only. Keep mkosi.key private.
mkosi build
(cd build && sha256sum -c fvca-dev-base.SHA256SUMS)
python3 tools/verify-base.py build/fvca-dev-base.raw mkosi.crt
```

The QEMU procedure uses one enrolled development certificate for both signing purposes. Production signer separation remains pending. The off-node verifier accepts a separate root-signing certificate with `--verity-certificate`. It reads the policy in the signed UKI and verifies the detached signature and dm-verity data from the actual disk image. The disk, split UKI, root hash and package manifests are in `build/`.

The package manifests record what the builder installed before file pruning. `python3 tools/audit-os-tree.py PATH` runs the content audit without changing an extracted tree. Preserve file modes and extended attributes when extracting the EROFS root for this check.

The build stages individual uutils 0.13.0 binaries, adds a mandatory hardened_malloc dependency, then removes the GNU coreutils commands after package scriptlets finish. The signed tree records the selected applets, Cargo lock digest, builds and license notices under `/usr/share`. [uutils 0.13.0](https://github.com/uutils/coreutils/releases/tag/0.13.0)

| Utility | Callers and inputs |
| --- | --- |
| `echo` | Readiness, failure and OCI probe units pass fixed status markers. |
| `sha256sum` | Privileged boot, release and recovery helpers hash pinned files or open file descriptors. Guest launch checks the authenticated checksum list with `--strict --check --status -`. |
| `true` | The execution-policy qualification copies the exact binary from the signed root and tests the volatile copy. |
| `chcon` | Hypervisor initramfs, lifecycle helpers and socket units set fixed SELinux contexts on their private paths. They pass `--no-dereference` for entries where link handling matters. |
| `cp` | Hypervisor capture copies the signed Guest release members into private staging with `--sparse=always --reflink=never --no-target-directory --`. The capture helper independently verifies content, sets mode `0400` and flushes each file before publication. |

Run `python3 tests/check-uutils.py BIN_DIRECTORY` on the built executables and add `--hypervisor` for the full Host set. Use the boot, update and capture checks to qualify the exact SELinux domains and storage behavior in each image.

For the disposable nested lifecycle and Stalwart diagnostic initramfs fixtures, add `qualification-utils` to the comma-separated mkosi profile list when building the test core and initramfs. That profile keeps the fixed GNU commands those fixtures invoke. The OBS role recipes select the release utility set.

Use a separate scratch directory for each build or qualification run. Keep the qualification logs, manifests, and digests, along with the inputs still needed for later tests or recovery. Remove disposable images, extracted trees, test data, and temporary keys as soon as the last step that uses them finishes.

Both images build hardened_malloc 14 from a digest-checked source archive, run its upstream tests, and retain the allocator license and build record under `/usr/share`. The build uses the upstream default profile with a fixed `x86-64` compiler target and the upstream GCC 16 header fix. The verified `/etc/ld.so.preload` selects the library for eligible programs. The Rust bootstrap and both copies of systemd have a mandatory loader dependency on the library. The Rust bootstrap and the readiness service check resolved allocator symbols. `vm.max_map_count = 1048576` is the development setting for allocator qualification. [hardened_malloc 14](https://github.com/GrapheneOS/hardened_malloc/releases/tag/14)

The builder compiles Fedora's pinned targeted SELinux policy offline with the FVCA initramfs module. It embeds the root labels in EROFS before dm-verity signing. The Rust bootstrap labels the unpacked CPIO with the contexts from the signed UKI before systemd loads the embedded policy. The policy denies unknown kernel permissions. A Rust check requires SELinux enforcing mode and the expected `init_t` domain for PID 1 before mounting the verified root and again before reporting readiness.

The composed Hypervisor and Service Guest boot policies require integrity lockdown and enforced kernel module signatures. Their initramfs loads the drivers needed by each role, then permanently disables module loading and unloading, kexec, and unprivileged BPF for that boot. The Hypervisor boot policy forcibly disables SMT and requests VT-d with interrupt remapping, translated DMA domains, and strict invalidation. Verify remapping and device isolation on the enrolled hardware. [Linux kernel sysctls](https://docs.kernel.org/admin-guide/sysctl/kernel.html) · [Linux kernel parameters](https://docs.kernel.org/admin-guide/kernel-parameters.html)

Both composed roles disable debugfs at kernel startup. The verified service manager removes `CAP_SYS_RAWIO` from PID 1 and its descendants. System service policy denies opening files on debugfs and tracefs and blocks `perf_event_open`, including requests for user-space counters. Integrity lockdown allows systemd to establish the signed-filesystem execution policy on the pinned Fedora kernel. [systemd manager security settings](https://www.freedesktop.org/software/systemd/man/262/systemd-system.conf.html#Security) · [systemd service sandboxing](https://www.freedesktop.org/software/systemd/man/262/systemd.exec.html)

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

Use the same QEMU command with `build/exec-check/fvca-dev-exec-check.raw` as the boot disk. The development test runs from the verified root after switch-root. It checks its allocator binding and requires permission denials for anonymous RX and RWX mappings, an RW-to-RX transition, and execution of a copied binary from `/run`. It also checks that `CAP_SYS_RAWIO` is absent and that kernel memory, tracefs, and per-thread performance counters are inaccessible to a system service. The console prints `FVCA_EXEC_CHECK_PASSED` before `FVCA_DEV_BASE_READY` when all checks pass. The probe is built only in the qualification profile.

## Open Build Service

Use a dedicated x86-64 image repository with `obs/project.conf` and the Fedora 45 `update` and `standard` paths. Disable publication on the qualification project. The native `fvca-base`, `fvca-hypervisor` and `fvca-service-guest` packages build their cores and initramfs from the reviewed Git commit. OBS extracts the package's dependency recipe from that commit to seed the worker's offline RPM mirror. The checked-out mkosi configuration applies the version pins and verifies the prepared source inputs.

```sh
./tools/fetch-allocator.sh
./tools/fetch-fwupd.sh
cargo vendor --locked --versioned-dirs --manifest-path uutils/Cargo.toml build/uutils-vendor/sources
python3 obs/prepare-build.py COMMIT build/allocator-upstream/hardened_malloc-14.tar.gz build/obs-base-sources \
  --uutils-vendor build/uutils-vendor/sources
python3 obs/prepare-build.py COMMIT build/allocator-upstream/hardened_malloc-14.tar.gz build/obs-hypervisor-sources \
  --uutils-vendor build/uutils-vendor/sources --role hypervisor --fwupd build/fwupd-source/fwupd-2.1.10.tar.xz
python3 obs/prepare-build.py COMMIT build/allocator-upstream/hardened_malloc-14.tar.gz build/obs-service-guest-sources \
  --uutils-vendor build/uutils-vendor/sources --role service-guest --vendor build/release-client-vendor/sources
```

Prepare the Guest vendor directory with the locked `cargo vendor --versioned-dirs` command in the release-client section below. The source preparer checks the Cargo lockfiles from the selected commit and packages the exact crate set for both Guest binaries. Commit every generated file to its corresponding OBS package. The worker uses the OBS project's staging certificate for its UKI and verity signatures. Decompress the disk and its package manifest so they share a basename with `.raw` and `.manifest` extensions. Run `tools/verify-base.py` with the staging certificate, `--extract-root` for the runtime build input, and `--extract-initrd` for the embedded initramfs. Production authorization requires independent evidence and production keys. [OBS mkosi build documentation](https://openbuildservice.org/help/manuals/obs-user-guide/cha-obs-package-formats#sec-obs-mkosi)

Verify the OBS manifest's signed checksum, save `_buildenv` for that same candidate, and collect the exact Fedora RPM archives named by the core and runtime manifests. Run the package review on the independent review system with RPM 6 and the Fedora 45 public signing key.

```sh
python3 obs/review-rpms.py hypervisor \
  --core-manifest CORE.manifest.gz --runtime-manifest vm-runtime.manifest \
  --buildenv HYPERVISOR_BUILDENV.xml --rpm-directory FEDORA_RPMS \
  --fedora-key RPM-GPG-KEY-fedora-45-primary --output hypervisor-rpm-review.json
```

Use `service-guest` with `oci-runtime.manifest` for the Guest. The report records exact package identities, archive SHA-256 digests, source RPM names, and licenses. It matches the core RPMs to the recorded OBS worker inputs and checks shared package versions across each core and runtime. Keep the report with the separate image-content and custom-binary build evidence. [Fedora package signing keys](https://fedoraproject.org/security/) · [RPM verification policy](https://rpm.org/docs/latest/man/rpmkeys.8.html)

Record the shipped files from the verified images. Keep each image's uncompressed mkosi manifest next to the corresponding raw disk with the same basename.

```sh
python3 tools/inventory-role.py hypervisor \
  --core core.raw --core-certificate obs-stage.crt \
  --runtime vm-runtime.raw --runtime-certificate vm-runtime.crt \
  --output hypervisor-file-inventory.json
```

Use `service-guest` and the OCI runtime disk for the Guest. The report binds the core, its native UKI initramfs, and the matching additive extension. It records paths, file hashes, permissions and links. Compare its package-manifest digests to the RPM review. Review EROFS ownership and extended attributes separately from the extracted file inventory. Keep the deployed boot tuple and workload evidence with the release. [Linux initramfs format](https://docs.kernel.org/driver-api/early-userspace/buffer-format.html) · [EROFS documentation](https://www.kernel.org/doc/html/latest/filesystems/erofs.html)

### Compare an independent core rebuild

Preserve the reviewed Git revision and package inputs. Verify the OBS image and manifest against their signed checksums. Supply each build's public certificate and keep its uncompressed mkosi manifest next to its image with the same basename. Use `hypervisor` for the corresponding Host core.

To reconstruct the source tree from Git, use `git -c tar.umask=0022 archive` and extract it with `tar --same-permissions` to preserve the expected overlay modes.

```sh
python3 tools/compare-core-rebuild.py service-guest \
  --reference obs-core.raw --reference-certificate obs-stage.crt \
  --rebuilt independent-core.raw --rebuilt-certificate independent-build.crt \
  --output rebuild-comparison.json
```

The tool authenticates both boot disks and compares the EROFS and verity bytes, the UKI with its outer signature removed, the kernel with its embedded signatures removed, and the initramfs. It also records the exact signed kernel digest from each UKI, package identities, and file differences. A verified mismatch writes the report and exits with status 2.

### Inventory an assembled boot release

Use the immutable Hypervisor slot image and the reviewed Secure Boot and Guest release certificates. The inventory verifies the signed GPT selection, core, VM runtime and Guest capsule before reporting their exact digests and files.

```sh
python3 tools/inventory-boot.py hypervisor --slot HOST_IMMUTABLE_GPT \
  --boot-certificate HOST_BOOT_CRT --guest-release-certificate GUEST_RELEASE_CRT \
  --output host-boot-inventory.json
python3 tools/inventory-boot.py service-guest --bundle GUEST_DIRECT_BOOT_BUNDLE \
  --boot-certificate GUEST_BOOT_CRT --runtime-certificate OCI_RUNTIME_CRT \
  --guest-release-certificate GUEST_RELEASE_CRT --output guest-boot-inventory.json
```

Compare the Guest release digest in both reports. Each report records the files in the native initramfs and the signed configuration archive that ukify appended. The direct-boot check also matches the separate Linux, initramfs and command-line files to the signed UKI. [systemd ukify](https://www.freedesktop.org/software/systemd/man/latest/ukify.html)

For a workload-bearing Guest, add `--workload-bundle AUTHORIZED_WORKLOAD` and `--admission-tool FVCA_WORKLOAD_ADMISSION` with the reviewed local admission binary. The inventory checks the workload under the policy and public keys in the signed Guest initramfs, then records the approved source, launch and installed root file hashes. The workload remains independently authorized and lives on the Guest data volume.

On the separate signing system, pass the reviewed digests of the uncompressed disk and package manifest to the core authorizer.

```sh
python3 tools/authorize-core.py core.raw --staging-certificate obs-stage.crt \
  --image-sha256 APPROVED_IMAGE_SHA256 --manifest-sha256 APPROVED_MANIFEST_SHA256 \
  --boot-certificate composition.crt --boot-key composition.key --output authorized-core
```

The authorization signs the same core root hash and UKI contents under the composition key and installs a fresh ESP with the authorized boot image. Use the resulting `core.raw` and `initrd.cpio.zst` with the matching runtime. The package inventory accompanies the core for the shared-package check. [Discoverable Partitions Specification](https://uapi-group.org/specifications/specs/discoverable_partitions_specification/)

## Appraise a Hypervisor boot quote

In trusted maintenance, enroll a TPM-generated restricted ECDSA P-256 key with SHA-256 at persistent handle `0x81004656`. The key uses the `PolicyCommandCode(TPM2_CC_Quote)` policy and the `fixedtpm`, `fixedparent`, `sensitivedataorigin`, `adminwithpolicy`, `noda`, `restricted`, and `sign` attributes. Preserve the enrolled public point and TPM qualified name on the separate verifier. The runtime collector opens `/dev/tpmrm0` and accepts one 32-byte challenge. [TPM 2.0 Library](https://www.trustedcomputinggroup.org/resources/documents/tpm-library-specification) · [TPM quote command](https://tpm2-tss.readthedocs.io/en/latest/group___esys___quote.html)

Keep the approved `fvca-hypervisor-boot-reference-v1` JSON on the verifier. Establish the reference in a controlled qualification boot of the exact Hypervisor release on the enrolled platform. Review which components the firmware and UKI measure before approving those values. Enroll a new reference for a qualified firmware or release change. [systemd-stub boot measurements](https://www.freedesktop.org/software/systemd/man/262/systemd-stub.html)

| Field | Value |
| --- | --- |
| `schema` | `fvca-hypervisor-boot-reference-v1` |
| `host` | Enrolled Hypervisor UUID |
| `release_manifest_sha256` | Independently approved release manifest digest |
| `ak_public` | Uncompressed SEC1 point as hex, starting with `04` |
| `ak_qualified_name` | TPM qualified name as hex, including the SHA-256 algorithm identifier `000b` |
| `sha256_pcrs` | Eight 32-byte hex digests for PCRs 0, 2, 4, 7, 9, 11, 12 and 13 in that order |

On the verifier, use the release client built without the `appliance` feature. Supply the independently trusted boot reference, an authenticated copy of the signed Host management enrollment, the management CA bundle and server name, and the enrolled attestation operator's PKCS#8 Ed25519 PEM key. Keep the key in a file owned by the verifier account with mode `0600`. The command checks the CA chain, server name, enrolled leaf certificate pin and protocol before sending the signed challenge. It emits the measured-boot verdict only after verifying the response identity, fresh TPM signature and approved PCRs.

```sh
fvca-release-client --appraise-remote-boot trusted-reference.json \
  trusted-management.json management-ca.pem fvca-management.example attestation-operator.key
```

For split collection and appraisal, create a new 0700 directory on the verifier and issue a challenge into it. Send the printed nonce through the [authenticated management protocol](#host-management-service) and save the returned evidence object. For trusted local maintenance, pass the nonce as `NONCE_HEX` to `--collect-boot-quote` or supply one newline-terminated hex line on stdin. Each challenge expires after two minutes. Successful appraisal consumes the saved challenge before it prints the verdict. [RATS architecture](https://www.rfc-editor.org/rfc/rfc9334.html)

```sh
mkdir -m 700 verifier-state
fvca-release-client --issue-boot-challenge trusted-reference.json verifier-state/pending
# On the Hypervisor, collect the quote for the nonce printed by the verifier.
fvca-release-client --collect-boot-quote NONCE_HEX
# On the verifier, supply the returned evidence JSON.
fvca-release-client --appraise-boot-quote trusted-reference.json verifier-state/pending evidence.json
```

The verdict identifies the approved measured boot and its enrolled Host. Guest identity, application authorization and runtime health are separate checks. Physical TPM enrollment qualification remains open. The disposable TPM test uses a client built with `--features swtpm-test` and runs `python3 tests/check-boot-attestation.py CLIENT` on the off-node test machine.

The measured Hypervisor UKI binds the exact VM runtime and Guest capsule roots through its embedded composition. The runtime activator submits each selected root and its signature to the kernel using `veritysetup`. This attachment path has no NvPCR dependency. Appraisal of the approved UKI establishes the selected composition. Live attachment and Guest agent readiness have their own evidence.

## Verify and stage a signed role release

`fvca-release-client` accepts an exact role release from a configured HTTPS or local TUF depot on the release or recovery workstation. Use an out-of-band trusted root and a separately authorized local selection record. Keep the TUF root and approved targets signing keys offline. Assign distinct Ed25519 keys to all four top-level TUF roles, and use consistent snapshots with SHA-256 and lengths at both metadata links. The client accepts timestamp metadata with up to 24 hours of remaining validity and snapshot metadata with up to seven days. Use a trusted clock and preserve the private metadata state across imports. [TUF specification](https://theupdateframework.github.io/specification/latest/) · [Amutable Quarry distribution](https://amutable.com/blog/distributing-images-quarry)

### Prepare reviewed TUF targets

On the review workstation, place the packed Guest disk at `guest-boot.raw`. For a Hypervisor release, also provide `boot.raw` and `vm-runtime.raw`. Generate `service-guest-boot-inventory.json` with `tools/inventory-boot.py service-guest --image guest-boot.raw --capsule-certificate CAPSULE_VERITY_CERT`, together with the Guest boot, runtime and release certificates from the [boot inventory procedure](#inventory-an-assembled-boot-release). A Hypervisor release also requires `hypervisor-boot-inventory.json` for `boot.raw` and uses the Host boot certificate to verify its Guest capsule.

The reviewer checks the role inventories, package provenance, integration results and available rebuild comparisons for the exact submission. The review file binds those records and the complete artifact set by length and SHA-256. For a Service Guest release, the review uses this shape. Supply the actual measured lengths and lowercase SHA-256 digests. Add the Host boot inventory and both Host artifacts for the `hypervisor` role. List additional reviewed evidence by filename under `evidence`.

```json
{
  "schema": "fvca-os-release-review-v1",
  "role": "service-guest",
  "epoch": 19,
  "artifacts": {"guest-boot.raw": {"bytes": 587538944, "sha256": "GUEST_BOOT_SHA256"}},
  "evidence": {
    "service-guest-boot-inventory.json": {"bytes": 8171112, "sha256": "GUEST_INVENTORY_SHA256"},
    "qualification.log": {"bytes": 1024, "sha256": "QUALIFICATION_SHA256"}
  }
}
```

Obtain the approved digest of `review.json` from the independent reviewer. Supply the minimum epoch from the release or recovery policy. For a Hypervisor release, pass `--vm-runtime-certificate` with the trusted certificate for the detached VM runtime.

```sh
python3 tools/pack-os-release.py --review review.json --review-sha256 APPROVED_REVIEW_SHA256 \
  --artifact-directory reviewed-images --evidence-directory reviewed-evidence \
  --minimum-epoch 19 --output prepared-release
```

The tool verifies the reviewed file hashes and the exact composition, including the correspondence between the detached and embedded Host payloads. It writes `selection.json`, `target-records.json` for the offline TUF targets signer, and `targets/` with the consistent-snapshot filenames. Each logical target uses `ROLE-EPOCH-MANIFEST_SHA256-` followed by the member name. The release manifest binds the exact `qualification.json`, which is the approved review file. Keep its named evidence in the review archive.

### Publish the signed TUF depot

Use Python TUF 7.0.1 and securesystemslib 1.6.0 with cryptographic support. Draft the complete intended targets index from prepared release and [signed channel](#author-the-channel-off-node) packages. Include the packages for active and permitted recovery releases that should remain discoverable. On the appropriate signing systems, load each draft with python-tuf and call `Metadata.sign` with each authorized role signer and `append=True`. Return each finalized document before drafting the role that references it. Preserve the signed bytes exactly. [python-tuf signing API](https://github.com/theupdateframework/python-tuf/blob/v7.0.1/tuf/api/metadata.py#L331)

```sh
python3 tools/tuf-depot.py draft-targets --version VERSION --expires TARGETS_EXPIRY \
  --package prepared-release --package new-channel > targets.unsigned.json
# Have the offline targets authority produce signed/targets.json.
python3 tools/tuf-depot.py draft-snapshot --version VERSION --expires SNAPSHOT_EXPIRY \
  --trusted-root current-root.json --input signed/targets.json > snapshot.unsigned.json
# Have the snapshot authority produce signed/snapshot.json.
python3 tools/tuf-depot.py draft-timestamp --version VERSION --expires TIMESTAMP_EXPIRY \
  --trusted-root current-root.json --input signed/snapshot.json > timestamp.unsigned.json
# Have the timestamp authority produce signed/timestamp.json.
python3 tools/tuf-depot.py publish --depot /srv/fvca/depot --trusted-root bootstrap-root.json \
  --signed signed --package prepared-release --package new-channel
```

Use Unix expiration seconds and advance each modified role's version. Reuse the exact signed targets index when renewing the snapshot, and reuse the exact signed snapshot when renewing only the timestamp. Put root rotations in `signed/` as `VERSION.root.json` with signatures from the required quorums of the predecessor and successor authorities. Keep the out-of-band bootstrap root pinned for publication and use the independently verified current root when drafting linked metadata. [TUF key rotation and repository operations](https://theupdateframework.github.io/specification/latest/#repository-operations)

Give the publisher a dedicated depot location on a local Btrfs filesystem with GNU `mv --exchange --no-copy`. Restrict writes to its parent and the depot to the publisher account. The publisher verifies all thresholds, links, validity windows, versions, and selected target bytes before atomically replacing the live directory. It retains previous versioned metadata and hash-addressed targets for clients already using them. A retry clears the abandoned private directory from an interrupted publication. Configure the origin to serve `metadata/` and `targets/` through the live path and revalidate `timestamp.json` on each request. Mount imported media with `nodev,nosuid,noexec` and keep it read-only for intake. [Consistent snapshots](https://theupdateframework.github.io/specification/latest/#consistent-snapshots)

Run `tests/check-os-release-packaging.py` with the reference TUF fixture environment and a verified development Host/Guest pair. It signs and publishes two disposable depots, verifies exact staging under standing policy for both roles, and checks rejection of a changed review, replaced artifact, and mismatched embedded Guest. Supply the client, artifact and evidence directories, VM runtime certificate, and a scratch directory on the same filesystem as the evidence. Run `tests/check-tuf-depot.py --client FILE --scratch-directory DIRECTORY` to exercise writer serialization, interruption, rollback, root rotation, and HTTPS intake against the published layout.

### Retire unused depot objects

Keep every active, fallback and recovery tuple required by the deployment in the current signed targets index. Remove a retired tuple from that index through the normal offline targets approval. Once clients use bounded depot transfers and the deployment has a known maximum clock skew, supply `--max-clock-skew-seconds` to `publish` to retire eligible objects during the publication. Use `prune` when a drain window ends between publications.

```sh
python3 tools/tuf-depot.py prune --depot /srv/fvca/depot \
  --trusted-root bootstrap-root.json --max-clock-skew-seconds DEPLOYMENT_CLOCK_SKEW
```

The command verifies the current index, root history and signed historical snapshot-to-target links. It keeps each previous view through the earlier signed expiry of its snapshot and targets, plus the 24-hour maximum client transfer window and the configured clock skew. It then atomically removes objects that no retained view reaches. The `next_expiry` value in the result is the next eligibility time in Unix seconds. [TUF expiration checks](https://theupdateframework.github.io/specification/latest/#detailed-client-workflow)

### Import the release

Keep the depot configuration and CA bundle under the intake operator's control alongside the trusted root. The release selection specifies a role, epoch, approved minimum epoch, manifest digest and byte budget. For HTTPS, configure a static origin with a trailing slash on the depot path, an absolute PEM CA bundle path and a deadline for fetching the complete release. The client verifies the server name against this CA bundle, connects directly to the configured origin and requires unencoded response bodies. Serve repository objects with HTTP 200 and missing objects with HTTP 404.

```json
{
  "transport": "https",
  "base_url": "https://updates.example.org/fvca/",
  "ca_file": "/etc/fvca/update-ca.pem",
  "deadline_seconds": 1800
}
```

For an offline depot, use `{"transport":"local","path":"/mnt/fvca/depot"}` in the depot configuration. Local transfers have a 24-hour ceiling. Each lookup resolves the live depot path without following symlinks, so a reader can still fetch retained immutable objects after publication exchanges the directory. Keep the same trusted TUF metadata state when moving between HTTPS and a local copy of the same repository.

Prepare a private state directory owned by the intake account with mode `0700`. In the trusted selection JSON, supply `role`, `epoch`, the independently authorized `minimum_epoch`, `manifest_sha256`, and `max_release_bytes` for the total logical size of the selected set. Supply the initial trusted root from verified configuration, and keep its bytes stable when the client advances the repository's trusted root through TUF rotation.

```sh
umask 077
# Install the Fedora C toolchain, pkgconf-pkg-config, and tpm2-tss-devel on the build system.
mkdir -p build/release-client-vendor
cargo vendor --locked --versioned-dirs --manifest-path release-client/Cargo.toml \
  "$PWD/build/release-client-vendor/sources" > build/release-client-vendor/config.toml
# Run the build below in a Fedora Rust 1.100 environment with networking disabled.
cargo build --frozen --release --manifest-path release-client/Cargo.toml \
  --config build/release-client-vendor/config.toml
release-client/target/release/fvca-release-client trusted-root.json depot.json intake-state selection.json
```

`FVCA_RELEASE_STAGED` names the complete verified tuple under `intake-state/staged/MANIFEST_SHA256`. Treat staged artifacts as inputs to the role's boot and installation verifiers. On-node activation and an independently protected on-node security epoch remain release gates.

Run `tests/check-release-intake.py` with Python TUF 7.0.1 and securesystemslib 1.6.0 with crypto support. Supply `--client`, `--hypervisor`, `--vm-runtime`, `--guest` and a new `--output` directory on the same filesystem as the three disposable lab images. The fixture signs a test depot with ephemeral keys and exercises staging, expiry, role and epoch mismatches, artifact corruption, and persistent metadata and root rollback checks.

Use the same Python environment for `tests/check-release-https.py --client FILE --fixture INTAKE_TEST_OUTPUT --output NEW_DIRECTORY`. It serves the signed fixtures over loopback TLS and checks CA and server-name validation, proxy and redirect handling, size and time bounds, recovery from an interrupted transfer, and persisted rollback checks.

### Discover an OS release under standing policy

Use a private release state directory for each role. The trusted boot controller supplies `active-os-release.json` with `role`, `sequence`, `epoch`, and `manifest_sha256` from the active release. Pin the owner public key in the verified deployment configuration. Sign the exact standing policy bytes with the owner key. The client expects a 32-byte raw Ed25519 public key and a 64-byte detached signature.

```json
{
  "schema": "fvca-os-update-policy-v1",
  "revision": 1,
  "role": "hypervisor",
  "channel": "stable",
  "enabled": true,
  "valid_from": 1795154400,
  "expires": 1797746400,
  "tuf_root_sha256": "INITIAL_TRUSTED_ROOT_SHA256",
  "depot_config_sha256": "DEPOT_CONFIG_SHA256",
  "qualification_key_ed25519": "RAW_32_BYTE_PUBLIC_KEY_AS_LOWERCASE_HEX",
  "compatibility_sha256": "REVIEWED_COMPATIBILITY_PROFILE_SHA256",
  "minimum_epoch": 17,
  "max_release_bytes": 4294967296,
  "max_staged_bytes": 17179869184
}
```

Publish the selection as TUF targets `fvca-os-ROLE-CHANNEL.json` and `fvca-os-ROLE-CHANNEL.sig`. The policy's independent qualification key signs the exact channel JSON bytes after reviewing the release and its evidence. Use distinct owner, qualification, and TUF keys. The qualification authority allocates increasing sequence numbers within each role across its channels. The release digest covers the full role manifest, which binds every payload and the qualification evidence. [The Update Framework specification](https://theupdateframework.github.io/specification/latest/)

#### Author the channel off-node

Use the release client built without the `appliance` feature. Create a `0700` trusted scope directory on the review workstation with `policy.json`, `policy.sig`, `owner.public`, the pinned `trusted-root.json`, and an authenticated copy of the site's `active-os-release.json`. For a Host trial, include `secure-boot.pem` matching the certificate digest in the standing policy and `running-context`, copied from `/run/fvca/running-trial-context` on the verified active Host. Include the site's pinned raw Ed25519 `promotion.public` and `guest-configuration.public` when their approvals are supplied. Obtain these scope files independently of the release submission.

Write the requested sequence, validity and exact approved candidate digest in `request.json`. The request's `release` is either `null` for a withdrawal or an object with `manifest_sha256` and `activation`. The tool derives the role, channel, compatibility and epoch from the authenticated scope and prepared release. Place the separately signed envelopes in the approvals directory using the role's `boot-trial.bin` or `guest-trial.bin`, with `boot-promotion.bin` and `guest-configuration-change.bin` when applicable. Use `-` for the release and approvals arguments when withdrawing a head.

```sh
fvca-release-client --prepare-os-channel trusted-scope request.json prepared-release approvals > head.json
openssl pkeyutl -sign -rawin -inkey qualification.key -in head.json -out head.sig
fvca-release-client --pack-os-channel trusted-scope request.json prepared-release approvals head.sig new-channel
```

Review the exact draft before signing it with the independent qualification key. The second command using `fvca-release-client` checks that signature against the standing policy and rechecks the release and approvals. It puts the head, detached signature, and authorized envelopes in `new-channel/targets/` with the consistent-snapshot filenames. Use `new-channel/target-records.json` alongside the prepared release records when authorizing the new TUF targets metadata.

#### Channel head format

```json
{
  "schema": "fvca-os-channel-v1",
  "role": "hypervisor",
  "channel": "stable",
  "sequence": 42,
  "valid_from": 1795154400,
  "expires": 1795240800,
  "compatibility_sha256": "REVIEWED_COMPATIBILITY_PROFILE_SHA256",
  "release": {
    "epoch": 17,
    "manifest_sha256": "QUALIFIED_CANDIDATE_MANIFEST_SHA256",
    "activation": {"urgency": "security", "activate_by": 1795183200}
  }
}
```

Use Unix seconds for validity, hold expiry, and security deadlines. Limit channel authorizations to seven days. A signed empty channel uses `"release": null`. Routine updates use `"activation": {"urgency": "routine"}` and default to 04:00–05:00 Europe/Berlin. Adjust the daily window with a signed `maintenance` object containing an IANA `timezone`, a `start_minute` and an `end_minute` measured from local midnight. An optional signed `hold` names a `manifest_sha256` and an expiry `until`. Security releases bypass the routine window and any matching hold ends by the signed security deadline.

```sh
fvca-release-client --discover-os-release trusted-root.json depot.json intake-state \
  policy.json policy.sig owner.public
```

On success the client writes and prints `fvca-os-update-status-v2` with the active identity, optional staged candidate, eligibility, last successful refresh, earliest authorization expiry and exact policy and channel checkpoint identities. A failed refresh exits with an error. The status file records the last successful observation. Activation requires fresh authorization. The client reuses TUF's persisted freshness state, rejects signed sequence rollback or conflicting records at a previously observed sequence, and retains existing staged releases when the staging quota is full. Run `python3 tests/check-release-channel.py --client CLIENT --output NEW_DIRECTORY` with the reference TUF fixture environment. Discovery and staging are available for both roles. Scheduled execution, lifecycle leasing, activation and health-controlled recovery remain release gates.

### Prepare a file-backed A/B slot

Use a private `0700` Btrfs slot store per role. To provision the initial boot tuple, append `--initialize-slots SLOT_STORE` to the intake command. This creates `slot-a` in an empty store and verifies the same slot on retry. Use the existing role boot verifier when booting the installed images.

For an update, obtain the active slot record from the trusted boot controller and hold its boot-selection lease during preparation. The record identifies the booted slot and its exact release manifest. For example, an active slot A uses `{"slot":"a","epoch":17,"manifest_sha256":"ACTIVE_MANIFEST_SHA256"}` with its actual digest. Select an independently approved manifest with a different digest and an epoch at or above the active release. Keep the active release eligible under the independently authorized epoch floor until the new release has passed trial boot.

```sh
release-client/target/release/fvca-release-client trusted-root.json depot.json inbox next-release.json \
  --prepare-inactive /srv/fvca/hypervisor-slots active-slot.json
```

The coordinator verifies the active tuple, then invokes systemd-sysupdate 262.1 with a private alternate root and an exact source digest from the TUF intake. It verifies the installed manifest and every member again, flushes the tuple, and publishes the inactive slot with an atomic directory rename. An identical retry verifies the existing inactive tuple. The active slot remains the recovery path throughout preparation. A forced stop before publication may leave a private `.prepare-*` directory, which can be removed after the installer exits.

This file-backed preparation works with the current Hypervisor and Service Guest bundles in the lab. The offline GPT installer below handles an already provisioned Hypervisor disk. Physical qualification of TPM floor advancement remains a release gate. [systemd-sysupdate transfer definitions](https://www.freedesktop.org/software/systemd/man/latest/sysupdate.d.html)

`tests/check-release-slots.py` uses the same Python TUF environment. Supply distinct matched `--active-boot`/`--active-guest` and `--next-boot`/`--next-guest` pairs, their `--vm-runtime`, the `--client`, and a new Btrfs `--output` directory on the images' filesystem. The fixture checks same-epoch Hypervisor preparation, rejects a lower epoch, and verifies both complete slots after a transfer interruption and after retrying and replacing the inactive tuple.

### Install a Hypervisor release into an inactive GPT slot

Run the release client from an offline maintenance system with both NVMe namespaces unused. Keep the verified recovery slot selected in firmware during installation. The client uses `sfdisk`, `mcopy`, and `sbverify`. On Fedora, `glibc-gconv-extra` supplies the FAT code-page support that `mcopy` needs. After verifying the Secure Boot signature, the release client reads `.cmdline` and `.pcrsig` directly from the signed x86-64 EFI image and rejects ambiguous section layouts. Stage the recovery release into the same private state directory before requesting the update. Use an immutable seven-partition `boot.raw` for each TUF release and keep its separate runtime and Guest bundle targets. Compose both images with `--epoch-policy` for the enrolled TPM counter and use `--immutable-output` at provisioning to save the exact reference alongside the combined disk. [UAPI.5 Unified Kernel Images](https://uapi-group.org/specifications/specs/unified_kernel_image/)

Use `fvca-release-client --inspect-hypervisor-gpt DISK 4096` to obtain each disk record from the reviewed provisioned layout. Record absolute NVMe device paths or private disposable disk-image paths. In this example the active release is epoch 17. The selected candidate can use epoch 17 or a higher epoch with a distinct approved manifest. Use the Secure Boot certificate approved for the two UKIs and the policy SHA-256 digest from the reviewed TPM enrollment.

```json
{
  "schema": "fvca-hypervisor-gpt-install-v2",
  "sector_size": 4096,
  "boot_certificate": "/etc/fvca/secure-boot.pem",
  "epoch_policy_sha256": "ENROLLED_TPM_POLICY_DIGEST",
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

The candidate must name the inactive slot's existing UUIDs and fit its allocated partitions. The ESP must match its allocated size. The client checks that the packed runtime and Guest bytes agree with the TUF release members. It verifies the signed UKIs of the candidate and active recovery, requires their epochs to match the corresponding release manifests, and checks both against the reviewed TPM policy digest. With exclusive access to both disks, it verifies their reviewed GPT fingerprints and reads back the active recovery EFI loader and payloads before writing. On the inactive disk it clears and flushes the ESP, writes and verifies the six payloads, then installs and verifies the approved ESP. It clears unused capacity inside the payload partitions. Both GPTs and both encrypted Host data partitions are preserved. A repeat verifies an already installed image and can resume an interrupted installation. Boot trial and promotion use their separate authorizations. [Linux exclusive block-device opens](https://man7.org/linux/man-pages/man2/open.2.html) · [util-linux GPT verification](https://github.com/util-linux/util-linux/blob/master/disk-utils/sfdisk.8.adoc)

After promoting a higher-epoch release, the same installer can write a separately approved recovery image at that epoch to the alternate slot. Verify both boot paths while the existing TPM floor remains in force. Floor advancement requires its own approval after both paths are ready.

`tests/check-hypervisor-gpt-install.py` uses the TUF fixture environment to test the same operation on copies of two provisioned disks. Supply both immutable release images, their runtime and Guest targets, both epochs, and the enrolled counter policy digest. Use matching epoch values to qualify installation of a distinct recovery release at the running release's epoch. Use a different runtime for the mixed-release refusal check, a signed fixture at the next epoch plus four with a different counter policy, and a fixture composed without an epoch. Use an inactive disk with a payload partition larger than the corresponding candidate partition to exercise tail clearing.

### Prepare the inactive Hypervisor slot under standing policy

Add a `hypervisor_gpt` object to the signed Hypervisor update policy. Set `sector_size`, the absolute `boot_certificate` path, `boot_certificate_sha256` over its exact bytes, and the enrolled `epoch_policy_sha256`. Set `storage_pcr_key_fingerprint` to systemd's `pkfp` for the enrolled PIN-less key on both members. For an RSA key, hash the PKCS#1 DER bytes from `openssl rsa -pubin -RSAPublicKey_out -outform DER -in pcr-public.pem` with SHA-256. Supply the reviewed disk records under `a` and `b` using `--inspect-hypervisor-gpt`. The boot controller includes `"slot": "a"` or `"slot": "b"` in the active release record before handing off to maintenance. This identifies the stable recovery disk and the exact recovery manifest that must already be staged. The signed disk policy can be reused across releases.

Use a trusted offline maintenance environment with both NVMe namespaces unused. Keep intake state and staged releases on storage separate from those two namespaces. Use `--boot-trial-candidate` when composing the candidate. Its signed UKI carries a transaction marker that must match its signed initramfs policy at boot. The candidate still requires a recorded authorized trial or a durable promotion record before it can start its Guest. [ukify inspection](https://www.freedesktop.org/software/systemd/man/262/ukify.html)

```sh
fvca-release-client --discover-os-release trusted-root.json depot.json intake-state \
  policy.json policy.sig owner.public --prepare-inactive-gpt
```

For an eligible release, the installer rechecks both boot signatures, the signed epochs, and the enrolled PIN-less PCR signing identity and purpose. It checks the live TPM floor and current channel eligibility immediately before changing the inactive ESP and again before publishing the replacement ESP. If authorization expires after the first check, an interrupted slot stays unbootable until an eligible retry completes it. On NVMe, the installer reads the whole disk for GPT verification and acquires exclusive write handles for the seven immutable partitions. Every handle must match the reviewed parent disk and partition boundaries before the installer changes any bytes. The receipt reports `prepared_inactive_slot` after durable readback. Deliver its signed trial approval before starting activation.

`tests/check-standing-hypervisor-install.py` uses the release client built with `swtpm-test`. Its fixture directory contains PIN-less integrated `installed-a.raw` and `installed-b.raw` images at epochs 1 and 2, their exact immutable `boot-a.raw` and `boot-b.raw` images, common `vm-runtime.raw` and `guest-boot.raw` artifacts, and the enrollment hashes in `epoch-policy-fingerprint` and `storage-pcr-fingerprint`. Supply separate software TPM states at each floor and use an output directory on the same filesystem as the fixture.

### Deliver a prepared Hypervisor trial from the release channel

Set `trial_key_ed25519` in the signed standing policy to the lowercase hex of the 32-byte Ed25519 trial public key. Compose both slots with this key using `--boot-trial-public-key`. The signed UKI command lines identify the key and the initramfs verifies that identity against its pinned authority. Use a trial key distinct from the owner, qualification, TUF, and image signing keys.

In the qualified channel announcement's `release` object, include `trial_approval` with the exact envelope's `bytes` and `sha256`. Publish the independently signed envelope as `hypervisor-EPOCH-MANIFEST_SHA256-boot-trial.bin` in the same TUF repository. The envelope uses the standing trial format below.

```sh
fvca-release-client --discover-os-release trusted-root.json depot.json intake-state \
  policy.json policy.sig owner.public --deliver-prepared-trial
```

Run delivery with the authenticated Btrfs Host data mounted at `/run/fvca/host-data`. The client refreshes the channel, checks the maintenance window and holds, and verifies the trial signature and validity. It opens both reviewed disks read-only and verifies the installed inactive slot against the staged release before checking both Secure Boot signatures, the enrolled TPM floor, the trial keys, and the candidate transaction. A complete approval is durably published to the Host inbox and reported as `delivered_trial`. An identical retry confirms the existing file. A different pending envelope requires reconciliation before another delivery.

`tests/check-standing-hypervisor-install.py --trial-key KEY` adds the delivery checks. Compose the fixture pair with the matching trial authority. Include the candidate selection in `candidate.txt` and the common verity roots as `core`, `runtime`, and `guest` in `roots.json`. Use a disposable Btrfs mount at the fixed Host data path.

### Activate a prepared trial from a running Hypervisor

For an eligible release already installed in the inactive slot, use `--activate-prepared-trial` on the running Hypervisor in place of `--deliver-prepared-trial`. The release client checks current eligibility, durably delivers the exact approved envelope, and requests `fvca-activate-hypervisor-trial.service`. The `delivered_trial` and `requested_trial` status fields report those separate steps. Candidate Guest health is recorded during the later trial boot. [systemctl job submission](https://www.freedesktop.org/software/systemd/man/262/systemctl.html#--no-block)

The service checks the signed approval against the verified boot identity saved by the initramfs, the live UEFI selection, and the installed candidate ESP. It defers while a capture or restore owns the Guest lifecycle lease. It retains that lease while verifying an orderly Guest agent shutdown and detaching the writable Btrfs-backed disk. It then rechecks the pending approval and queues an orderly reboot. The stable initramfs performs the one-shot candidate handoff before it would start another Guest.

If the reboot request fails after the Guest stopped, systemd starts `fvca-recover-hypervisor-activation.service` to reconcile the attachment and restart the stable Guest. Inspect both services for a failed or uncertain shutdown. Deadline-authorized forced stop and watchdog-backed trial retries remain release gates.

### Enroll scheduled Hypervisor release checks

Compose each enrolled PIN-less GPT slot with `--os-update-owner owner.public`. The file contains the raw 32-byte Ed25519 public key for the owner-signed channel policy and must use a distinct key from the boot trial and promotion authorities. The UKI binds the owner key and depot scope. For a local depot, use `{"transport":"local","path":"/run/fvca/host-data/os-update/depot"}` and place its TUF `metadata` and `targets` under that path. For HTTPS, pass `--os-update-address IP --os-update-ca CA.pem` at composition and configure the depot URL with the same literal IP and `/run/fvca/os-update-ca.pem` as its CA path. The scheduled service can reach only the enrolled address.

Before booting the enrolled slot, provision `/run/fvca/host-data/os-update` on the authenticated Btrfs Host data volume as a root-owned directory with mode `0700`. Populate it with `trusted-root.json`, `depot.json`, `policy.json`, `policy.sig`, and `active-os-release.json`. The verified initrd labels the private staging directory for atomic release publication. The active record includes the currently promoted slot. Keep these inputs current when promoting a release.

To enable scheduled installation, compose each slot with `--os-update-peer-slot UUID` using the other provisioned slot's `--gpt-slot` value. The UKI grants the service write access to exactly that slot's seven immutable partition UUIDs. Keep the exact active recovery release under `os-update/staged/MANIFEST_SHA256` using the verified intake procedure above. An enrollment without a peer slot can activate an already installed candidate.

A verified stable boot enrolls `fvca-host-update.timer`. It checks after boot and hourly with up to 90 seconds of jitter. A failed service can retry after five minutes, capped at three starts in 30 minutes. For an eligible release, the client checks the signed trial approval against the running boot, verifies the active recovery image, and takes the Guest lifecycle lease during live installation and approval delivery. It refuses to replace a different pending trial. The client releases the lease before requesting Guest shutdown and reboot through the existing activation service. Results go to the console and to `/run/fvca/host-data/os-update/os-update-status.json`. [systemd timer semantics](https://www.freedesktop.org/software/systemd/man/262/systemd.timer.html)

### Authorize automatic promotion

Compose both slots with the same independent `--boot-promotion-public-key`. The release publisher can authorize promotion before deployment by signing the exact trial, candidate EFI loader, release manifest and next channel sequence. Use the active record from the currently promoted slot and run the signer with `mcopy` available.

```sh
python3 tools/sign-hypervisor-promotion.py --trial signed-trial.bin \
  --trial-key trial.pub --standing-active active-os-release.json \
  --candidate boot.raw --candidate-manifest release.json --candidate-sequence 2 \
  --sign-key promotion.key --output standing-promotion.bin
```

Publish the grant as `hypervisor-EPOCH-MANIFEST_SHA256-boot-promotion.bin` and list its exact `bytes` and `sha256` under `promotion_approval` in the qualified channel release. The scheduled client authenticates the grant and delivers it with the trial authorization. After recording local Guest health, the candidate drains the Guest and returns to the stable slot. The stable initrd checks the reviewed ESP geometry, the exact EFI loader bytes and all three candidate verity trees. It writes the promotion intent to Btrfs and commits the new EFI order before rebooting. The first normal boot verifies the intent and the scheduler records the promoted manifest as active. A later boot may use the confirmed release as the second EFI entry while its epoch remains eligible.

### Stage a qualified Host firmware cabinet

Run the firmware intake gate on a trusted maintenance system. It checks an exact Host and device transition against a signed standing policy, an independently signed TUF offer, and a recent fwupd observation. It then writes the approved cabinet and signed offer to a private, durable staging directory.

```sh
fvca-release-client --stage-host-firmware trusted-root.json depot.json private-state \
  policy.json policy.sig owner.public observation.json
```

`private-state` is a dedicated mode-`0700` firmware state directory. Use the pinned 32-byte Ed25519 owner key and a 64-byte detached signature over the exact policy JSON. The `fvca-firmware-policy-v1` policy binds the `hypervisor` role, the enrolled platform, exact fwupd version, allowed device profiles and remotes, TUF root, depot configuration, independent qualification key, archive budget and firmware epoch floor. The platform record contains the SMBIOS system UUID, vendor, product, board and board revision. Keep it private.

Publish `fvca-firmware-CHANNEL.json` and `fvca-firmware-CHANNEL.sig` as TUF targets. The independent qualification authority signs the exact bytes of the `fvca-firmware-channel-v1` document. The document binds the Host UUID, fwupd version, channel, sequence and validity. Its `offer` binds the exact enrolled device, version transition, cabinet and embedded payload digests, signed LVFS catalog, and independent qualification evidence. Publish the cabinet as `fvca-firmware-ARCHIVE_SHA256.cab`. In the offer’s `catalog` field, give `metadata` and `signature` their exact `bytes` and `sha256`. Publish the unmodified LVFS metadata as `fvca-firmware-catalog-METADATA_SHA256.bin` and its JCat file as `fvca-firmware-catalog-SIGNATURE_SHA256.jcat`. The limits are 32 MiB and 1 MiB respectively. Publish a higher sequence with `"offer": null` to withdraw an offer. The signed fixtures in `tests/check-firmware-intake.py` show the complete schema.

Publish the `fvca-firmware-boot-transition-v3` document as `fvca-firmware-transition-SHA256.json` and put its exact SHA-256 in `transition_evidence_sha256` before signing the offer. It binds the Host UUID, fwupd version, device identity, starting and target versions, and both firmware digests. Set `qualified_at` to the Unix time in seconds when independent qualification of that exact transition completed. Intake requires the date to precede the offer expiry and be at or before the authenticated admission check. Its `before` and `after` records each bind the ESP, core and runtime verity roots, release epoch and policy digest, TPM rollback floor, SHA-256 bank PCR 7, Btrfs filesystem UUID, and signed storage policy digest. Intake requires the same Btrfs pool and nondecreasing epoch and TPM floor. Set `key_release` to `preserve-enrollment` for identical records, or `requires-preparation` for a transition that needs separately authorized storage preparation. Intake retains the exact bytes as `transition.json` with the staged offer. [Firmware intake fixtures](tests/check-firmware-intake.py)

The offer's four operational evidence digests name TUF targets `fvca-firmware-KIND-SHA256.json`, where `KIND` is `distribution`, `vendor`, `reboot-policy`, or `recovery`. Each document has schema `fvca-firmware-KIND-v1`, a `transition_sha256` matching the qualified boot transition, and an `evidence` object. Intake verifies every digest and keeps the exact documents in the same staged directory.

| Evidence | Required scope |
| --- | --- |
| Distribution | The selected remote and the exact LVFS metadata and JCat digests. |
| Vendor | The qualified authentication mechanism and its vendor procedure reference. Independent vendor signature verification also records the signing key SHA-256. |
| Reboot policy | Authenticated `routine` or `security` urgency, a device-compatible delivery route, required power conditions, and the ordered reboot or power-transition steps. |
| Recovery | The qualified recovery method, vendor procedure reference, and retry allowance. A physical-repair-only method has a zero retry allowance. |

Use an `fvca-firmware-observation-v2` document with the same platform and fwupd version, an `observed_at` Unix timestamp, the complete `fwupdmgr get-devices --json` and `fwupdmgr get-updates --json` results under `devices` and `upgrades`, and the ESRT entries under `esrt`. The observation must be less than five minutes old when staging finishes. Capsule admission compares the exact ESRT class, type and raw version. Each ESRT record also includes the minimum supported version, capsule flags, last attempted version and last attempt status as JSON integers. NVMe admission requires the individual fwupd device ID and SHA-256 of the reported serial bytes. A model or GUID can identify multiple controllers. [fwupd capsule inventory](https://fwupd.github.io/libfwupdplugin/uefi-capsule-README.html) · [fwupd NVMe identities](https://fwupd.github.io/libfwupdplugin/nvme-README.html)

On the enrolled Host, pass `--live` in place of `observation.json`. The client verifies the catalog against TUF and the independent offer, then seals the two files and passes them to the root fwupd process on `/run/fvca-firmware-bus/inventory`. fwupd verifies the LVFS JCat checksum and signature against the image’s trust roots. The client pins the daemon’s unique bus owner and the resulting catalog generation across both live observations. It also requires `OnlyTrusted=true` and `Tainted=false`. [fwupd D-Bus interface](https://github.com/fwupd/fwupd/blob/cad845481d02d223adb97795edfd7a825cd3ac84/src/org.freedesktop.fwupd.xml)

An accepted cabinet reports `staged`. Live intake gives fwupd a sealed copy of the exact cabinet. fwupd checks its SHA-256 before parsing, caps the expanded archive at 256 MiB, and resolves a unique release by the signed device GUID and target version. It requires the approved protocol, trusted JCat signatures for the cabinet metadata and selected payload, and the exact approved SHA-256 of the payload stream. Live staging and retries report `verified_payload_sha256` and `verified_payload_bytes` for that stream. An authenticated replacement or withdrawal immediately retires superseded staging files. Activation still requires device-specific vendor authentication, power, TPM and recovery checks. fwupd distribution trust and on-device signature enforcement provide separate evidence. [fwupd distribution trust](https://fwupd.github.io/libfwupdplugin/only-trusted.html)

The native verifier also resolves the exact live fwupd device ID, checks its starting version, flags, and protocol, and runs fwupd's release and engine requirements with fixed install flags. The capsule-on-disk preflight requires fwupd's native capsule-on-disk backend together with the verified EFI route. [fwupd UEFI capsule plugin](https://fwupd.github.io/libfwupdplugin/uefi-capsule-README.html)

The native capsule writer requires the exact staged offer and sealed cabinet, the already held Host lifecycle lease, a synchronized flashing record on the authenticated Btrfs pool, and the matching boot-local Guest drain receipt. The Guest launcher can produce that receipt only after it verifies the inherited lease, checks the Guest and its disk attachment are inactive, and synchronizes the Btrfs pool. When the Guest is enrolled, the launcher also verifies its orderly shutdown receipt against the detached raw disk. The writer binds the native volume to the initramfs-verified ESP, records the exact operation in fwupd history, and flushes the capsule before setting the EFI delivery flag.

Firmware reads descend through open directory descriptors on the selected mount. Both the release client and the native capsule integration reject symlinks and verify mount identity at each step when opening operation records or inspecting the ESP queue.

The Host service `fvca-fwupd-writer.service` starts only for a current operation with a matching Guest drain receipt and a held lifecycle lease. It verifies the ordinary Secure Boot route and EFI variable capacity before enabling writes on its private ESP mount, then drops its Linux capabilities before executing fwupd. The inventory's ESP view stays read-only. The root-only writer bus accepts the sealed cabinet and the held lease as file descriptors, and the native daemons acquire exclusive custody of persistent history before loading it. Scheduled activation records the dispatch on the authenticated Btrfs pool before calling the writer. It requests a hardware reboot only after the writer acknowledges the operation and the broker records and rechecks the exact EFI queue entry. An ambiguous writer outcome keeps the Guest fenced for recovery. An interrupted drain can resume the Guest after confirming that the writer never received authorization and that the EFI queue is empty.

Read-only inventory of the future Proxmox host on 2026-11-20 observed ThinkStation P3 Ultra board 1066, BIOS S0JKT2AA (fwupd 1.42), EC 1.13 and two Toshiba KXG50PNV1T02 drives at AFDA4103. The two drives reported the same model GUIDs. Live EFI variables advertised capsule-on-disk delivery and capsule result reporting. The LVFS BIOS 1.51 cabinet contains an AMI BIOS Guard payload. Device-side signature enforcement and the physical transition remain unqualified. [UEFI indication flags](https://uefi.org/specs/UEFI/2.11/08_Services_Runtime_Services.html#exchanging-information-between-the-os-and-firmware)

### Enroll scheduled Host firmware discovery

Compose ordinary epoch-protected slots with PIN-less TPM storage and `--firmware-update-owner owner.public`. Use a distinct 32-byte Ed25519 owner key. Provision `/run/fvca/host-data/firmware-update` as a root-owned mode-`0700` directory on the authenticated Btrfs pool. Add `trusted-root.json`, `depot.json`, `policy.json`, and `policy.sig` there. For a local depot, place TUF metadata and targets under `/run/fvca/host-data/firmware-update/depot` and use that absolute path in `depot.json`. For HTTPS, compose with `--firmware-update-address IP --firmware-update-ca CA.pem`, then use that literal IP in the HTTPS URL and `/run/fvca/firmware-update-ca.pem` for the CA path.

`fvca-firmware-update.timer` starts discovery after stable boot and hourly with bounded jitter. Results in `firmware-update-status.json` distinguish an in-progress check, a staged cabinet, a signed withdrawal or empty channel, and a blocked attempt. The record includes the last verified channel sequence and its freshness deadline. An interrupted check or a depot failure cannot authorize staged content. [systemd timer semantics](https://www.freedesktop.org/software/systemd/man/262/systemd.timer.html)

For a staged UEFI capsule, the scheduled result includes a `capsule_delivery` record with the selected ESRT entry and either the verified delivery route for the current boot ID or a blocking reason. Under the shared Host lifecycle lease, the updater checks Secure Boot, capsule-on-disk support, pending EFI indications, boot priority and the exact GPT ESP carried forward by the verified initramfs. It blocks delivery if ESRT records an earlier attempt at the target version or the target is below the ESRT floor.

The verified initramfs mounts only the selected ESP read-only for inspection. The updater verifies the mounted device identity and rejects any existing entry in `EFI/UpdateCapsule`. A matched result reports the available ESP bytes and the required allowance of twice the verified firmware payload size plus 1 MiB. [UEFI capsule-on-disk delivery](https://uefi.org/specs/UEFI/2.11/08_Services_Runtime_Services.html#delivery-of-capsules-via-file-on-mass-storage-device)

The same check reads nonvolatile variable capacity and boot variables from one pinned efivarfs mount. It reports the available bytes after the kernel reserve and requires 256 bytes for setting and restoring `OsIndications`. Missing or inconsistent capacity counters and a disabled x86 reserve block delivery. The capacity observation must be refreshed before any future write. Firmware-specific write behavior, device authentication, power and post-update TPM authorization still require qualification. [Linux efivarfs capacity accounting](https://github.com/torvalds/linux/blob/master/fs/efivarfs/super.c)

An active `firmware-update/activation.json` record on the authenticated Host pool fences Guest startup, capture, and ordinary Host update and reboot operations. The scheduled firmware service reconciles that record before reading the update depot. It distinguishes an interrupted `draining` phase from a write that could have reached the device. If it can acquire the lifecycle lease after recorded flashing was interrupted, it durably records `outcome-unknown` and preserves the original operation, boot, device and signed offer identity. Reboot and power-transition states stay pending. The service retains the staged cabinet and reports the active operation in `firmware-update-status.json`.

Scheduled staging refreshes the native cabinet and live device checks under the same Host lifecycle lease as the EFI route, measured boot, storage and power checks. The `boot_transition` status reports whether the current boot and mirror match the signed `before` policy. Recovery checks the transition retained with the pinned offer and compares the resulting boot and mirror to its `after` policy. Each comparison requires an exact policy match and two mirror members with zero recorded errors.

The owner's signed `maintenance` object uses `timezone`, `start_minute`, and `end_minute`. Its default window is 04:00–05:00 Europe/Berlin. Scheduled `operational_preflight` checks the qualified delivery sequence, live boot and storage, and required power before evaluating timing. A TPM transition that requires preparation reports `recovery-needed`. The timing check accepts a security offer outside the routine window once those prerequisites pass. An offer requiring mains uses the kernel's online mains reading. A continuity requirement stays blocked until a qualified power source can attest it. The preflight currently checks capsule-on-disk with one reboot and reports other qualified sequences as unavailable. [Linux power supply class](https://docs.kernel.org/power/power_supply_class.html)

After a different Linux boot, recovery checks the digest of the original staged offer and reads the exact device from the pinned fwupd peer. A capsule operation also needs the pre-flash `esrt_before` entry in its activation record. Recovery compares the installed version with ESRT's version and last-attempt fields and reports its assessment under `recovery_evidence`. An NVMe version observation requires additional controller-specific result evidence. [UEFI ESRT fields](https://uefi.org/specs/UEFI/2.11/23_Firmware_Update_and_Reporting.html)

Recovery also rechecks the retained recovery document and reports the authorized procedure and retry allowance. The lifecycle interlock keeps ambiguous writes pending for device-specific reconciliation.

The enrolled Host gives fwupd a private history directory under `firmware-update` on the authenticated Btrfs pool. `GetFvcaResult` reads the recorded terminal result for one device and requires the activation's transaction ID and offer SHA-256. It returns the stored target version, protocol and state without adding current catalog data. The activation implementation must write the reserved fwupd history metadata key `FvcaOperation` as `TRANSACTION:OFFER_SHA256` before starting the device operation. Recovery reports `fwupd_history` and treats a matching history result that disagrees with the live version as a conflict. [fwupd history implementation](https://github.com/fwupd/fwupd/blob/2.1.10/src/fu-history.c)

On a firmware-enrolled boot, the signed Host initramfs reads the enrolled TPM rollback floor and SHA-256 bank PCR 7 from the same TPM before automatic unlock. It issues a boot receipt after accepting the release epoch, verifying both roots, and opening both integrity-protected volumes under the signed TPM automatic-unlock policy. Recovery ties that receipt to the running boot and mounted Btrfs pool. It checks the ordinary Secure Boot route, enforcing SELinux, signed dm-verity roots and writable RAID1 data, metadata and system allocations. The nested `boot_evidence` reports the two live members and their persistent error counters. [Linux Btrfs device state](https://github.com/torvalds/linux/blob/master/fs/btrfs/sysfs.c)

A recorded one-reboot capsule operation can reach `verified-success` after a different boot. The exact fwupd result, live ESRT result, signed after-boot policy, healthy Btrfs mirror, and empty capsule queue must agree. The updater synchronizes `activation-result-TRANSACTION.json` on the authenticated pool before removing the activation fence and retires the completed capsule's cabinet. On a recovery boot the initramfs prepares the lifecycle lease and verifies the Guest's selected boot bundle. The dedicated local recovery service starts the Guest after it releases the fence. [systemd unit activation](https://www.freedesktop.org/software/systemd/man/262/systemd.unit.html#OnSuccess=)

### Build the Host core with firmware discovery

```sh
./tools/fetch-fwupd.sh
mkosi --profile=hypervisor-core --output-dir=build/hypervisor-core build
python3 tools/verify-base.py build/hypervisor-core/fvca-dev-host-core.raw mkosi.crt
```

Use `fvca-dev-host-core.raw` for Hypervisor runtime extraction and composition. The profile builds pinned fwupd source offline with only the `nvme` and `uefi_capsule` plugins and disables external plugin loading. It includes the LVFS trust roots and declares both native daemons’ hardened allocator dependency. The Host initramfs loads the firmware SELinux policy before switch-root. The Service Guest profile omits this component, and Guest composition rejects a core carrying it. [fwupd 2.1.10 release](https://github.com/fwupd/fwupd/releases/tag/2.1.10)

Start `fvca-fwupd.service` on the enrolled Host before running the live staging command. The root-only bus permits property reads, inventory, exact-device upgrade and operation-result lookups, import of two sealed LVFS catalog descriptors and verification of one sealed cabinet descriptor. The daemon keeps the verified catalog in its private runtime directory, which systemd removes when the service stops. Physical device access and firmware activation still require qualification. [D-Bus policy documentation](https://dbus.freedesktop.org/doc/dbus-daemon.1.html#configuration_file)

## Hypervisor runtime candidate

The separate mkosi recipe builds `vm-runtime.raw`, a signed EROFS system extension. It contains QEMU, the modular libvirt QEMU, log and lock daemons, the selected OVMF firmware, restic, and `/usr/libexec/fvca/release-client`. The release client checks the hardened allocator before running. It uses a bundled IANA time-zone database and the native EFI helpers in the verified runtime. The VMM is built offline from the pinned upstream QEMU release and the build checks that KVM is its only accelerator. The development appliance uses private UNIX sockets for libvirt and requires SELinux confinement for QEMU processes. The build strips Fedora's automatic service hooks and management commands before signing, records the exact core root hash in the extension and checks the shared package versions. [QEMU release archive and signing key](https://www.qemu.org/download/)

Vendor the locked release-client sources into `build/release-client-vendor/sources` using the command above. Prepare a fresh base input from the verified development disk, and use a separate development certificate for the runtime. Keep the private key in the ignored build directory.

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

### Authorize a prepared Hypervisor trial under a standing key

Compose both ordinary slots with `--boot-trial-public-key PUBLIC_KEY_PEM`, authenticated PIN-less TPM storage, and a protected release epoch. Keep the Ed25519 private key with the off-node trial issuer. It must be distinct from the boot, runtime, Guest release, and promotion keys. The candidate uses `--boot-trial-candidate FILE` to bind its transaction and slot pair. The stable UKI pins the trial key and can receive a new authorization through the encrypted Host Btrfs inbox.

The issuer reviews the prepared candidate and the running stable release, then prepends the following header to the exact `FVCA-HYPERVISOR-TRIAL-2` record above. Measure `/EFI/BOOT/BOOTX64.EFI` within the prepared ESP and include the GPT UUIDs for each candidate data and verity partition. Use the verity root reported by `tools/pack-guest-boot.py` for each Guest bundle field. Use Unix seconds from a trusted clock. The authorization lasts at most 24 hours and both releases must use the named TPM counter policy.

```text
FVCA-HYPERVISOR-STANDING-TRIAL-2
not_before=1795154400
expires=1795156200
stable_epoch=17
candidate_epoch=18
epoch_policy_sha256=ENROLLED_COUNTER_POLICY_SHA256
stable_core=STABLE_CORE_VERITY_ROOT
stable_runtime=STABLE_RUNTIME_VERITY_ROOT
stable_guest_bundle=STABLE_GUEST_BUNDLE_VERITY_ROOT
candidate_uki_sha256=CANDIDATE_BOOTX64_EFI_SHA256
candidate_uki_bytes=CANDIDATE_BOOTX64_EFI_LENGTH_IN_BYTES
candidate_core_devices=CORE_DATA_UUID,CORE_VERITY_UUID
candidate_runtime_devices=RUNTIME_DATA_UUID,RUNTIME_VERITY_UUID
candidate_guest_devices=GUEST_BOOT_DATA_UUID,GUEST_BOOT_VERITY_UUID
```

Sign the complete bytes with Ed25519 and prefix the body with the 64-byte detached signature. The envelope is at most 2048 bytes. Publish it as `boot-trials/pending-trial` through the authorized maintenance path. The directory is root-owned with mode `0700`. Publish a regular root-owned file with mode `0600` via atomic rename and flush the file and directory. [OpenSSL Ed25519 signing](https://docs.openssl.org/3.5/man1/openssl-pkeyutl/)

The stable initramfs verifies the running release, both EFI entries, the watchdog and the signed candidate. It verifies the complete ESP on the first attempt and checks the exact UKI and all three verity trees on every attempt. It flushes a numbered reservation before writing `BootNext` and flushes the arming record after reading it back. It then requests a reboot and inhibits switch-root. The candidate verifies the signed envelope and its own epoch, partitions and roots before recording the boot ID against that reservation. Stable closes the previous reservation on return even if the candidate reset before unlocking storage. A matching health receipt ends retries and permits independently authorized promotion. After three unsuccessful reservations, stable retires the pending envelope, retains the consumed transaction and starts its Guest.

`tests/check-hypervisor-standing-trial.py` uses a disposable enrolled software TPM, two signed 4Kn boot images and matching authenticated Btrfs members. It exercises signature, expiry and stable-release refusal. Its approved run observes the stable initramfs reboot into the candidate, which unlocks storage without a PIN and records Guest health. A subsequent stable boot exercises replay of the consumed trial.

Compose standing candidates with `--boot-trial-watchdog-seconds SECONDS` to sign a health deadline of 10–300 seconds into the UKI. The current profile uses an i6300ESB watchdog. The Hypervisor initrd arms it after verifying EFI candidate selection and before checking the TPM floor or unlocking Host storage. Verified Guest readiness and the matching durable trial record authorize disarming it. A timeout resets to the stable entry in the EFI boot order.

`tests/check-hypervisor-watchdog.py` uses a signed 10-second candidate and a signed 180-second candidate with the emulated i6300ESB. It checks QMP for three reset events followed by stable recovery and confirms that the healthy candidate disarms the timer and records health on its first attempt.

For live activation qualification, build the stable UKI with the initramfs produced by `tests/nested-guest-shutdown-initrd.sh INPUT_INITRAMFS OUTPUT_INITRAMFS online-trial`. Use the original initramfs for the candidate and pass `--online-handoff` to the standing trial test. The additional checks cover a tampered approval, capture contention, failure to queue the reboot, restart of the stable Guest, and a successful retry through candidate health.

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

### Trial a staged direct-boot Guest release

Enroll a distinct Ed25519 Guest trial authority and the current Guest epoch with `--guest-trial-public-key` and `--guest-trial-epoch` when composing the Hypervisor. This profile requires authenticated Host storage and an authorized Service Guest. Use `tools/sign-guest-trial.py` off-node with an exact candidate `guest-boot.raw`, the two public certificates that authorize its Guest release and dm-verity image, and the independent trial signing key. Supply the current bundle and epoch, the candidate epoch, the validity interval and a 10–300 second health deadline. Use `--compatible-data` after reviewing both releases against the current mutable data.

Place the approval at `/run/fvca/host-data/guest-updates/pending-trial` and the exact candidate at `/run/fvca/host-data/guest-updates/BUNDLE_ROOT/guest-boot.raw` through the authorized staging path. The directories are root-owned with mode `0700` and the files are private regular files. Run `fvca-verify-guest-trial.service` to authenticate the approval and check the candidate digest, signed dm-verity mount and complete direct-boot inventory. The service uses a private mount namespace while the current Guest continues running. [systemd-dissect](https://www.freedesktop.org/software/systemd/man/latest/systemd-dissect.html)

Use the `guest-trial` mode of `tests/nested-guest-shutdown-initrd.sh` and run `tests/check-guest-trial.py` against a disposable Secure Boot Hypervisor and an authenticated Btrfs fixture. The test checks the approved candidate, a damaged signature and a signed image digest mismatch against the same running Guest.

Start `fvca-activate-guest-trial.service` to activate the authorized candidate. The controller verifies the candidate and stable boot files, acquires the Guest lifecycle lease, and confirms a clean shutdown of the running Guest. It records each attempt on Btrfs before letting a separate Host systemd unit boot the candidate. Host systemd kills a trial worker that exceeds the signed deadline. The controller stops the failed VM, reclaims the disk attachment and retries up to three attempts for the candidate bundle.

After verified boot and Guest-agent readiness, the controller commits the exact signed approval as the active Guest selection. Ordinary startup revalidates and mounts the committed bundle from the Host pool. When attempts are exhausted or activation is interrupted before commit, the controller or its recovery handler starts the last authorized active bundle on the same writable data disk.

Use the `guest-trial-activation` initrd mode and pass `--activation commit` or `--activation exhaust` to the KVM test. These cases check the successful commit and three Host-enforced timeouts. Both then boot the Hypervisor again from their existing Btrfs members and check the selected Guest.

### Enroll automatic Service Guest updates

Compose the ordinary Hypervisor with `--guest-os-update-owner owner.public` and the independent Guest trial key and epoch. This enables a Host timer for the `service-guest` OS release channel. Provision a private root-owned `/run/fvca/host-data/guest-os-update` directory with the signed policy, its detached signature, the pinned TUF root, the depot configuration and `active-os-release.json`. The active record includes the baseline Guest's `guest_bundle` root hash, role, epoch, release manifest digest and channel sequence. Its bundle and epoch must match the signed boot selection. Use `/run/fvca/host-data/guest-os-update/depot` for a local depot. For HTTPS, compose with `--guest-os-update-address IP --guest-os-update-ca CA.pem` and use that literal IP and `/run/fvca/guest-os-update-ca.pem` in the signed depot configuration.

Pin the enrolled independent Guest trial key as `trial_key_ed25519` in the owner policy. In the independently signed channel announcement, set `trial_approval` to the envelope's exact `bytes` and `sha256`. Publish the envelope as `service-guest-EPOCH-MANIFEST_SHA256-guest-trial.bin`. The Service Guest release manifest covers the entire direct-boot bundle and its qualification evidence.

`fvca-guest-os-update.timer` checks after boot and hourly with bounded jitter. The release client stages the exact qualified image, then requests the existing Host trial service once the activation is eligible. Routine activation follows the signed maintenance window. Security activation can start as soon as the release is eligible. The Host keeps the writable Guest data disk attached to only one instance at a time. After commit, the next check reconciles the active channel record with the signed Guest selection and removes superseded download staging. Status is recorded in `guest-os-update/os-update-status.json`. The committed Guest bundle and its recovery dependencies stay available on the Host pool.

The updater saves a receipt named `channel-release-ENVELOPE_SHA256.json` alongside each delivered bundle. While the lifecycle lease is idle, a newer qualified channel sequence can replace an earlier channel-owned approval for the same active release. Independently staged approvals require their own reconciliation. A qualified channel withdrawal retires its pending approval. Retirement is recorded before the inbox changes, so an interrupted cleanup can resume on the next check. Cleanup preserves the active image, its fallback, the current pending image and the numbered attempt records.

Run `tests/check-guest-os-update.py` with the TUF fixture environment, a disposable enrolled Hypervisor image, an authenticated storage fixture and its test trial and owner keys. Use `--routine` to exercise staging outside the configured window. The default run exercises a security candidate and checks its active channel record after the next Hypervisor boot. Supply `--previous-approval` and `--previous-image` to seed a previous handoff, with `--withdraw` for a signed channel withdrawal or `--independent` to check that the updater preserves an independently staged approval.

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

The disposable fixture flips ciphertext beneath each member's primary Btrfs superblock and requires both decrypted reads to fail with zero bytes returned. It cuts VM power after a flushed record and subsequent writes, then verifies the retained record and scrubs the remounted pool. It also exercises single-member recovery and replacement. Use the same `tests/check-storage.py` command with the authenticated lab and its signed images to check Secure Boot activation, rejection of the plain member, and boot with the replacement. Physical NVMe interruption, TPM enrollment on the target platform, and performance qualification remain release gates.

### Select the Host TPM unlock profile

Select `unlock=tpm2-auto` for normal unattended operation or `unlock=tpm2-pin` for attended boot. After the Btrfs filesystem identity, add `token_a=INDEX,SHA256` and `token_b=INDEX,SHA256` to the storage selection. Each digest covers the exact `cryptsetup token export` output from that member. Pass the selection with `--storage`, the two exports with `--tpm-token-a` and `--tpm-token-b`, and the RSA PCR signing key with `--pcr-key`. The assembler checks the unlock profile, SHA-256 PCR bank, direct PCRs 7, 12 and 13, signed PCR 11, and policy reference. It signs PCR 11 only for the `enter-initrd` phase. [systemd-cryptenroll](https://www.freedesktop.org/software/systemd/man/262/systemd-cryptenroll.html)

The PIN-less profile requires authenticated LUKS2 storage and a protected Hypervisor epoch on every release, including fallback and recovery. Use a fresh PCR signing key reserved for `fvca-host-storage-auto-v1` and a Secure Boot authority scoped to boot paths that enforce that epoch. The signed initramfs verifies a private copy of each LUKS2 header, then presents only the selected token to cryptsetup, with no input or network service. Attended enrollment uses `--tpm2-with-pin=yes`, Argon2id PIN hardening, and the separate `fvca-host-storage` policy purpose. Changing profiles requires a separately authorized enrollment and verification of historical unlock paths.

In the disposable enrollment environment, use the target firmware and its Secure Boot keys. A measured systemd initramfs applies the `os-separator` event automatically. A minimal lab initramfs must apply that same event to PCRs 7, 12 and 13 before enrollment. Preserve the separate recovery credential. [systemd PCR phase and separator](https://www.freedesktop.org/software/systemd/man/262/systemd-pcrphase.service.html)

In the disposable enrollment guest, enroll the two LUKS2 partitions individually. Supply the fixture recovery key and the public half of the separate PCR signing key. The example exports the first token on each fresh fixture member.

```sh
for member in a b; do
  partition="/dev/vd${member}1"
  systemd-cryptenroll "$partition" --unlock-key-file=storage.key \
    --tpm2-device=/dev/tpmrm0 --tpm2-with-pin=no \
    --tpm2-pcrs=7:sha256+12:sha256+13:sha256 --tpm2-public-key=pcr-public.pem \
    --tpm2-public-key-pcrs=11 --tpm2-public-key-policyref=fvca-host-storage-auto-v1
  cryptsetup token export --token-id=0 "$partition" > "token-${member}.json"
  sha256sum "token-${member}.json"
done
```

Run `python3 tests/check-hypervisor-epoch.py --auto-unlock` with two independently composed and signed UKIs and the same PIN-less member enrollments. The VM has no network, and the test sends no console input. The check requires both authenticated Btrfs mappings to activate at the approved floor and tests refusal of an older UKI, a missing or invalid floor, an absent TPM, and an extra measured command-line input. The separate attended storage lab takes `--tpm-state` for its enrolled software TPM and `--pin-file` for the disposable PIN.

Physical TPM qualification and retirement of historical unlock paths remain release gates. An intact stolen machine can boot an approved release and unlock its storage under `tpm2-auto`. Access to the unlocked data then depends on the platform's runtime access controls.

The Hypervisor initramfs omits systemd's stock NvPCR definitions. The storage PCR authority authorizes only LUKS2 unsealing.

The shared SELinux policy switches Fedora's PCR measurement domain to enforcing. Both the initramfs and the core verify the domain against the policy loaded in the kernel. On a measured boot, systemd prepares the root-only, separately labeled log at `/run/log/systemd/tpm2-measure.log` before the first userspace PCR measurements.

### Enforce the Hypervisor epoch floor at boot

Compose the stable slot and its recovery release with `--epoch-policy FILE`, GPT slots, and authenticated TPM storage. Use a dedicated Secure Boot authority for this deployment. Enroll only authorities whose trusted boot paths enforce the epoch gate. Every signed Hypervisor boot path, including recovery, must carry the policy. Keep control of the TPM owner hierarchy separate from release and storage signing.

```text
FVCA-HYPERVISOR-EPOCH-1
epoch=2
policy_sha256=ENROLLED_TPM_POLICY_DIGEST_AS_64_LOWERCASE_HEX_DIGITS
```

The signed initramfs selects a release epoch and the public authorization policy of TPM NV counter `0x01504656`. The composer writes the same selection into the signed UKI command line for inspection during installation. At boot, the initramfs requires an exact match between the command-line selection and its signed policy. The counter must be initialized, use SHA-256 and eight bytes, and permit writes only through a TPM policy session. The epoch counts from the actual value read after TPM initialization. The initramfs verifies the selected GPT slot first, then checks the counter before using either TPM storage token or activating the VM runtime. A missing TPM, missing or uninitialized counter, policy mismatch, or release below the floor stops boot. Restoring disks or EFI variables leaves hardware TPM NV state in place. [TCG TPM 2.0 Library Architecture](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf) · [TPM NV attributes](https://tpm2-tools.readthedocs.io/en/latest/man/common/nv-attrs/)

Run `bash tests/prepare-hypervisor-epoch-tpm.sh` to create disposable copies of an enrolled software TPM at the initial floor, the next floor, and with an uninitialized counter. The fixture uses `PolicySigned` with a dedicated P-256 key, a per-enrollment policy reference, the live session nonce, a positive expiration, and the command hash for `NV_Increment`. It closes the session on increment and tests unsigned writes, use of the signature in a competing session, and replay after consumption. Compose two signed slots from the generated epoch policies and a third with a different policy digest. Run `python3 tests/check-hypervisor-epoch.py` with those slots, the original TPM-enrolled encrypted members, and the same enrolled firmware. Select `--auto-unlock` for the headless profile or `--pin-file` for an attended fixture. Pass `--paired-slots A B` to also boot both provisioned disks from a successful same-epoch installation at each floor. Each paired slot must carry the higher epoch and its own encrypted member. The test opens its own software TPM copies and captures serial logs for each boot. [TPM 2.0 PolicySigned](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_3_Version_184_pub_2337d80b91.pdf) · [tpm2_policysigned](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_policysigned.1.md)

### Verify the installed pair for a floor approval

Have the independent release authority review the qualification evidence for both boot paths. Bind the evidence digest for each boot, the two staged release manifests, the reviewed GPT records, the exact Secure Boot certificate, and the enrolled TPM policy in one signed approval. `valid_from` and `expires` use Unix seconds on the trusted maintenance clock, with a maximum validity of 24 hours. `next_floor` advances `previous_floor` by one. Both signed releases must meet the next floor.

```json
{
  "schema": "fvca-hypervisor-floor-approval-v1",
  "valid_from": 1795154400,
  "expires": 1795156200,
  "sector_size": 4096,
  "secure_boot_certificate_sha256": "CERTIFICATE_SHA256",
  "epoch_policy_sha256": "ENROLLED_TPM_POLICY_DIGEST",
  "previous_floor": 1,
  "next_floor": 2,
  "primary": {
    "epoch": 2,
    "manifest_sha256": "PRIMARY_MANIFEST_SHA256",
    "boot_evidence_sha256": "PRIMARY_BOOT_EVIDENCE_SHA256",
    "disk": {"path": "/dev/disk/by-id/PRIMARY_NVME", "gpt_sha256": "PRIMARY_GPT_SHA256"}
  },
  "recovery": {
    "epoch": 2,
    "manifest_sha256": "RECOVERY_MANIFEST_SHA256",
    "boot_evidence_sha256": "RECOVERY_BOOT_EVIDENCE_SHA256",
    "disk": {"path": "/dev/disk/by-id/RECOVERY_NVME", "gpt_sha256": "RECOVERY_GPT_SHA256"}
  }
}
```

Sign the exact approval bytes with the independent Ed25519 authority. Supply the raw 64-byte signature and the raw 32-byte trusted public key provisioned on the maintenance system. Run the read-only check with both NVMe namespaces unused and both manifests in the private TUF staging directory.

```sh
fvca-release-client --verify-hypervisor-floor-approval intake-state approval.json approval.sig authority.pub secure-boot.pem
```

The command independently verifies the approval signature and checks both installed disks against the staged releases. It holds both disk leases, verifies each Secure Boot loader and its signed epoch against the approved enrollment, and reads back all immutable payloads before printing the approval digest. The approving authority retains and verifies the boot evidence referenced by the signed digests. Run `tests/check-hypervisor-floor-approval.py` against the installer output and paired boot logs to qualify the workflow with disposable keys.

### Commit the approved TPM floor

Use the maintenance system on the enrolled Hypervisor with both reviewed NVMe namespaces unused and the two approved releases staged. The release client uses Fedora's `tpm2-tss` through `/dev/tpmrm0`. Provide the enrollment's P-256 `TPM2B_PUBLIC` blob and 40-byte policy reference. The enrollment reference is `FVCA-HYPERVISOR-FLOOR-1` followed by a NUL byte and a per-appliance random 16-byte value. The enrolled policy combines `PolicySigned` for that key and reference with `PolicyCommandCode(NV_Increment)`. Export the loaded key with `tpm2_readpublic --format=tss --output increment.tpm2b`. Keep the P-256 private key with the independent increment authority. [Fedora TPM stack](https://packages.fedoraproject.org/pkgs/tpm2-tss/tpm2-tss/) · [TPM 2.0 PolicySigned](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_3_Version_184_pub_2337d80b91.pdf)

```sh
fvca-release-client --advance-hypervisor-floor intake-state approval.json approval.sig authority.pub \
  secure-boot.pem increment.tpm2b policy-reference.bin
```

After readback of both disks and verification of the live TPM counter, the command prints `FVCA_HYPERVISOR_FLOOR_CHALLENGE` followed by JSON. The increment authority checks the approval digest, the proposed floor step, and its outstanding authorization for that enrollment. The decoded `message` contains the 32-byte nonce, a four-byte positive big-endian expiration in seconds, the SHA-256 command hash for `NV_Increment` on the enrolled index, and the enrollment reference. Check these fields and sign the decoded bytes with P-256 ECDSA and SHA-256. Issue one live nonce authorization per enrollment. After interruption, confirm the old authorization expired and read back the floor before replacing an outstanding authorization. Enter the 128 hexadecimal characters of the raw `r || s` signature followed by a newline while the command is waiting. Each scalar uses 32 big-endian bytes. The TPM authorization expires within five minutes.

The client holds both disk leases and the staging lock through authorization, a durable intent, the single increment, and its readback. It writes the outcome under `intake-state/floor-transactions/` and prints `FVCA_HYPERVISOR_FLOOR_COMMITTED` with the observed floor and approval digest. After an interruption, the same signed approval reconciles a matching intent and a TPM already at the target floor without issuing another increment. If the TPM still reads the previous floor, it requires a fresh signature in a new session while the approval is valid.

Build a separate qualification binary with `--features swtpm-test` for `tests/check-hypervisor-floor-advance.py`. The test uses disposable disk copies, approval keys, and software TPM state. The default release binary requires two reviewed NVMe namespaces and the local hardware TPM device. Physical TPM qualification remains pending.

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
mkdir -p build/release-client-vendor
cargo vendor --locked --versioned-dirs --manifest-path release-client/Cargo.toml \
  "$PWD/build/release-client-vendor/sources" > build/release-client-vendor/config.toml
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

Qualify a self-contained 4 KiB GPT slot with the disposable authenticated mirror and its enrolled software TPM state.

```sh
python3 tests/check-storage.py --nested-guest-tpm-auto \
  --disk HOST_GPT_SLOT --variables ENROLLED_OVMF_VARS --firmware OVMF_SECBOOT_CODE \
  --lab HOST_MIRROR_FIXTURE --tpm-state STOPPED_SWTPM_STATE --output NEW_OUTPUT_DIRECTORY
```

Seed the Guest Btrfs disk to match the selected release. A workload-bearing release requires its signed workload files and provisioned volumes before the Guest can reach readiness. The check requires the Host epoch gate, unattended unlock, authenticated RAID1, an enforcing sVirt Guest and Guest agent readiness before the Host reports ready.

To qualify a provisioned pair, supply the other GPT slot with `--peer-slot PEER_GPT_SLOT` in place of `--lab`. Run the check in both directions. It verifies that the requested slot's ESP booted and that the integrated members unlock the same Btrfs mirror.

To configure CPU and RAM for the registered VM, pass `--guest-vm-settings PATH` when composing the Hypervisor. The file accepts this JSON object.

```json
{
  "schema": "fvca-service-guest-vm-v2",
  "guest": "e629aa43-af11-47c6-aedc-a2dc47f1cc3a",
  "configuration_revision": 1,
  "vcpus": 3,
  "memory_mib": 2560
}
```

The fixed direct-boot profile accepts one to four vCPUs and 1,024–4,096 MiB in increments of 256 MiB. Its default is two vCPUs and 2,048 MiB. The composer binds the revision and SHA-256 of the canonical settings record to the signed Host UKI. An ordinary standing Host update must preserve the exact revision, digest and enrolled configuration authority. Guest release trials and ordinary Guest OS updates use the same Host settings. The launcher reconstructs the fixed machine definition and requires enough available Host CPUs and memory for the selected Guest plus a 1,024 MiB Host reserve and 512 MiB QEMU reserve.

On the Hypervisor, `/usr/libexec/fvca/release-client --guest-configuration-status` reports the boot-selected revision, digest, and resource values. The default profile has null revision and digest. This read-only status reports the Host boot selection independently of Guest readiness and release generations.

#### Change CPU and memory through a standing Host trial

During provisioning, compose both slots with the same `--guest-configuration-public-key configuration.public.pem`, their respective `--os-update-peer-slot`, and the standing OS update, trial and promotion authorities. Keep the Ed25519 configuration signing key off the Host and separate from the boot, release, policy, trial and promotion keys.

After the authenticated OpenTofu apply reports a pending operation, export the three configuration outputs from the managed state. Give the tool the independently retained `management.json` enrollment associated with the reviewed Host slots. It recomputes the canonical settings digests and operation ID before preparing the next revision for the composer.

```sh
umask 077
tofu -chdir=opentofu/examples/plan output -json | jq -e '{
  active_configuration: .active_configuration.value,
  planned_configuration: .planned_configuration.value,
  configuration_operation: .configuration_operation.value
}' > pending-configuration.json
python3 -B -W error tools/authorize-guest-configuration.py prepare \
  --outputs pending-configuration.json --enrollment management.json --output candidate-settings.json
```

Compose the exact candidate with `--guest-vm-settings candidate-settings.json`. Generate the separately signed standing trial and promotion approval for the reviewed pair. On the configuration signing workstation, use the reviewed slot images, the independently pinned Secure Boot certificate, and the distinct configuration key. The tool verifies the UKI signatures, enrolled management and configuration authorities, selected settings, and the standing trial's fresh signature and exact candidate ESP and loader before publishing the approval file.

```sh
python3 -B -W error tools/authorize-guest-configuration.py authorize \
  --outputs pending-configuration.json --enrollment management.json \
  --stable stable.raw --candidate candidate.raw --boot-certificate secure-boot.pem \
  --trial approvals/boot-trial.bin --configuration-key configuration.key \
  --output approvals/guest-configuration-change.bin
```

The exported outputs are review inputs. The scheduled updater independently checks the durable broker-admitted operation, expected revision and exact signed UKIs before writing the peer slot. The independently qualified TUF release uses `guest_configuration_change` alongside the trial and promotion approvals. `accepted_guest_configuration_revision` reports acceptance into the trial inbox. The Host commits the revision after the authorized trial passes local Guest health and the promoted boot verifies the approval. A superseded slot cannot start the Guest with its old settings after commitment.

Run `python3 -B -W error tests/check-guest-configuration-handoff.py -v` on the Fedora review workstation to exercise signing and refusal cases using disposable Secure Boot keys and 4 KiB GPT slots. The fixture verifies authorization without booting the images.

#### Host management service

The verified Hypervisor initrd installs a default-deny nftables policy for IPv4, IPv6 and bridge traffic. Without an uplink enrollment it permits loopback IP traffic only. For a physical management uplink, pass `--host-network FILE` with a record in this format. Use the same record for both Host slots.

```text
FVCA-HOST-NETWORK-1
pci=0000:03:00.0
mac=02:fc:00:00:00:01
address=192.168.44.15/24
gateway=192.168.44.1
operator=192.168.44.20
```

Replace the example PCI address and MAC with the selected NIC's PCI address and permanent MAC. Set `gateway=none` for an on-link deployment and `operator=none` when management is local or disabled. A remote management listener must equal the uplink's IPv4 address. Its TCP port accepts new connections only from the signed operator address on the selected NIC. Host-initiated traffic on that NIC is limited to the enrolled HTTPS update destinations on port 443 and the enrolled S3 address and port. The initrd applies filtering before activating the link. Standing updates preserve the uplink record. This profile covers Host management and depot traffic. [nftables reference](https://netfilter.org/projects/nftables/manpage.html)

`compose-hypervisor.py --management-enrollment FILE` binds the exact enrollment JSON and listener address to the signed Hypervisor UKI. Supply the same file for both slots. Its schema is `fvca-hypervisor-management-v1` and its fields are `host` (enrolled Host UUID), `address` (literal private or loopback IP with port 1024–65535), `gateway_uid` and `gateway_gid` (both `62000`), `tls_certificate_sha256` (leaf certificate DER digest), and `operator_public_key` (hex-encoded Ed25519 public key dedicated to status and preflight). The initrd publishes the verified record at `/run/fvca/management.json`. Standing Host updates preserve this enrollment. Operator or certificate changes require explicit enrollment.

From trusted Host maintenance, stage the PEM chain as `management/tls.crt` and the PEM private key as `management/tls.key` on the authenticated Hypervisor Btrfs pool. Use `root:root` ownership, mode `0700` on `management/`, and mode `0600` on the two regular files. At boot the initrd enables the listener only when the signed enrollment and protected credential files are present. systemd copies the credentials into the unprivileged gateway's credential mount and passes it the enrolled TCP socket. The gateway runs in an enforcing SELinux domain and forwards authorized requests over `/run/fvca-management-broker/broker.sock`. The broker runs in a separate domain and checks the gateway's UID and GID. Both services use private network namespaces and can create only Unix sockets.

Connect with TLS 1.3, verify the enrolled server certificate and negotiate ALPN `fvca-management/1`. Each connection carries one request and response. Each frame starts with a four-byte big-endian length. The request frame contains the 64-byte Ed25519 signature followed by the exact UTF-8 JSON signed by the enrolled operator for that operation. The response frame contains JSON. Requests and responses are limited to 2,048 and 4,096 bytes, respectively.

```json
{
  "schema": "fvca-management-request-v1",
  "host": "367f5cbc-c46a-437d-af72-5d96d805d234",
  "guest": "e629aa43-af11-47c6-aedc-a2dc47f1cc3a",
  "nonce": "fef3d5c1b88198ab8fa6de0a55363735",
  "issued_at": 1795190400,
  "expires": 1795190430,
  "operation": {"type": "preflight", "expected": null, "vcpus": 3, "memory_mib": 2560}
}
```

Generate a fresh random nonce and use current Unix seconds with a validity window of at most 30 seconds. Use `{"type":"status"}` to read boot-selected settings, Host trial state and separate updater-owned release observations. For preflight, supply `expected: null` for the default profile or `expected: {"revision": 1, "sha256": "..."}` from status. The broker returns the candidate settings revision, its canonical digest and the required activation scope. A stale revision, a changed digest or a running Host trial produces a typed refusal. Check the `fvca-management-response-v1` schema, both identities and the echoed nonce on each response. Apply continues through the signed Host channel and trial described above.

To enable remote boot appraisal, add `attestation_operator_public_key` to the signed enrollment. Use a dedicated hex-encoded Ed25519 public key distinct from read, configuration and release authorities. Sign the usual management envelope with this key and set the operation to `{"type":"boot-quote","challenge":"NONCE_HEX"}`, where `NONCE_HEX` is the 64-character lowercase nonce issued by the separate verifier. The request envelope still carries its own fresh 16-byte nonce. For `result: "boot-quote"`, save the `evidence` object as JSON and pass it to `--appraise-boot-quote`. For `result: "refused"` with `code: "boot-quote-unavailable"`, the Host could not collect a quote.

The broker delegates only the 32-byte challenge to the SELinux-confined collector over its systemd activation socket. The collector serves one request per instance and its device allowlist grants access to `/dev/tpmrm0`. The gateway and broker keep their private device namespaces. [systemd socket activation](https://www.freedesktop.org/software/systemd/man/262/systemd.socket.html) · [systemd device controls](https://www.freedesktop.org/software/systemd/man/262/systemd.resource-control.html#DeviceAllow=)

The [off-node OpenTofu provider and module](opentofu/README.md) use this protocol for authenticated Guest configuration preflight and separate release observations.

Send `{"type":"os-release-status","role":"hypervisor"}` or select `"service-guest"` to read that role's recorded active release and last completed updater check. The check includes the candidate and staged manifest digests, disposition, last authenticated refresh, earliest expiry, and any hold, security deadline, or trial handoff recorded during that pass. The broker reports `fresh`, `expired`, `clock-regressed`, `superseded`, or `not-applicable` for the saved check. A different accepted policy or channel checkpoint, or a changed active record, makes the check superseded. Disposition and trial fields describe the saved check. The read opens a fixed set of status records.

The response reports `enrolled: false` for a role without signed update enrollment and `last_check: null` before the first recorded check. A check from an earlier status schema produces `os-release-status-unavailable` until the updater replaces it. Firmware observations use their dedicated operations.

Send `{"type":"host-firmware-status"}` with the management read key for firmware enrollment, the current activation identity and phase, and the last discovery or recovery check. A staged check reports the exact device, offer and archive digests, qualified source and target versions, and recorded eligibility. A recovery check can report the operation it assessed and the observed result. Check timestamps and freshness describe that observation. `last_check_unavailable` signals that the observer could not verify the saved check.

This operation remains available while a pending firmware activation fences Guest startup. A separate enforcing SELinux service reads bounded records on the authenticated Btrfs pool. The observer has read-only mounts and receives one private Unix connection from the broker. Its sandbox blocks the firmware buses. A `host-firmware-status-unavailable` reply means the observer could not read the current activation state.

The firmware status v2 response includes `qualification` for a staged offer and for an activation or recovery result with dated transition evidence. It reports `qualified_at`, the current `observed_at` and their difference in `age_seconds`. An activation whose dated evidence cannot be recovered or whose clock is earlier than the qualification retains its operation identity and reports null for qualification.

Send `{"type":"host-firmware-inventory"}` with the management read key to query installed firmware. Each page carries the fwupd version, observation time, device-list digest and one device. A device includes its fwupd ID, plugin, GUIDs, protocol and vendor IDs, installed version, and device flags for inhibition, reboot, shutdown and activation. A null device on the first page denotes a successful empty inventory. Pass `next` as `after` until `next` is null. A `firmware-inventory-changed` refusal means a live observation differs from the earlier page and the scan must start again.

The inventory collector runs under its own UID and SELinux domain. Its D-Bus policy permits device and property reads from the pinned fwupd owner with zero attached descriptors. The collector verifies the daemon's UID and SELinux context, and the writer bus is outside its mount namespace. An inventory read may be unavailable while fwupd hands off to the writer. [D-Bus peer credentials and policy](https://dbus.freedesktop.org/doc/dbus-specification.html#bus-messages-get-connection-selinux-security-context)

Send `{"type":"host-storage-health"}` with the enrolled read operator key to inspect the mounted Hypervisor Btrfs pool. The result `host-storage-health` returns the filesystem UUID, RAID1 profile and observed read-only state under `pool`. The `data`, `metadata` and `system` records each report logical `total_bytes` and `used_bytes` in allocated chunks. Each of the two `members` reports its Btrfs device ID, byte span visible to Btrfs, allocated bytes, and the kernel's cumulative write, read, flush, corruption and generation error counters. The request takes no arguments. A `host-storage-health-unavailable` refusal means a complete observation could not be made. [Linux Btrfs UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/btrfs.h)

#### Scheduled Btrfs scrub

Both roles enable `fvca-storage-scrub.timer` after verified data activation. The timer checks shortly after boot and weekly, with up to 30 minutes of jitter. A new attempt is due 30 days after the last receipt update. Verified boot sets a 64 MiB/s kernel scrub limit on each selected device. The worker checks that limit before each device and scans the Host mirror serially. Service Guest scans its single device, with repair available for replicated metadata and system chunks. [Btrfs scrub and bandwidth limits](https://btrfs.readthedocs.io/en/latest/Scrub.html)

The service journals `FVCA_BTRFS_SCRUB` and syncs a bounded receipt to `.fvca-scrub/report.json` on the verified data volume. The receipt records Unix start and finish times, completed members, data and metadata bytes scanned, blocks without checksums, and corrected and uncorrectable errors. The Hypervisor's `host-storage-health` includes that receipt as `pool.last_scrub`. A new pool returns `null` before its first run, and `scrub_history_unavailable` signals an unreadable or invalid receipt. An interrupted run retains partial progress and a power loss can leave `in-progress-or-interrupted` as its last recorded outcome. The per-scrub counts are independent of the cumulative device error counters.

#### Host workload uplink

For a connected Service Guest, pass `--workload-uplink FILE` along with `--guest-boot` to `compose-hypervisor.py`. Start the file with the dedicated workload NIC's PCI address and permanent MAC. Use the complete [Guest workload network record](#service-guest-workload-uplink) immediately after that header, starting on the next line. For a Hypervisor-managed Guest, use `pci=0000:00:06.0` in the Guest record. The Hypervisor checks the digest against the registered Guest release before signing and again on boot and trial admission.

```text
FVCA-HOST-WORKLOAD-1
pci=0000:04:00.0
mac=02:fc:00:00:00:02
```

Use distinct management and workload NICs, MAC addresses, and IPv4 subnets. Connect the workload NIC to its dedicated untagged network. The Hypervisor creates a bridge with no IP addresses and exactly two ports, the enrolled physical NIC and a fixed TAP. It filters transit by direction, the Guest's source and destination identity, approved peer and port, and connection state. The bridge admits ARP for approved neighbors including the enrolled gateway. Its host-facing chains drop traffic. Libvirt passes the pre-created TAP to the confined QEMU process with the userspace VirtIO backend. Standing updates preserve the exact Host workload enrollment. [Libvirt interface XML](https://libvirt.org/formatdomain.html#generic-ethernet-connection) · [nftables bridge filtering](https://wiki.nftables.org/wiki-nftables/index.php/Bridge_filtering)

#### Admit a planned Guest configuration

Add `apply_operator_public_key` to the signed management enrollment to authorize submission. Use a dedicated hex-encoded Ed25519 public key distinct from the read operator and the appliance's signing and release authorities. Writer enrollment requires the existing signed Host configuration-change path. Sign the request envelope with the submitter key and use this operation:

```json
{
  "type": "apply-configuration",
  "plan": {
    "expected": null,
    "next": {
      "revision": 1,
      "sha256": "d1bfe17ab1d4bba583943189bf1a98f40381038bf6b768d6d7ab0d4979b62b99"
    },
    "vcpus": 3,
    "memory_mib": 2560,
    "planned_at": 1795190400,
    "plan_expires": 1795191300
  }
}
```

Use the expected binding and candidate revision and digest from planning. Set the plan's Unix timestamps with a validity interval of at most 15 minutes. Keep the enclosing request within its separate 30-second validity interval. The broker checks the exact revision and digest, machine profile, Host resource capacity, and lifecycle lease before recording the signed intent on Host Btrfs. An accepted operation returns `pending-activation` with a stable `operation_id`. A fresh request for the same intent returns the existing operation. The broker accepts one pending intent at a time.

Use the read operator to request `{"type":"configuration-operation","operation_id":"..."}`. The returned configuration state can be `pending-activation`, `in-trial`, `active` or `superseded`. The broker retains the latest admitted operation. Guest health is covered by the standing trial and promotion protocol. With a submitter enrolled, the scheduled updater admits a configuration-changing release only when its independently signed configuration change matches the broker's admitted intent. The release publisher supplies the signed composition, trial, and promotion approvals through the TUF channel. Enable `manage_guest` in the OpenTofu module to submit a saved settings plan on apply.

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

### Commission the initial Service Guest disk

Prepare a raw Guest data disk for the Btrfs partition identity and filesystem UUID selected by the approved Guest release. During offline enrollment, place that exact file at `guest-commissioning/seed.raw` relative to the root of the authenticated Host Btrfs mirror. The directory and seed must be owned by root with modes `0700` and `0600` respectively. Use ordinary checksummed Btrfs storage for the seed and leave the registered Guest slot vacant.

Compose the ordinary stable Host UKI with `--guest-boot`, `--guest-release-certificate`, the authenticated `--storage` selection, and `--guest-commissioning-seed PATH` pointing to the original raw file. The composer checks the seed's GPT partition and Btrfs filesystem identities against the verified Guest initramfs. The UKI binds the fixed Guest UUID and exact verified Guest boot bundle to the seed's byte length and SHA-256. Use the Hypervisor initramfs and VM runtime built with commissioning support.

On boot the Host verifies the seed copy in a private Btrfs subvolume, flushes its identity to the commissioning journal, and moves it into the vacant registered slot. The Guest launch waits for installation and still requires separate Guest readiness. An interrupted install reconciles the same subvolume. Once the installation is durable, the Host retires the authorized seed. A later missing slot requires explicit recovery. The Host never mounts the Guest filesystem during commissioning.

For OpenTofu-managed commissioning, also pass `--managed-guest-commissioning` and `--management-enrollment FILE`. Add a dedicated Ed25519 public key as `commission_operator_public_key` in the enrollment. Use a key distinct from the management read, configuration and attestation keys and from release and boot authorities. Supply the exact approved Guest verity root, seed SHA-256, byte length and machine settings to the [OpenTofu commissioning resource](opentofu/README.md#commission-the-initial-service-guest).

The Host starts management while the Guest slot is vacant. After apply admits the signed offer, a fixed systemd unit starts the existing commissioning service. The durable operation stays `pending` until the Guest reaches startup readiness and answers the Guest agent check. A later boot with the same policy resumes the admitted operation. The installer checks whether the disk already exists before resuming. Inspect `fvca-commission-guest.service` and `fvca-service-guest.service` for a pending operation that fails to reach readiness.

For KVM qualification, prepare two authenticated mirrors from the approved seed and a same-length copy with an altered byte. Compose a 4 KiB GPT Host slot against the original file and the lab's `host-storage.conf`. Enroll the Host signing certificate in a disposable OVMF variable store.

```sh
tests/storage-lab.sh --commissioning APPROVED_LAB GUEST_DATA_RAW
tests/storage-lab.sh --commissioning ALTERED_LAB ALTERED_GUEST_DATA_RAW
python3 tests/check-guest-commissioning.py --disk HOST_GPT_RAW --variables OVMF_VARS \
  --lab APPROVED_LAB --altered-lab ALTERED_LAB --output NEW_RESULTS_DIRECTORY
```

The check requires normal Guest readiness after commissioning and again on a cold start with the same mirror. The altered seed must fail before the launcher starts a Guest.

For the managed KVM check, use a disposable TPM-enrolled mirror and a 4 KiB signed GPT slot composed with `--managed-guest-commissioning`. QEMU emulates an Intel NIC supported by the Hypervisor's `igb` driver. The signed management uplink selects PCI `0000:00:06.0`, MAC `52:54:00:35:5e:01`, address `10.0.2.15/24`, and operator address `10.0.2.2`. Use `gateway=none` and enroll the listener at `10.0.2.15:8443`. The test exposes it on an ephemeral loopback port through QEMU. Use `tests/storage-lab.sh --commissioning --management TLS_DIRECTORY` to stage the lab TLS chain and key before enrolling the mirror's TPM tokens.

The private lab directory contains `mirror/member-a.raw`, `mirror/member-b.raw`, `management.json`, `server-name`, `tls/ca.pem`, the mode-`0600` runner keys `keys/operator.key` and `keys/commission_operator.key`, and `tofu-mirror/` from the locked provider build. Supply the seed used at composition, the verified Guest bundle root, the TPM-measuring Secure Boot OVMF and its matching enrolled variables, and the stopped TPM state at its enrolled floor.

```sh
python3 -B tests/check-managed-guest-commissioning.py \
  --disk HOST_GPT_RAW --firmware OVMF_CODE --variables OVMF_VARS --tpm-state STOPPED_SWTPM_STATE \
  --lab LAB_DIRECTORY --seed GUEST_DATA_RAW --bundle-sha256 GUEST_VERITY_ROOT \
  --output NEW_EVIDENCE_DIRECTORY
```

The check refuses a plan for a different seed and an apply without the dedicated key. It requires the Host to stay reachable while the Guest slot is vacant, and verifies Guest agent readiness, the original operation after a cold boot and refusal of destroy. It also checks the enforcing audit log for unexpected access to the PCR measurement socket or the broker's cgroup filesystem. It discards the writable mirror copies, local provider installation, plans and state when the checks finish.

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

Send `{"type":"host-backup-status"}` with the enrolled management read key to check the signed scheduled job without starting work. `scheduled` contains the enrolled repository ID, the observation time, the last verified upload and its capture age, any pending capture, the last attempt failure flag, and the configured data loss and restore objectives. The age is recomputed from the original capture time when the broker answers. `last_verified_upload` is `null` before the first verified upload, and `scheduled` is `null` when the running Host has no enrolled job. `host-backup-status-unavailable` means the broker lacks a fresh observation for the enrolled repository and mounted pool. Use off-node verification to check current repository contents and restore results.

The job saves its pending UUID on the encrypted Hypervisor Btrfs mirror before capture. A retry after reboot reuses the acknowledged sealed snapshot. The launcher journals the attached disk's Btrfs and inode identities before handing it to libvirt. After an abrupt shutdown it reclaims that exact disk once the previous VM, PID file and bind mount are gone. Clean-stop receipts still require an orderly Guest shutdown.

If an interrupted attempt ended before creating any snapshot and the Guest operation lease is clear, the job records that attempt as abandoned and allocates a new UUID. An unacknowledged snapshot is preserved for reconciliation. A verified S3 receipt remains eligible for age reporting after local expiry.

### Inventory and expire local captures

Start `fvca-capture-list.service` to log the local capture catalog or `fvca-capture-inspect@CAPTURE_UUID.service` to inspect one capture. Finalized entries report capture time, disk SHA-256, Btrfs snapshot UUID and pending backup status. Expired entries retain their manifest and backup receipt for reference.

Use the enrolled management read key with `{"type":"host-local-captures"}` to list up to eight entries. Pass the previous result's `next` value as `after` for the following page. A `null` cursor marks the end. The cursor is scoped to the catalog directory in the current Btrfs pool. Pages follow filesystem enumeration order and can reflect changes made between calls. Send `{"type":"host-local-capture","capture_id":"CAPTURE_UUID"}` to inspect a single entry.

Both operations return `pending`, `complete`, `expiry-pending`, or `expired`. A complete entry reports the original capture time, its age in seconds, the achieved consistency class, snapshot identity, and disk digest from finalization. The broker checks the manifest, its sidecars, and the identity of the read-only Btrfs snapshot without reading the Guest disk. Entries marked for expiry have no local recovery-point age. The API reports the scheduled S3 recovery point through `host-backup-status`.

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

Review `derivation.json` and `launch.json`, then have the deployment authority sign the exact deployment document as detached DER CMS. The `fvca-workload-deployment-v2` document contains these fields.

| Fields | Approval scope |
| --- | --- |
| `schema`, `role`, `guest`, `service` | Schema version, `service-guest`, assigned Guest identity and service |
| `source_index`, `manifest`, `provenance`, `launch` | Exact index digest, platform digest, source classification, and launch digest from the reviewed derivation |
| `valid_from`, `expires`, `security_epoch`, `revocation_id` | Unix timestamps, positive epoch and revocation UUID |
| `id_map` | Approved subordinate `uid_base` and `gid_base`, each mapping a `size` of 65536 IDs from container ID zero |
| `network`, `limits` | `none` or `{"workload":"sha256:<profile digest>"}`, plus `memory_bytes`, `cpu_percent`, `pids`, `read_bytes_per_second` and `write_bytes_per_second` |

Both bandwidth limits are integers from 1 MiB/s through 512 MiB/s. The Guest applies them to the whole virtio block disk backing its authorized Btrfs data partition. Podman places the payload and monitor in child cgroups of the bounded service. The start check reads the kernel's `io.max` and requires both exact values. Automatic workload updates may retain or tighten the limits. Reauthorize workload deployments with both limits for this Guest release. [systemd I/O bandwidth controls](https://www.freedesktop.org/software/systemd/man/262/systemd.resource-control.html#IOReadBandwidthMax=device%20bytes) · [Linux cgroup v2 writeback](https://docs.kernel.org/admin-guide/cgroup-v2.html#writeback)

The workload-root authority uses a separate key. The authorizer verifies the deployment signature and validity period, verifies the publisher again, and reproduces the candidate byte for byte in a fresh worker before signing the output. The v2 authorization binds `source-evidence.json`, which contains the exact reviewed source policy bytes and the typed publisher evidence. Reauthorize existing workload bundles before using the v2 verifier.

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

This flow uses signed-only source admission. Full Stalwart service acceptance remains open.

### Issue an unsigned-source permit off-node

Use the signed-only policy by default. The owner can review a separate `fvca-oci-explicit-exceptions-v1` source policy for a particular unsigned digest. Include the same `service`, `repository`, `index`, `manifest`, `uid`, `gid`, and `volumes` fields and the `permit_authority` SHA-256 digest of the issuer's DER certificate. This policy has no publisher identity fields. Preserve the exact source policy bytes for the delegation and request digests.

Prepare the exact OCI index and single-platform layout as above. Print the normalized launch for human review. The preview reads the pinned OCI metadata and the expected execution identity. The isolated derivation worker separately checks the unpacked executable and resolved identity.

```sh
python3 tools/issue-workload-permit.py preview --policy exception-policy.json \
  --source-index source-index.json --layout source.oci > launch.json
```

Use lowercase `sha256:` digests, integer Unix seconds, and a lowercase UUID for `revocation_id`. The permit authority and operator use distinct pinned certificates. Use the detached DER CMS signing command above for each exact JSON document and its corresponding signer.

| Document | Signer | Fields |
| --- | --- | --- |
| `fvca-workload-permit-delegation-v1` | Permit authority | `schema`, `operator`, `operator_certificate` as the digest of the operator's DER certificate, `role` as `workload-unsigned-approver`, `guest`, `service`, `repository`, `source_policy`, `valid_from`, `expires`, `max_permit_seconds`, and `registry_token_service` |
| `fvca-workload-permit-request-v1` | Delegated operator | `schema`, `operator`, `role`, `guest`, `service`, `repository`, `source_policy`, `source_index`, `manifest`, `platform` as `{"os":"linux","architecture":"amd64"}`, `launch` as the exact launch digest, `acknowledgment`, `reason`, `requested_at`, `expires`, `revocation_id`, and `revocation_action` as `block-new-starts` or `stop` |

Review the source digests, destination, launch and expiry before signing the request. Enter the exact text **I KNOW THIS MIGHT BE INSECURE** in the `acknowledgment` field. Ordinary expiry is recorded as `block-new-starts`. Stopping a running workload requires an explicit revocation. Each digest needs its own reviewed acknowledgment.

Set `registry_token_service` to `null` for unauthenticated registry access or supply a pinned HTTPS `url` and `service` for an anonymous pull token. The issuer checks both immutable source manifests and observes the unfiltered OCI referrers API, the OCI referrers tag, and the legacy Cosign signature tag in the same repository. Only explicit missing manifest responses or the expected empty lists clear these checks. Signature metadata, unauthorized responses, malformed replies and retrieval failures fence issuance. Record that the decision covers the configured discovery locations at the time of issuance. [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#listing-referrers) · [Cosign signature discovery](https://github.com/sigstore/cosign/blob/v3.1.4/specs/SIGNATURE_SPEC.md)

```sh
python3 tools/issue-workload-permit.py issue --policy exception-policy.json \
  --source-index source-index.json --layout source.oci --launch launch.json \
  --request request.json --request-signature request.p7s --operator-certificate operator.crt \
  --delegation delegation.json --delegation-signature delegation.p7s \
  --authority-certificate permit-authority.crt --authority-key permit-authority.key \
  --output reviewed-permit
```

Retain the private output containing the signed permit, its `UNSIGNED_UPSTREAM_APPROVED` provenance, registry observation, and signed operator request and delegation. Run `python3 -B -W error tests/check-workload-permit.py` to check the issuer and its rejection paths.

Use `--unsigned-permit reviewed-permit` in the derivation and independent authorization commands for the approved exception policy. Sign the deployment with `UNSIGNED_UPSTREAM_APPROVED`. Both commands verify the authority signature and the exact source and normalized launch. The authorizer also checks the permit's Guest and separates the permit, deployment, and workload-root keys. The resulting `source-evidence.json` carries the policy, permit, signature, and public issuer certificate. The signed derivation records the permit digest.

To enable permits for a Guest, add `unsigned_permit_authority` to its signed workload scope. Set it to the reviewed permit issuer's DER certificate digest, matching `permit_authority` in the exception source policy. Give the Guest composer that issuer's PEM certificate with `--permit-authority-certificate`. The composer checks its fingerprint and separates it from the boot, runtime, release, deployment, and workload authorities. The Guest checks the permit signature, exact deployment binding, and enrolled revocation list. Its verification and startup logs report the source classification, permit UUID, and effective expiry. The earlier of the deployment and permit expiries bounds staged updates, boot and service starts.

The Guest checks the mounted permit about every 30 seconds while that workload is mounted. It writes the current condition, provenance, permit UUID, permit expiry, and effective start deadline to `/run/fvca/workload-image/permit-status/status.json`. `FVCA_WORKLOAD_PERMIT_STATUS` reports condition changes in the journal. Expiry raises a warning and fences the next start. A running workload continues under its verified root. [systemd timer behavior](https://www.freedesktop.org/software/systemd/man/262/systemd.timer.html)

### Revoke an exact unsigned permit

The enrolled permit authority signs a notice for the exact original permit, including its target Guest, service, UUID, and SHA-256 digest. Choose `block-new-starts` to fence starts and updates, or `stop` to also stop the mounted workload. The issuer can sign an explicit stop after the permit expires. A stop notice takes precedence over an earlier block notice.

```sh
python3 tools/revoke-workload-permit.py --permit reviewed-permit \
  --authority-key permit-authority.key --action stop \
  --reason 'Revoke the reviewed deployment' --output signed-revocation
```

Use the trusted Guest data intake writer to publish the exact receipt under `/run/fvca/guest-data/workload-updates/permit-revocations/` on the selected Btrfs pool. Use root-owned `0700` directories and a root-owned `0400` receipt. Flush the file, publish it by a same-filesystem rename without replacement, and flush the directory. Keep both receipts when escalating a block to a stop. The Guest rechecks the notice at boot, start, staging, and trial commit. A valid stop notice authorizes the monitor to stop only the generated workload service. A malformed notice fences new starts and produces a warning.

For automatic delivery, add `--channel stable` to the signing command and publish the generated target in the enrolled channel's top-level TUF targets with consistent snapshots. Retain the original target bytes for repeat publication. Each notice carries the public issuer certificate, which the Guest checks against its signed enrollment. The normal workload refresh authenticates the complete notice set before attempting the workload head, so an expired or withdrawn workload offer does not suppress a valid notice. A refresh accepts notices up to 64 KiB each and 1 MiB in total. [TUF targets and consistent snapshots](https://theupdateframework.github.io/specification/latest/#consistent-snapshots)

The client persists each exact notice on Btrfs before staging an offer. It accepts retries of identical bytes and rejects replacement of an existing notice. Removing a target from subsequent TUF metadata cannot remove a retained local notice. Keep the authority's records independently of Guest captures. Reapply the current records before booting restored data and include revoked permit UUIDs in the current signed Guest enrollment.

Use `tests/check-workload-revocation-channel.py` with the development workload channel client and verifier, a rootless Fedora builder image, and an output directory on Btrfs. It exercises the normal Guest entry point with signed TUF metadata and an independently signed notice. The existing workload channel tests also exercise HTTPS transport.

For KVM qualification, start with a disposable, independently authorized unsigned workload that stays running until stopped. Seed its bundle onto a fresh Btrfs fixture using `tests/workload-data-lab.sh`. The deployment must remain valid beyond the permit expiry. Sign an exact `stop` target for channel `stable` using the lab issuer, then prepare the isolated test depot and initramfs.

```sh
python3 -B -W error tests/check-workload-permit-boot.py prepare \
  --issued ISSUED_PERMIT --notice SIGNED_STOP_TARGET --output ENROLLMENT
bash tests/workload-permit-initrd.sh GUEST_INITRAMFS LAB_INITRAMFS
```

Compose a separately signed direct-boot lab bundle with `LAB_INITRAMFS` and the exact workload scope and certificates, including the permit issuer. Pass `ENROLLMENT/uplink`, `channel.json`, `depot/metadata/1.root.json`, `depot.json` and `permit-lab-ca.pem` to the composer's workload network and channel options. The lab initramfs shortens the wait for the first refresh and adds separate service-state checks. It preserves the generated workload service and the production permit monitor.

```sh
python3 -B -W error tests/check-workload-permit-boot.py check \
  --issued ISSUED_PERMIT --enrollment ENROLLMENT --bundle DIRECT_BOOT_BUNDLE \
  --release-certificate RELEASE_CERTIFICATE --data BTRFS_FIXTURE/approved.raw \
  --output TEST_REPORTS
```

The check moves the Guest clock across the permit deadline, observes the running service after expiry, and delivers the signed stop over pinned HTTPS. It checks that systemd stops the service and refuses a restart. Two additional boots check ordinary expiry and revocation retained on Btrfs with the depot offline.

### Verify an executable-only workload transition

Use the trusted scope of the currently selected workload and the enrolled deployment and workload-root certificates to verify a proposed replacement. Both private bundle directories contain the independently signed deployment and authorization, publisher evidence, and exact workload disk. Re-run source admission and derivation for the candidate under its own pinned source policy.

The deployment authority signs a `fvca-workload-transition-v1` JSON record as detached DER CMS. The record names the enrolled `guest` and `service`. The `from_authorization` and `to_authorization` fields each contain the `sha256:` digest of that endpoint's exact `authorization.json`. The `to_source_policy` field binds the candidate's exact source policy digest. Set `data_compatibility` to `bidirectional` only after qualifying both executables against the same mutable data, including data written during the candidate's trial. Set `valid_from` and `expires` in Unix seconds.

```sh
fvca-workload-admission --verify-transition CURRENT_POLICY DEPLOYMENT_CERT WORKLOAD_CERT \
  CURRENT_BUNDLE CANDIDATE_BUNDLE transition.json transition.p7s
```

The verifier checks both endpoints, the exact transition signature, and the enrolled Guest scope. The repository, container and subordinate identities, writable volume destinations, and network profile must match. A publisher-verified workload retains its publisher issuer across transitions and can advance only to another publisher-verified deployment. Each endpoint needs a declared health check. The candidate must preserve the security epoch and fit the active release's resource bounds. The verifier reports the exact authorization digests and the earliest expiry. This step checks admission before the updater's separate lifecycle lease, restart, health assessment, and recovery transaction.

### Stage the verified transition on the Guest

The trusted intake writer publishes one complete `incoming/` directory under `/run/fvca/guest-data/workload-updates/` on the selected Btrfs filesystem. It writes `transition.json`, `transition.p7s`, and a `candidate/` directory holding the complete workload bundle. Use root-owned `0700` directories and root-owned `0600` or `0400` regular files. Label the store and its contents `system_u:object_r:fvca_workload_stage_t:s0`. The writer flushes its inputs and publishes the complete directory atomically. It retains write access only while preparing its private inputs.

The Guest runs `fvca-stage-workload.service` after starting the mounted workload. The service can also be started after delivery. It takes the Guest workload lease, checks the signed from-authorization against the mounted image, verifies both bundles again, and flushes the incoming directory before atomically publishing `staged/`. The staged bundle survives reboot and is revalidated on retry. An occupied stage fences a different incoming directory. `FVCA_WORKLOAD_STAGED` records publication or retention, the exact grant and endpoint authorization digests, and their common freshness limit. The existing service continues on its mounted root while the stage is prepared.

Create the staging fixtures with `tests/workload-data-lab.sh --stage UPDATE_STORE TEMPLATE CURRENT_BUNDLE FIXTURE STALWART_MAIL_LAB`. Size the Guest data partition for both signed bundles and the active application's data. The fixture builder alters one byte in the candidate image on `tampered.raw`. For the disposable signed boot bundle, prepare its initramfs with `tests/stalwart-mail-initrd.sh --workload-stage` to label the staging tree under the Guest SELinux policy. Run `tests/check-storage.py --guest --direct-boot BUNDLE --release-certificate CERT --workload-stage TRANSITION_JSON --lab FIXTURE --output NEW_DIRECTORY`. The check boots a private copy of the approved disk twice and verifies that the second boot retains the same stage.

### Trial and commit a staged workload

The Guest checks for a transition hourly. `fvca-trial-workload.service` also accepts an explicit start from the local release controller. It takes the workload lease and rechecks the signed grant against the mounted and committed authorizations. Before stopping the payload, it durably publishes the `trial/` directory and records the exact grant so redelivery of the same last grant cannot repeat the restart.

The coordinator changes only the affected workload root and unit. The new unit uses the signed local health check. After health and a final freshness check, one atomic rename makes the candidate the boot selection in `selected/`. Subsequent starts still verify the candidate's deployment and the source policy in its signed grant. A process failure invokes recovery from the same unit. On boot, the Guest starts the committed executable and clears an interrupted trial after the committed service starts. Fallback uses the identical Btrfs payload volumes, including writes accepted during the trial. The coordinator removes the failed or superseded trial bundle once the selected executable is running.

Prepare the disposable Stalwart initramfs with `tests/stalwart-mail-initrd.sh --workload-trial`. Build two signed Btrfs fixtures for the same starting workload, with a healthy candidate on `approved.raw` and a candidate whose signed health command persists `/var/lib/stalwart/.fvca-trial-write` and fails on `unhealthy.raw`. Keep the healthy candidate's deployment valid past its trial grant. Run `tests/check-storage.py --guest --direct-boot BUNDLE --release-certificate CERT --workload-trial GOOD_GRANT BAD_GRANT --lab FIXTURE --output NEW_DIRECTORY`. The check exercises a healthy commit and reboot after grant expiry, a power interruption before commit, and recovery from a failed health check while retaining a candidate write.

### Enroll a workload update channel

After source authorization, use `tools/pack-workload-offer.py` with the current verifier, enrolled policy, signer certificates, current bundle, and complete signed transition directory. It verifies the copied offer and emits an exact head and its targets for publication by the TUF repository. Use hash-prefixed consistent snapshots and separate keys for root, targets, snapshot and timestamp. Each head is named `fvca-workload.GUEST.SERVICE.CHANNEL.json`. Advance its sequence for every publication, including withdrawal with `"release": null`. The target names contain the signed transition's exact SHA-256 digest.

Enroll the channel when composing the signed Guest. Pass `--workload-channel-policy`, `--workload-channel-root`, `--workload-channel-depot` and `--workload-channel-ca` along with workload trust and the signed workload uplink. Use a policy with `schema` set to `fvca-workload-channel-policy-v1`, the enrolled `guest` and `service`, `channel`, `tuf_root_sha256`, `depot_config_sha256`, and `max_artifact_bytes`. Use lowercase SHA-256 hex for the exact root and depot files. The depot JSON uses HTTPS, a numeric IPv4 directory URL on TCP 443, `ca_file` set to `/run/fvca/workload-trust/channel-ca.pem`, and a deadline of at most 900 seconds. Enroll the matching `egress=tcp,ADDRESS,443` rule.

The hourly check authenticates the fresh TUF head and the exact current selection. It checks the signed deployment, compatible launch, artifact length and digest before requesting the raw image. After validating the received verity image, it publishes one complete Btrfs inbox and gives the trial an authorization for that exact grant. A successful refresh can reauthorize the same queued grant. The updater removes a channel delivery when a verified refresh withdraws or supersedes it. It also clears partial downloads on failure or when the worker next starts after an interruption. The trial checks channel freshness before stopping the workload and again before committing. A failed refresh fences the trial and leaves the running service available.

Run `tests/check-workload-channel.py` with the same pinned Python TUF tools used for release qualification. It exercises local and HTTPS delivery, withdrawal, rollback and conflicting sequences. It also verifies that the updater refuses independently invalid CMS and TUF artifact records before requesting the raw image. For an enrolled disposable direct-boot Guest with the Stalwart trial initramfs, `tests/check-workload-channel-boot.py` starts KVM and its HTTPS depot on an isolated TAP link and checks discovery through healthy commit. Add `--interrupt-delivery` to check reauthorization after a forced reset without downloading the same image twice.

## Guest workload verifier

The Rust verifier checks both CMS signatures against separate signer certificates. It binds the exact deployment, derivation, reviewed source policy, source evidence, launch definition and raw image bytes, then checks both GPT tables and the signed dm-verity root hash. It checks the target Guest and service, validity period, minimum security epoch, revocation list and offline launch profile before returning the verified file descriptor and partition offsets.

The policy record contains `guest`, `service`, the reviewed `source_policy` SHA-256 digest from the derivation, `minimum_epoch` and `revoked` as a list of deployment or permit UUIDs. An explicit-exceptions deployment also requires the `unsigned_permit_authority` pin. The development CLI takes that record, the two public signer certificates and a private staging directory.

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

The Guest generates a private Quadlet from the authorized entrypoint, arguments, environment, health check, signal, identity, network and volume destinations. It starts the generated service only after systemd confirms the expected fragment and permitted OS defaults. Podman uses the verified rootfs read-only, drops all capabilities, and applies the approved UID/GID mapping. The workload service applies the signed memory, CPU and PID budgets and waits for the approved health check before reporting ready. Each start or restart requires an unexpired approval and the active verity mount. [Podman Quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)

The Guest keeps each declared persistent volume on Btrfs under `/run/fvca/guest-data/payload/<service>/<digest>`, where `digest` is the SHA-256 of the container mount destination. It creates missing volumes with the mapped workload owner and rejects ownership mismatches on existing data. The container receives only its declared volumes, with `nodev,nosuid,noexec` and a private SELinux label. Podman keeps the container log in volatile storage and caps its size.

### Service Guest workload uplink

The Guest installs a default-deny IPv4 and IPv6 policy in its own network namespace. A scoped workload deployment can get a dedicated virtio NIC in a separate namespace. Pass `--workload-network FILE` to `compose-service-guest.py` with the signed workload trust inputs. The deployment authority sets `network` to `{"workload":"sha256:<profile digest>"}` using the SHA-256 of the exact record. The measured Guest boot and each workload start must agree on that digest.

```text
FVCA-GUEST-WORKLOAD-NETWORK-2
pci=0000:00:06.0
mac=52:54:00:10:20:30
address=192.168.44.15/24
gateway=192.168.44.1
mtu=1400
dns=192.168.44.53
receive_bytes_per_second=1048576
send_bytes_per_second=524288
ingress=tcp,192.168.44.20,443
egress=tcp,192.168.44.70,443
```

Use `gateway=none` for an on-link profile and `dns=none` to omit a configured resolver. Each `ingress` or `egress` rule approves an exact IPv4 peer and TCP or UDP destination port. An enrolled resolver allows TCP and UDP on port 53 to that address. The workload receives the original client address and terminates its own application protocols. The `none` deployment uses Podman's isolated offline network mode. A connected lab supplies the enrolled virtio NIC on an isolated segment. Enroll a [Host workload uplink](#host-workload-uplink) for a Hypervisor-managed Guest. [Podman networking](https://docs.podman.io/en/latest/markdown/podman-run.1.html) · [nftables reference](https://netfilter.org/projects/nftables/manpage.html)

Both rate fields require canonical integers between 65,536 and 125,000,000 bytes per second. Each direction shares one kernel token bucket across its allowed IPv4 traffic, including established flows, DNS and workload updates. The bucket permits an initial burst of one second's worth of traffic and drops packets over budget. A connected Guest requires a new signed profile and matching deployment authorization. Hypervisor-managed Guests also require a matching signed Host enrollment. [nftables token-bucket limits](https://netfilter.org/projects/nftables/manpage.html#LIMIT_STATEMENT)

For Stalwart lifecycle qualification, run `tests/stalwart-lifecycle-initrd.sh` with the development OCI initramfs and a new output file. Use that initramfs when composing the disposable Guest, then add `--stalwart-lifecycle` to the `tests/check-storage.py --workload` invocation. The fixture checks the health endpoint, UID/GID, SELinux label, resource settings, Btrfs file persistence across restart, and clean stop. Stalwart runs in its offline bootstrap mode. Controller-backed freshness and protected updates remain pending. [Stalwart bootstrap mode](https://stalw.art/docs/configuration/bootstrap-mode/)

### Configured Stalwart mail fixture

With the approved OCI image staged locally by digest, run `python3 tests/stalwart-mail-lab.py build/stalwart-mail-lab`. The disposable server uses an embedded SQLite store and binds to its container loopback. The fixture provisions a test account, submits a synthetic message over authenticated SMTP with pinned TLS, and records the exact bytes retrieved through IMAP with the same certificate pin. [Stalwart declarative deployment](https://stalw.art/docs/configuration/declarative-deployments/) · [Stalwart certificates](https://stalw.art/docs/server/tls/certificates/)

Pass `build/stalwart-mail-lab` as the fourth argument to `tests/workload-data-lab.sh` to seed the two signed Stalwart volume mappings on the Guest Btrfs disk. Run `bash tests/stalwart-mail-initrd.sh GUEST_INITRAMFS NEW_INITRAMFS build/stalwart-mail-lab`, then compose the disposable Guest with `NEW_INITRAMFS`. The fixture initramfs contains a synthetic mailbox credential. Use `--workload --stalwart-mail` with `tests/check-storage.py` to verify that the exact message is retrieved before Guest readiness. The workload image alteration check also runs.

To check rejection of a different message, copy the lab's `imap.curl` to a new private fixture directory and write a different `mail.eml` there. Build a second direct-boot bundle with the same core, runtime, release authority and command line using that fixture directory with `tests/stalwart-mail-initrd.sh`. Pass the bundle as `--stalwart-mail-mismatch` alongside the normal direct-boot workload test. The test uses the approved Btrfs disk for both mail comparisons and requires the mismatched reference to stop readiness after authenticated retrieval.

For the unattended nested test, seed the disposable authenticated Host mirror from the workload lab's `approved.raw` and pack the normal mail fixture's signed direct-boot bundle into the Host slot. Use `--nested-guest-tpm-auto` to check Host and Guest readiness together.

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
