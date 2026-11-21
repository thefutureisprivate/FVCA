# FVCA OpenTofu provider

The off-node provider `registry.opentofu.org/thefutureisprivate/fvca` version `0.3.0` implements the `fvca_guest_configuration_plan` data source and the `fvca_guest_configuration` resource for an enrolled Service Guest. The `fvca-appliance` module preflights typed CPU and memory settings by default. Set `manage_guest = true` to track the settings in OpenTofu and submit them on apply. Automatic Host release observations remain separate from the desired configuration revision.

Use the `fvca_host_firmware` data source with the enrolled `host_id` to observe firmware independently of Guest configuration. Its computed attributes include enrollment, current activation, and the last discovery or recovery check. The data source uses the existing management read key and TLS pin.

The example uses OpenTofu `1.13.9`, a Linux amd64 runner and a locally built provider. The checked-in lock file pins the provider package. The Host endpoint and Guest must already be enrolled as described in the appliance README.

## Build and install the locked provider

Use Go `1.27.4` and Python 3 on the off-node runner. Build from a verified revision of this repository.

```sh
mirror=$(mktemp -d)
bash opentofu/build-provider.sh "$mirror"
cat > "$mirror/tofu.rc" <<EOF
provider_installation {
  filesystem_mirror {
    path    = "$mirror"
    include = ["registry.opentofu.org/thefutureisprivate/fvca"]
  }
}
EOF
export TF_CLI_CONFIG_FILE="$mirror/tofu.rc"
tofu -chdir=opentofu/examples/plan init -lockfile=readonly
```

The build uses the checked-in Go dependency checksums. OpenTofu verifies the installed provider against the example's lock file. [OpenTofu provider installation](https://opentofu.org/docs/cli/config/config-file/#provider-installation)

## Plan against an enrolled Host

- Set the example's `host` input to its enrolled UUID, private endpoint, certificate name and SHA-256 of the DER leaf certificate. Set `guest` to the enrolled Service Guest identity with the desired CPU and memory.
- Supply `FVCA_MANAGEMENT_CA_FILE` and `FVCA_OPERATOR_KEY_FILE` through the runner. The operator file contains the dedicated PKCS#8 Ed25519 read key, owned by the runner with mode `0600`.
- Inject `TF_VAR_state_passphrase` from the runner's secret store. The example enforces AES-GCM encryption for both saved plans and local state. [OpenTofu state and plan encryption](https://opentofu.org/docs/v1.13/language/state/encryption/)

```sh
tofu -chdir=opentofu/examples/plan plan -out=guest.tfplan
```

The output identifies the Host and Guest, the boot-selected settings, the proposed settings, and the observed Host release. An already satisfied configuration reports activation `none`. Changed settings report `host-trial`.

## Submit a managed configuration

Enable `manage_guest` and enroll a dedicated configuration submitter key on the Host. Generate an encrypted saved plan with the read key. At apply, supply `FVCA_APPLY_OPERATOR_KEY_FILE` through the runner using the same private-file requirements as the read credential. Apply the saved plan within 15 minutes.

```sh
tofu -chdir=opentofu/examples/plan apply guest.tfplan
```

The broker validates the saved expected revision and returns a stable operation ID. A lost response or interrupted apply can be reconciled by reading that ID. The operation stays `pending-activation` until the Host receives the matching signed composition, trial and promotion approvals. A later refresh distinguishes `in-trial`, `active` and `superseded` and reports the boot-selected configuration separately. Independent OS release updates refresh observed release fields without replacing the resource or driving a settings submission.

Keep the registered Guest and its Host identity in configuration. The provider refuses resource destroy and identity replacement. Boot-image signing, commissioning a new Guest, and retirement use their own authorities.
