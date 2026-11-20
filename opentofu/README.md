# FVCA OpenTofu provider

The off-node provider `registry.opentofu.org/thefutureisprivate/fvca` version `0.1.0` implements the `fvca_guest_configuration_plan` data source. The `fvca-appliance` module uses it to preflight typed CPU and memory settings for the registered Service Guest. The Host broker checks the current settings revision and returns the exact candidate digest and activation scope. Automatic Host release observations are computed separately from configuration intent.

The example uses OpenTofu `1.13.9`, a Linux amd64 runner and a locally built provider. The checked-in lock file pins the provider package. The Host endpoint must already be enrolled as described in the appliance README. Managed resources, mutation and production management service enablement are separate implementation work.

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

The output identifies the Host and Guest, the boot-selected settings, the proposed settings, and the observed Host release. An already satisfied configuration reports activation `none`. Changed settings report `host-trial`. Applying this data-only example records its outputs in encrypted local state. The separate signed Host release and trial workflow applies CPU and memory changes on the appliance.
