package main

import (
	"context"
	"math/big"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type guestConfigurationPlan struct {
	client *client
}

func (p *guestConfigurationPlan) Metadata(_ context.Context, req datasource.MetadataRequest, res *datasource.MetadataResponse) {
	res.TypeName = req.ProviderTypeName + "_guest_configuration_plan"
}

func (p *guestConfigurationPlan) Schema(_ context.Context, _ datasource.SchemaRequest, res *datasource.SchemaResponse) {
	res.Schema = schema.Schema{
		Description: "Read Host status and preflight typed Guest settings without submitting a change.",
		Attributes: map[string]schema.Attribute{
			"host_id":                        schema.StringAttribute{Required: true},
			"guest_id":                       schema.StringAttribute{Required: true},
			"vcpus":                          schema.Int64Attribute{Required: true},
			"memory_mib":                     schema.Int64Attribute{Required: true},
			"active_configuration_revision":  schema.NumberAttribute{Computed: true},
			"active_configuration_sha256":    schema.StringAttribute{Computed: true},
			"active_vcpus":                   schema.Int64Attribute{Computed: true},
			"active_memory_mib":              schema.Int64Attribute{Computed: true},
			"planned_configuration_revision": schema.NumberAttribute{Computed: true},
			"planned_configuration_sha256":   schema.StringAttribute{Computed: true},
			"activation":                     schema.StringAttribute{Computed: true},
			"observed_release_epoch":         schema.NumberAttribute{Computed: true},
			"observed_release_generation":    schema.NumberAttribute{Computed: true},
			"observed_release_sha256":        schema.StringAttribute{Computed: true},
		},
	}
}

func (p *guestConfigurationPlan) Configure(_ context.Context, req datasource.ConfigureRequest, res *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client)
	if !ok {
		res.Diagnostics.AddError("Invalid FVCA client", "The provider did not configure the management client.")
		return
	}
	p.client = c
}

type preflightState struct {
	HostID          types.String `tfsdk:"host_id"`
	GuestID         types.String `tfsdk:"guest_id"`
	VCPUs           types.Int64  `tfsdk:"vcpus"`
	MemoryMiB       types.Int64  `tfsdk:"memory_mib"`
	ActiveRevision  types.Number `tfsdk:"active_configuration_revision"`
	ActiveSHA256    types.String `tfsdk:"active_configuration_sha256"`
	ActiveVCPUs     types.Int64  `tfsdk:"active_vcpus"`
	ActiveMemory    types.Int64  `tfsdk:"active_memory_mib"`
	PlannedRevision types.Number `tfsdk:"planned_configuration_revision"`
	PlannedSHA256   types.String `tfsdk:"planned_configuration_sha256"`
	Activation      types.String `tfsdk:"activation"`
	ReleaseEpoch    types.Number `tfsdk:"observed_release_epoch"`
	ReleaseSequence types.Number `tfsdk:"observed_release_generation"`
	ReleaseSHA256   types.String `tfsdk:"observed_release_sha256"`
}

func number(value uint64) types.Number {
	return types.NumberValue(new(big.Float).SetUint64(value))
}

func bindingState(configuration settings) (types.Number, types.String) {
	if selected := configuration.binding(); selected != nil {
		return number(selected.Revision), types.StringValue(selected.SHA256)
	}
	return types.NumberNull(), types.StringNull()
}

func (p *guestConfigurationPlan) Read(ctx context.Context, req datasource.ReadRequest, res *datasource.ReadResponse) {
	var state preflightState
	res.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if res.Diagnostics.HasError() {
		return
	}
	host, guest := state.HostID.ValueString(), state.GuestID.ValueString()
	cpu, memory := state.VCPUs.ValueInt64(), state.MemoryMiB.ValueInt64()
	if !uuid.MatchString(host) || host == "00000000-0000-0000-0000-000000000000" ||
		host == guest || guest != serviceGuest {
		res.Diagnostics.AddError("Invalid FVCA identity", "Supply the enrolled Host UUID and the registered Service Guest UUID.")
		return
	}
	if !machineProfile(cpu, memory) {
		res.Diagnostics.AddError("Invalid Guest machine profile", "Choose 1–4 vCPUs and 1024–4096 MiB of memory in 256 MiB increments.")
		return
	}
	if p.client == nil {
		res.Diagnostics.AddError("Missing FVCA client", "Configure the provider with the enrolled Host endpoint and runner credentials.")
		return
	}
	planned, err := p.client.preflight(ctx, host, guest, cpu, memory)
	if err != nil {
		res.Diagnostics.AddError("FVCA preflight failed", err.Error())
		return
	}
	state.ActiveRevision, state.ActiveSHA256 = bindingState(planned.Active)
	state.PlannedRevision, state.PlannedSHA256 = bindingState(planned.Desired)
	state.ActiveVCPUs = types.Int64Value(planned.Active.VCPUs)
	state.ActiveMemory = types.Int64Value(planned.Active.MemoryMiB)
	state.Activation = types.StringValue(planned.Scope)
	if planned.Release != nil {
		state.ReleaseEpoch = number(planned.Release.Epoch)
		state.ReleaseSequence = number(planned.Release.Sequence)
		state.ReleaseSHA256 = types.StringValue(planned.Release.SHA256)
	}
	res.Diagnostics.Append(res.State.Set(ctx, &state)...)
}
