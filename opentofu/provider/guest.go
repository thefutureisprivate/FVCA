package main

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type guestConfiguration struct {
	client *client
}

var _ resource.ResourceWithModifyPlan = (*guestConfiguration)(nil)

func (r *guestConfiguration) Metadata(_ context.Context, req resource.MetadataRequest, res *resource.MetadataResponse) {
	res.TypeName = req.ProviderTypeName + "_guest_configuration"
}

func (r *guestConfiguration) Schema(_ context.Context, _ resource.SchemaRequest, res *resource.SchemaResponse) {
	res.Schema = schema.Schema{
		Description: "Manage CPU and memory intent for an enrolled FVCA Service Guest.",
		Attributes: map[string]schema.Attribute{
			"host_id":                        schema.StringAttribute{Required: true},
			"guest_id":                       schema.StringAttribute{Required: true},
			"vcpus":                          schema.Int64Attribute{Required: true},
			"memory_mib":                     schema.Int64Attribute{Required: true},
			"proposal":                       schema.StringAttribute{Required: true, WriteOnly: true},
			"expected_revision":              schema.NumberAttribute{Computed: true},
			"expected_sha256":                schema.StringAttribute{Computed: true},
			"desired_configuration_revision": schema.NumberAttribute{Computed: true},
			"desired_configuration_sha256":   schema.StringAttribute{Computed: true},
			"planned_at":                     schema.Int64Attribute{Computed: true},
			"plan_expires":                   schema.Int64Attribute{Computed: true},
			"activation":                     schema.StringAttribute{Computed: true},
			"operation_id":                   schema.StringAttribute{Computed: true},
			"operation_state":                schema.StringAttribute{Computed: true},
			"boot_configuration_revision":    schema.NumberAttribute{Computed: true},
			"boot_configuration_sha256":      schema.StringAttribute{Computed: true},
			"boot_vcpus":                     schema.Int64Attribute{Computed: true},
			"boot_memory_mib":                schema.Int64Attribute{Computed: true},
			"host_trial":                     schema.BoolAttribute{Computed: true},
			"observed_release_generation":    schema.NumberAttribute{Computed: true},
			"observed_release_epoch":         schema.NumberAttribute{Computed: true},
			"observed_release_sha256":        schema.StringAttribute{Computed: true},
		},
	}
}

func (r *guestConfiguration) Configure(_ context.Context, req resource.ConfigureRequest, res *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	var ok bool
	r.client, ok = req.ProviderData.(*client)
	if !ok {
		res.Diagnostics.AddError("Invalid FVCA client", "The provider did not configure the management client.")
	}
}

type guestState struct {
	HostID          types.String `tfsdk:"host_id"`
	GuestID         types.String `tfsdk:"guest_id"`
	VCPUs           types.Int64  `tfsdk:"vcpus"`
	MemoryMiB       types.Int64  `tfsdk:"memory_mib"`
	Proposal        types.String `tfsdk:"proposal"`
	ExpectedRev     types.Number `tfsdk:"expected_revision"`
	ExpectedSHA     types.String `tfsdk:"expected_sha256"`
	DesiredRev      types.Number `tfsdk:"desired_configuration_revision"`
	DesiredSHA      types.String `tfsdk:"desired_configuration_sha256"`
	PlannedAt       types.Int64  `tfsdk:"planned_at"`
	PlanExpires     types.Int64  `tfsdk:"plan_expires"`
	Activation      types.String `tfsdk:"activation"`
	OperationID     types.String `tfsdk:"operation_id"`
	OperationState  types.String `tfsdk:"operation_state"`
	BootRev         types.Number `tfsdk:"boot_configuration_revision"`
	BootSHA         types.String `tfsdk:"boot_configuration_sha256"`
	BootVCPUs       types.Int64  `tfsdk:"boot_vcpus"`
	BootMemory      types.Int64  `tfsdk:"boot_memory_mib"`
	HostTrial       types.Bool   `tfsdk:"host_trial"`
	ReleaseSequence types.Number `tfsdk:"observed_release_generation"`
	ReleaseEpoch    types.Number `tfsdk:"observed_release_epoch"`
	ReleaseSHA      types.String `tfsdk:"observed_release_sha256"`
}

func knownBinding(revision types.Number, digest types.String) (*binding, error) {
	if revision.IsNull() && digest.IsNull() {
		return nil, nil
	}
	value := revision.ValueBigFloat()
	if value == nil || !isDigest(digest.ValueString()) {
		return nil, errors.New("invalid planned configuration revision or digest")
	}
	integer, accuracy := value.Uint64()
	if integer == 0 || accuracy != big.Exact {
		return nil, errors.New("invalid planned configuration revision")
	}
	return &binding{Revision: integer, SHA256: digest.ValueString()}, nil
}

func (p guestState) validInputs() bool {
	return enrolledIdentity(p.HostID.ValueString(), p.GuestID.ValueString()) &&
		machineProfile(p.VCPUs.ValueInt64(), p.MemoryMiB.ValueInt64())
}

func (p guestState) sameIdentity(prior guestState) bool {
	return p.HostID.Equal(prior.HostID) && p.GuestID.Equal(prior.GuestID)
}

func (p *guestState) observe(status response) {
	boot := status.BootConfiguration
	p.BootRev, p.BootSHA = bindingState(*boot)
	p.BootVCPUs = types.Int64Value(boot.VCPUs)
	p.BootMemory = types.Int64Value(boot.MemoryMiB)
	p.HostTrial = types.BoolValue(*status.HostTrial)
	p.ReleaseEpoch = types.NumberNull()
	p.ReleaseSequence = types.NumberNull()
	p.ReleaseSHA = types.StringNull()
	if status.Observed != nil {
		p.ReleaseEpoch = number(status.Observed.Epoch)
		p.ReleaseSequence = number(status.Observed.Sequence)
		p.ReleaseSHA = types.StringValue(status.Observed.SHA256)
	}
}

func (p guestState) matchesBoot(status response, desired *binding) bool {
	actual := status.BootConfiguration.binding()
	same := actual == nil && desired == nil || actual != nil && desired != nil && *actual == *desired
	return same && status.BootConfiguration.VCPUs == p.VCPUs.ValueInt64() &&
		status.BootConfiguration.MemoryMiB == p.MemoryMiB.ValueInt64()
}

func (r *guestConfiguration) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, res *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		res.Diagnostics.AddError("Guest retirement requires separate authorization",
			"Keep the registered Guest in configuration. This resource manages settings for an existing Guest.")
		return
	}
	var proposed guestState
	res.Diagnostics.Append(req.Plan.Get(ctx, &proposed)...)
	if res.Diagnostics.HasError() {
		return
	}
	if !proposed.validInputs() {
		res.Diagnostics.AddError("Invalid FVCA settings", "Supply enrolled identities and a supported CPU and memory profile.")
		return
	}
	if !req.State.Raw.IsNull() {
		var prior guestState
		res.Diagnostics.Append(req.State.Get(ctx, &prior)...)
		if res.Diagnostics.HasError() {
			return
		}
		if !proposed.sameIdentity(prior) {
			res.Diagnostics.AddError("FVCA identity is immutable", "Use the original enrolled Host and Guest identities.")
			return
		}
		if proposed.VCPUs.Equal(prior.VCPUs) && proposed.MemoryMiB.Equal(prior.MemoryMiB) {
			res.Diagnostics.Append(res.Plan.Set(ctx, &prior)...)
			return
		}
	}
	host, guest := proposed.HostID.ValueString(), proposed.GuestID.ValueString()
	var source types.String
	res.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("proposal"), &source)...)
	if res.Diagnostics.HasError() {
		return
	}
	var saved proposal
	if input := source.ValueString(); len(input) > 2048 || json.Unmarshal([]byte(input), &saved) != nil ||
		saved.Host != host || saved.Guest != guest || saved.Plan.VCPUs != proposed.VCPUs.ValueInt64() ||
		saved.Plan.MemoryMiB != proposed.MemoryMiB.ValueInt64() || !saved.Plan.validAt(saved.Plan.PlannedAt) {
		res.Diagnostics.AddError("Missing or invalid FVCA proposal", "Use the authenticated preflight result for these exact identities and CPU and memory settings.")
		return
	}
	if saved.Scope == "trial-in-progress" {
		res.Diagnostics.AddError("A Host trial is in progress", "Plan the settings change after the trial resolves.")
		return
	}
	if !saved.validIntent() {
		res.Diagnostics.AddError("Invalid FVCA configuration intent", "The proposal must bind the exact expected and desired revisions.")
		return
	}
	s := saved.Plan
	proposed.ExpectedRev, proposed.ExpectedSHA = plannedBinding(s.Expected)
	proposed.DesiredRev, proposed.DesiredSHA = plannedBinding(nil)
	if s.Next.Revision != 0 {
		proposed.DesiredRev, proposed.DesiredSHA = plannedBinding(&s.Next)
	}
	proposed.Activation = types.StringValue(saved.Scope)
	proposed.PlannedAt = types.Int64Value(s.PlannedAt)
	proposed.PlanExpires = types.Int64Value(s.PlanExpires)
	proposed.OperationID = types.StringNull()
	if saved.Scope == "host-trial" {
		id := operationID(host, guest, s.Expected, s.Next)
		proposed.OperationID = types.StringValue(id)
	}
	res.Diagnostics.Append(res.Plan.Set(ctx, &proposed)...)
}

func plannedBinding(value *binding) (types.Number, types.String) {
	if value == nil {
		return types.NumberNull(), types.StringNull()
	}
	return number(value.Revision), types.StringValue(value.SHA256)
}

func (r *guestConfiguration) apply(ctx context.Context, selected *guestState) error {
	if r.client == nil || !selected.validInputs() {
		return errors.New("missing FVCA client or invalid planned identities and resource settings")
	}
	host, guest := selected.HostID.ValueString(), selected.GuestID.ValueString()
	previous, err := knownBinding(selected.ExpectedRev, selected.ExpectedSHA)
	if err != nil {
		return err
	}
	desired, err := knownBinding(selected.DesiredRev, selected.DesiredSHA)
	if err != nil {
		return err
	}
	status, err := r.client.status(ctx, host, guest)
	if err != nil {
		return err
	}
	if !*status.ConfigurationEnrolled {
		return errors.New("the Host configuration signing authority is unavailable")
	}
	s := submission{
		Expected: previous, VCPUs: selected.VCPUs.ValueInt64(), MemoryMiB: selected.MemoryMiB.ValueInt64(),
		PlannedAt: selected.PlannedAt.ValueInt64(), PlanExpires: selected.PlanExpires.ValueInt64(),
	}
	var operation string
	switch selected.Activation.ValueString() {
	case "none":
		if !s.validAt(time.Now().Unix()) || *status.HostTrial || !selected.matchesBoot(status, desired) {
			return errors.New("configuration no longer matches the saved plan; create a new plan")
		}
		operation = "active"
	case "host-trial":
		if desired == nil || desired.SHA256 != configurationDigest(guest, desired.Revision, s.VCPUs, s.MemoryMiB) {
			return errors.New("saved plan lacks the exact desired configuration digest")
		}
		s.Next = *desired
		id := operationID(host, guest, previous, s.Next)
		if selected.OperationID.ValueString() != id {
			return errors.New("saved operation ID differs from its planned configuration")
		}
		operation, err = r.client.submit(ctx, host, guest, id, s)
		if err != nil {
			return err
		}
	default:
		return errors.New("saved plan has no recognized activation scope")
	}
	selected.OperationState = types.StringValue(operation)
	selected.observe(status)
	return nil
}

func (r *guestConfiguration) Create(ctx context.Context, req resource.CreateRequest, res *resource.CreateResponse) {
	var selected guestState
	res.Diagnostics.Append(req.Plan.Get(ctx, &selected)...)
	if !res.Diagnostics.HasError() {
		r.applyState(ctx, &selected, &res.Diagnostics)
		if !res.Diagnostics.HasError() {
			res.Diagnostics.Append(res.State.Set(ctx, &selected)...)
		}
	}
}

func (r *guestConfiguration) Update(ctx context.Context, req resource.UpdateRequest, res *resource.UpdateResponse) {
	var selected, prior guestState
	res.Diagnostics.Append(req.Plan.Get(ctx, &selected)...)
	res.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if res.Diagnostics.HasError() {
		return
	}
	if !selected.sameIdentity(prior) {
		res.Diagnostics.AddError("FVCA identity is immutable", "Use the original enrolled Host and Guest identities.")
		return
	}
	if !selected.VCPUs.Equal(prior.VCPUs) || !selected.MemoryMiB.Equal(prior.MemoryMiB) {
		r.applyState(ctx, &selected, &res.Diagnostics)
	} else {
		selected = prior
	}
	if !res.Diagnostics.HasError() {
		res.Diagnostics.Append(res.State.Set(ctx, &selected)...)
	}
}

func (r *guestConfiguration) applyState(ctx context.Context, selected *guestState, diagnostics *diag.Diagnostics) {
	if err := r.apply(ctx, selected); err != nil {
		diagnostics.AddError("FVCA configuration apply failed", err.Error())
	}
}

func (r *guestConfiguration) Read(ctx context.Context, req resource.ReadRequest, res *resource.ReadResponse) {
	var prior guestState
	res.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if res.Diagnostics.HasError() {
		return
	}
	if r.client == nil || !prior.validInputs() {
		res.Diagnostics.AddError("Invalid FVCA state", "A configured Host client and enrolled resource identities are required.")
		return
	}
	host, guest := prior.HostID.ValueString(), prior.GuestID.ValueString()
	status, err := r.client.status(ctx, host, guest)
	if err != nil {
		res.Diagnostics.AddError("FVCA status failed", err.Error())
		return
	}
	desired, err := knownBinding(prior.DesiredRev, prior.DesiredSHA)
	if err != nil {
		res.Diagnostics.AddError("Invalid FVCA state", err.Error())
		return
	}
	operation := "superseded"
	if prior.matchesBoot(status, desired) {
		operation = "active"
		if *status.HostTrial {
			operation = "in-trial"
		}
	}
	if id := prior.OperationID.ValueString(); id != "" {
		if desired == nil {
			res.Diagnostics.AddError("Invalid FVCA state", "The saved operation requires a desired configuration digest.")
			return
		}
		observed, err := r.client.inspect(ctx, host, guest, id, *desired, prior.VCPUs.ValueInt64(), prior.MemoryMiB.ValueInt64())
		if err == nil {
			operation = observed
		} else if !errors.Is(err, errUnknownOperation) {
			res.Diagnostics.AddError("FVCA configuration operation status failed", err.Error())
			return
		}
	}
	prior.OperationState = types.StringValue(operation)
	prior.observe(status)
	res.Diagnostics.Append(res.State.Set(ctx, &prior)...)
}

func (r *guestConfiguration) Delete(_ context.Context, _ resource.DeleteRequest, res *resource.DeleteResponse) {
	res.Diagnostics.AddError("Guest retirement requires separate authorization",
		"FVCA configuration credentials authorize settings changes for an enrolled Guest.")
}
