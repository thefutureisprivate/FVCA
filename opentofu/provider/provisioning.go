package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type guestProvisioning struct {
	client *client
}

var _ resource.ResourceWithModifyPlan = (*guestProvisioning)(nil)

type provisioningReceipt struct {
	OperationID   string    `json:"operation_id"`
	State         string    `json:"state"`
	BundleSHA     string    `json:"bundle_sha256"`
	SeedSHA       string    `json:"seed_sha256"`
	DiskBytes     int64     `json:"disk_bytes"`
	Configuration *settings `json:"configuration"`
}

type provisioningPlan struct {
	OperationID string `json:"operation_id"`
	PlannedAt   int64  `json:"planned_at"`
	PlanExpires int64  `json:"plan_expires"`
}

type provisioningProposal struct {
	Offer provisioningReceipt `json:"offer"`
	Plan  provisioningPlan    `json:"plan"`
}

func (p provisioningPlan) validAt(now int64) bool {
	return isDigest(p.OperationID) && p.PlannedAt > 0 && p.PlannedAt <= math.MaxInt64-planValiditySeconds &&
		p.PlanExpires == p.PlannedAt+planValiditySeconds && p.PlannedAt <= now && now < p.PlanExpires
}

type provisioningState struct {
	HostID         types.String `tfsdk:"host_id"`
	GuestID        types.String `tfsdk:"guest_id"`
	BundleSHA      types.String `tfsdk:"bundle_sha256"`
	SeedSHA        types.String `tfsdk:"seed_sha256"`
	DiskBytes      types.Int64  `tfsdk:"disk_bytes"`
	VCPUs          types.Int64  `tfsdk:"vcpus"`
	MemoryMiB      types.Int64  `tfsdk:"memory_mib"`
	Proposal       types.String `tfsdk:"proposal"`
	OperationID    types.String `tfsdk:"operation_id"`
	OperationState types.String `tfsdk:"operation_state"`
	PlannedAt      types.Int64  `tfsdk:"planned_at"`
	PlanExpires    types.Int64  `tfsdk:"plan_expires"`
}

func (s provisioningState) sameInputs(other provisioningState) bool {
	return s.HostID.Equal(other.HostID) && s.GuestID.Equal(other.GuestID) &&
		s.BundleSHA.Equal(other.BundleSHA) && s.SeedSHA.Equal(other.SeedSHA) &&
		s.DiskBytes.Equal(other.DiskBytes) && s.VCPUs.Equal(other.VCPUs) && s.MemoryMiB.Equal(other.MemoryMiB)
}

func (s provisioningState) validInputs() bool {
	bytes := s.DiskBytes.ValueInt64()
	return enrolledIdentity(s.HostID.ValueString(), s.GuestID.ValueString()) &&
		isDigest(s.BundleSHA.ValueString()) && isDigest(s.SeedSHA.ValueString()) && bytes > 0 && bytes%512 == 0 &&
		machineProfile(s.VCPUs.ValueInt64(), s.MemoryMiB.ValueInt64())
}

func (s provisioningState) requireReceipt(reply response) (*provisioningReceipt, error) {
	r := reply.Provisioning
	if reply.Result != "guest-provisioning" || r == nil || r.Configuration == nil ||
		!r.Configuration.valid(s.GuestID.ValueString()) ||
		r.BundleSHA != s.BundleSHA.ValueString() || r.SeedSHA != s.SeedSHA.ValueString() ||
		r.DiskBytes != s.DiskBytes.ValueInt64() || r.Configuration.VCPUs != s.VCPUs.ValueInt64() ||
		r.Configuration.MemoryMiB != s.MemoryMiB.ValueInt64() {
		return nil, errors.New("the signed Host offer differs from the requested Guest disk, release or resources")
	}
	binding := "default"
	if value := r.Configuration.binding(); value != nil {
		binding = fmt.Sprintf("%d,%s", value.Revision, value.SHA256)
	}
	body := fmt.Sprintf("FVCA-GUEST-PROVISIONING-1\nhost=%s\nconfiguration=%s\nvcpus=%d\nmemory_mib=%d\n"+
		"FVCA-GUEST-COMMISSIONING-1\nguest=%s\nbundle=%s\nbytes=%d\nseed_sha256=%s\n",
		s.HostID.ValueString(), binding, r.Configuration.VCPUs, r.Configuration.MemoryMiB,
		s.GuestID.ValueString(), r.BundleSHA, r.DiskBytes, r.SeedSHA)
	digest := sha256.Sum256([]byte(body))
	if r.OperationID != hex.EncodeToString(digest[:]) ||
		(!s.OperationID.IsNull() && !s.OperationID.IsUnknown() && s.OperationID.ValueString() != r.OperationID) {
		return nil, errors.New("the Host did not return the exact saved Guest provisioning operation")
	}
	switch r.State {
	case "awaiting-apply", "pending", "ready":
		return r, nil
	default:
		return nil, errors.New("the Host returned an unknown Guest provisioning state")
	}
}

func (r *guestProvisioning) Metadata(_ context.Context, req resource.MetadataRequest, res *resource.MetadataResponse) {
	res.TypeName = req.ProviderTypeName + "_guest_provisioning"
}

func (r *guestProvisioning) Schema(_ context.Context, _ resource.SchemaRequest, res *resource.SchemaResponse) {
	res.Schema = schema.Schema{
		Description: "Admit the exact initial Service Guest offer signed by the enrolled FVCA Hypervisor.",
		Attributes: map[string]schema.Attribute{
			"host_id":         schema.StringAttribute{Required: true},
			"guest_id":        schema.StringAttribute{Required: true},
			"bundle_sha256":   schema.StringAttribute{Required: true, Description: "Approved Guest dm-verity root hash."},
			"seed_sha256":     schema.StringAttribute{Required: true},
			"disk_bytes":      schema.Int64Attribute{Required: true},
			"vcpus":           schema.Int64Attribute{Required: true},
			"memory_mib":      schema.Int64Attribute{Required: true},
			"proposal":        schema.StringAttribute{Required: true, WriteOnly: true, Description: "Exact proposal from the authenticated provisioning data source."},
			"operation_id":    schema.StringAttribute{Computed: true},
			"operation_state": schema.StringAttribute{Computed: true},
			"planned_at":      schema.Int64Attribute{Computed: true},
			"plan_expires":    schema.Int64Attribute{Computed: true},
		},
	}
}

func (r *guestProvisioning) Configure(_ context.Context, req resource.ConfigureRequest, res *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	var ok bool
	r.client, ok = req.ProviderData.(*client)
	if !ok {
		res.Diagnostics.AddError("Invalid FVCA client", "Configure the authenticated management client.")
	}
}

func (r *guestProvisioning) inspect(ctx context.Context, s provisioningState) (*provisioningReceipt, error) {
	if r.client == nil || !s.validInputs() {
		return nil, errors.New("supply a configured Host client, enrolled identities, approved digests and bounded disk and machine settings")
	}
	reply, err := r.client.provisioning(ctx, s.HostID.ValueString(), s.GuestID.ValueString())
	if err != nil {
		return nil, err
	}
	return s.requireReceipt(reply)
}

func (r *guestProvisioning) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, res *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		res.Diagnostics.AddError("Guest retirement requires separate authorization", "Keep the initial Guest operation in configuration.")
		return
	}
	var selected provisioningState
	res.Diagnostics.Append(req.Plan.Get(ctx, &selected)...)
	if res.Diagnostics.HasError() {
		return
	}
	if !req.State.Raw.IsNull() {
		var prior provisioningState
		res.Diagnostics.Append(req.State.Get(ctx, &prior)...)
		if res.Diagnostics.HasError() {
			return
		}
		if !selected.sameInputs(prior) {
			res.Diagnostics.AddError("Initial Guest provisioning is immutable", "Use the Guest configuration resource for later supported settings changes.")
			return
		}
		res.Diagnostics.Append(res.Plan.Set(ctx, &prior)...)
		return
	}
	if !selected.validInputs() {
		res.Diagnostics.AddError("Invalid FVCA provisioning settings", "Supply enrolled identities, approved digests and bounded disk and machine settings.")
		return
	}
	var source types.String
	res.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("proposal"), &source)...)
	if res.Diagnostics.HasError() {
		return
	}
	var saved provisioningProposal
	if input := source.ValueString(); len(input) > 2048 || json.Unmarshal([]byte(input), &saved) != nil ||
		saved.Plan.OperationID != saved.Offer.OperationID || !saved.Plan.validAt(saved.Plan.PlannedAt) {
		res.Diagnostics.AddError("Missing or invalid FVCA provisioning proposal", "Use the authenticated provisioning preflight for this Host and Guest.")
		return
	}
	offer, err := selected.requireReceipt(response{Result: "guest-provisioning", Provisioning: &saved.Offer})
	if err != nil {
		res.Diagnostics.AddError("FVCA provisioning preflight failed", err.Error())
		return
	}
	selected.OperationID = types.StringValue(offer.OperationID)
	selected.OperationState = types.StringUnknown()
	selected.PlannedAt = types.Int64Value(saved.Plan.PlannedAt)
	selected.PlanExpires = types.Int64Value(saved.Plan.PlanExpires)
	res.Diagnostics.Append(res.Plan.Set(ctx, &selected)...)
}

func (r *guestProvisioning) apply(ctx context.Context, s provisioningState) (*provisioningReceipt, error) {
	current, err := r.inspect(ctx, s)
	if err != nil || current.State != "awaiting-apply" {
		return current, err
	}
	plan := provisioningPlan{s.OperationID.ValueString(), s.PlannedAt.ValueInt64(), s.PlanExpires.ValueInt64()}
	if !plan.validAt(time.Now().Unix()) {
		return nil, errors.New("the saved provisioning plan expired or lacks its exact operation ID")
	}
	signer, err := loadSigner(os.Getenv("FVCA_PROVISION_OPERATOR_KEY_FILE"))
	if err != nil {
		return nil, errors.New("FVCA_PROVISION_OPERATOR_KEY_FILE must name the runner's private PKCS#8 Ed25519 provisioning key with mode 0600")
	}
	defer clear(signer)
	reply, err := r.client.signedExchange(ctx, s.HostID.ValueString(), s.GuestID.ValueString(), struct {
		Type string           `json:"type"`
		Plan provisioningPlan `json:"plan"`
	}{"apply-guest-provisioning", plan}, signer)
	if err != nil {
		if admitted, inspectErr := r.inspect(ctx, s); inspectErr == nil && admitted.State != "awaiting-apply" {
			return admitted, nil
		}
		return nil, err
	}
	admitted, err := s.requireReceipt(reply)
	if err == nil && admitted.State == "awaiting-apply" {
		return nil, errors.New("the Host did not admit the initial Guest operation")
	}
	return admitted, err
}

func (r *guestProvisioning) Create(ctx context.Context, req resource.CreateRequest, res *resource.CreateResponse) {
	var selected provisioningState
	res.Diagnostics.Append(req.Plan.Get(ctx, &selected)...)
	if res.Diagnostics.HasError() {
		return
	}
	receipt, err := r.apply(ctx, selected)
	if err != nil {
		res.Diagnostics.AddError("FVCA provisioning apply failed", err.Error())
		return
	}
	selected.OperationState = types.StringValue(receipt.State)
	res.Diagnostics.Append(res.State.Set(ctx, &selected)...)
}

func (r *guestProvisioning) Read(ctx context.Context, req resource.ReadRequest, res *resource.ReadResponse) {
	var prior provisioningState
	res.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if res.Diagnostics.HasError() {
		return
	}
	receipt, err := r.inspect(ctx, prior)
	if err != nil {
		res.Diagnostics.AddError("FVCA provisioning status failed", err.Error())
		return
	}
	if receipt.State == "awaiting-apply" {
		res.Diagnostics.AddError("FVCA provisioning receipt disappeared", "Reconcile the installed Host and its durable initial Guest operation.")
		return
	}
	prior.OperationState = types.StringValue(receipt.State)
	res.Diagnostics.Append(res.State.Set(ctx, &prior)...)
}

func (*guestProvisioning) Update(_ context.Context, _ resource.UpdateRequest, res *resource.UpdateResponse) {
	res.Diagnostics.AddError("Initial Guest provisioning is immutable", "Use the Guest configuration resource for later supported settings changes.")
}

func (*guestProvisioning) Delete(_ context.Context, _ resource.DeleteRequest, res *resource.DeleteResponse) {
	res.Diagnostics.AddError("Guest retirement requires separate authorization", "Keep the initial Guest operation in configuration.")
}
