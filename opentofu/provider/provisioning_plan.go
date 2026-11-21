package main

import (
	"context"
	"encoding/json"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type guestProvisioningPlan struct {
	client *client
}

type provisioningPreflight struct {
	HostID   types.String `tfsdk:"host_id"`
	GuestID  types.String `tfsdk:"guest_id"`
	Proposal types.String `tfsdk:"proposal"`
}

func (c *client) provisioning(ctx context.Context, host, guest string) (response, error) {
	return c.exchange(ctx, host, guest, struct {
		Type string `json:"type"`
	}{"guest-provisioning"})
}

func (*guestProvisioningPlan) Metadata(_ context.Context, req datasource.MetadataRequest, res *datasource.MetadataResponse) {
	res.TypeName = req.ProviderTypeName + "_guest_provisioning_plan"
}

func (*guestProvisioningPlan) Schema(_ context.Context, _ datasource.SchemaRequest, res *datasource.SchemaResponse) {
	res.Schema = schema.Schema{
		Description: "Capture the enrolled Host's initial Guest offer in a read-only provisioning proposal.",
		Attributes: map[string]schema.Attribute{
			"host_id":  schema.StringAttribute{Required: true},
			"guest_id": schema.StringAttribute{Required: true},
			"proposal": schema.StringAttribute{Computed: true},
		},
	}
}

func (p *guestProvisioningPlan) Configure(_ context.Context, req datasource.ConfigureRequest, res *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	var ok bool
	p.client, ok = req.ProviderData.(*client)
	if !ok {
		res.Diagnostics.AddError("Invalid FVCA client", "Configure the authenticated management client.")
	}
}

func (p *guestProvisioningPlan) Read(ctx context.Context, req datasource.ReadRequest, res *datasource.ReadResponse) {
	var selected provisioningPreflight
	res.Diagnostics.Append(req.Config.Get(ctx, &selected)...)
	if res.Diagnostics.HasError() {
		return
	}
	host, guest := selected.HostID.ValueString(), selected.GuestID.ValueString()
	if p.client == nil || !enrolledIdentity(host, guest) {
		res.Diagnostics.AddError("Invalid FVCA provisioning preflight", "Supply the configured client and enrolled Host and Guest identities.")
		return
	}
	reply, err := p.client.provisioning(ctx, host, guest)
	if err != nil {
		res.Diagnostics.AddError("FVCA provisioning preflight failed", err.Error())
		return
	}
	if reply.Result != "guest-provisioning" || reply.Provisioning == nil || !isDigest(reply.Provisioning.OperationID) {
		res.Diagnostics.AddError("Invalid FVCA provisioning preflight", "The enrolled Host did not return a valid provisioning offer.")
		return
	}
	now := time.Now().Unix()
	payload, err := json.Marshal(provisioningProposal{
		Offer: *reply.Provisioning,
		Plan: provisioningPlan{
			OperationID: reply.Provisioning.OperationID, PlannedAt: now, PlanExpires: now + planValiditySeconds,
		},
	})
	if err != nil {
		res.Diagnostics.AddError("Invalid FVCA provisioning preflight", "Could not capture the Host offer.")
		return
	}
	selected.Proposal = types.StringValue(string(payload))
	res.Diagnostics.Append(res.State.Set(ctx, &selected)...)
}
