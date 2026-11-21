package main

import (
	"context"
	"errors"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type recordedOSRelease struct {
	release
	Role        string  `json:"role"`
	Slot        *string `json:"slot"`
	GuestBundle *string `json:"guest_bundle"`
}

type osCandidate struct {
	Epoch      uint64 `json:"epoch"`
	SHA256     string `json:"manifest_sha256"`
	Urgency    string `json:"urgency"`
	ActivateBy *int64 `json:"activate_by"`
}

type osCheck struct {
	Channel                string       `json:"channel"`
	PolicyRevision         uint64       `json:"policy_revision"`
	Disposition            string       `json:"disposition"`
	Freshness              string       `json:"freshness"`
	LastRefresh            *int64       `json:"last_refresh"`
	FreshUntil             *int64       `json:"fresh_until"`
	ChannelSequence        *uint64      `json:"channel_sequence"`
	Candidate              *osCandidate `json:"candidate"`
	Staged                 *string      `json:"staged"`
	PreparedInactiveSlot   *string      `json:"prepared_inactive_slot"`
	DeliveredTrial         *string      `json:"delivered_trial"`
	RequestedTrial         *string      `json:"requested_trial"`
	HoldUntil              *int64       `json:"hold_until"`
	SecurityDeadlineMissed *bool        `json:"security_deadline_missed"`
}

type osReleaseStatus struct {
	Schema     string             `json:"schema"`
	Role       string             `json:"role"`
	Enrolled   *bool              `json:"enrolled"`
	ObservedAt int64              `json:"observed_at"`
	Active     *recordedOSRelease `json:"recorded_active"`
	Check      *osCheck           `json:"last_check"`
}

var osChannel = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func osRole(role string) bool {
	return role == "hypervisor" || role == "service-guest"
}

func osSlot(slot *string) bool {
	return slot != nil && (*slot == "a" || *slot == "b")
}

func (status *osReleaseStatus) valid(role string) bool {
	if status == nil || status.Schema != "fvca-os-release-observation-v1" ||
		!osRole(role) || status.Role != role || status.Enrolled == nil || status.ObservedAt <= 0 {
		return false
	}
	if !*status.Enrolled {
		return status.Active == nil && status.Check == nil
	}
	if active := status.Active; active != nil {
		if active.Role != role || active.Epoch == 0 || active.Sequence == 0 || !isDigest(active.SHA256) {
			return false
		}
		if role == "hypervisor" {
			if !osSlot(active.Slot) || active.GuestBundle != nil {
				return false
			}
		} else if active.Slot != nil || active.GuestBundle == nil || !isDigest(*active.GuestBundle) {
			return false
		}
	}
	check := status.Check
	if check == nil {
		return true
	}
	if !osChannel.MatchString(check.Channel) || check.PolicyRevision == 0 ||
		check.SecurityDeadlineMissed == nil || (check.Freshness != "superseded" && status.Active == nil) {
		return false
	}
	if check.Disposition == "disabled" {
		return (check.Freshness == "not-applicable" || check.Freshness == "superseded") &&
			check.LastRefresh == nil && check.FreshUntil == nil && check.ChannelSequence == nil &&
			check.Candidate == nil && check.Staged == nil && check.PreparedInactiveSlot == nil &&
			check.DeliveredTrial == nil && check.RequestedTrial == nil && check.HoldUntil == nil &&
			!*check.SecurityDeadlineMissed
	}
	switch check.Disposition {
	case "no-release", "current", "ready", "outside-maintenance", "hold", "exhausted":
	default:
		return false
	}
	if check.LastRefresh == nil || check.FreshUntil == nil || check.ChannelSequence == nil ||
		*check.LastRefresh <= 0 || *check.FreshUntil <= *check.LastRefresh || *check.ChannelSequence == 0 {
		return false
	}
	expectedFreshness := "fresh"
	if status.ObservedAt < *check.LastRefresh {
		expectedFreshness = "clock-regressed"
	} else if status.ObservedAt >= *check.FreshUntil {
		expectedFreshness = "expired"
	}
	if check.Freshness != "superseded" && check.Freshness != expectedFreshness {
		return false
	}
	stageExpected := check.Disposition != "no-release" && check.Disposition != "current"
	if (check.Candidate == nil) != (check.Disposition == "no-release") ||
		(check.Staged != nil) != stageExpected ||
		(check.PreparedInactiveSlot != nil && (role != "hypervisor" || !osSlot(check.PreparedInactiveSlot) || !stageExpected)) ||
		(check.DeliveredTrial != nil && (!uuid.MatchString(*check.DeliveredTrial) || !stageExpected)) ||
		(check.RequestedTrial != nil && (check.DeliveredTrial == nil || *check.RequestedTrial != *check.DeliveredTrial)) ||
		(check.HoldUntil != nil) != (check.Disposition == "hold") ||
		(check.HoldUntil != nil && *check.HoldUntil <= 0) {
		return false
	}
	candidate := check.Candidate
	if candidate == nil {
		return !*check.SecurityDeadlineMissed
	}
	if candidate.Epoch == 0 || !isDigest(candidate.SHA256) ||
		(check.Staged != nil && *check.Staged != candidate.SHA256) {
		return false
	}
	switch candidate.Urgency {
	case "routine":
		return candidate.ActivateBy == nil && !*check.SecurityDeadlineMissed
	case "security":
		return candidate.ActivateBy != nil && *candidate.ActivateBy > 0
	}
	return false
}

func (c *client) osRelease(ctx context.Context, host, role string) (*osReleaseStatus, error) {
	view, err := c.exchange(ctx, host, serviceGuest, struct {
		Type string `json:"type"`
		Role string `json:"role"`
	}{"os-release-status", role})
	if err != nil {
		return nil, err
	}
	if view.Result != "os-release-status" || !view.OSRelease.valid(role) || view.Code != "" ||
		view.BootConfiguration != nil || view.ConfigurationEnrolled != nil || view.HostTrial != nil ||
		view.Observed != nil || view.Configuration != nil || view.Activation != "" ||
		view.OperationID != "" || view.OperationState != "" || view.Firmware != nil || view.Inventory != nil {
		return nil, errors.New("Host returned an invalid OS release observation")
	}
	return view.OSRelease, nil
}

type osReleaseData struct{ client *client }

func (p *osReleaseData) Metadata(_ context.Context, req datasource.MetadataRequest, res *datasource.MetadataResponse) {
	res.TypeName = req.ProviderTypeName + "_os_release"
}

func (p *osReleaseData) Schema(_ context.Context, _ datasource.SchemaRequest, res *datasource.SchemaResponse) {
	stringField := schema.StringAttribute{Computed: true}
	numberField := schema.NumberAttribute{Computed: true}
	seconds := schema.Int64Attribute{Computed: true}
	res.Schema = schema.Schema{
		Description: "Observe the recorded active release and last update check for one appliance role.",
		Attributes: map[string]schema.Attribute{
			"host_id":     schema.StringAttribute{Required: true},
			"role":        schema.StringAttribute{Required: true, Description: "hypervisor or service-guest."},
			"enrolled":    schema.BoolAttribute{Computed: true},
			"observed_at": seconds,
			"recorded_active": schema.SingleNestedAttribute{Computed: true, Attributes: map[string]schema.Attribute{
				"epoch": numberField, "sequence": numberField, "manifest_sha256": stringField,
				"slot": stringField, "guest_bundle": stringField,
			}},
			"last_check": schema.SingleNestedAttribute{Computed: true, Attributes: map[string]schema.Attribute{
				"channel": stringField, "policy_revision": numberField, "disposition": stringField, "freshness": stringField,
				"last_refresh": seconds, "fresh_until": seconds, "channel_sequence": numberField, "staged": stringField,
				"prepared_inactive_slot": stringField, "delivered_trial": stringField, "requested_trial": stringField,
				"hold_until": seconds, "security_deadline_missed": schema.BoolAttribute{Computed: true},
				"candidate": schema.SingleNestedAttribute{Computed: true, Attributes: map[string]schema.Attribute{
					"epoch": numberField, "manifest_sha256": stringField, "urgency": stringField, "activate_by": seconds,
				}},
			}},
		},
	}
}

func (p *osReleaseData) Configure(_ context.Context, req datasource.ConfigureRequest, res *datasource.ConfigureResponse) {
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

type osActiveModel struct {
	Epoch       types.Number `tfsdk:"epoch"`
	Sequence    types.Number `tfsdk:"sequence"`
	SHA256      types.String `tfsdk:"manifest_sha256"`
	Slot        types.String `tfsdk:"slot"`
	GuestBundle types.String `tfsdk:"guest_bundle"`
}

type osCandidateModel struct {
	Epoch      types.Number `tfsdk:"epoch"`
	SHA256     types.String `tfsdk:"manifest_sha256"`
	Urgency    types.String `tfsdk:"urgency"`
	ActivateBy types.Int64  `tfsdk:"activate_by"`
}

type osCheckModel struct {
	Channel                types.String      `tfsdk:"channel"`
	PolicyRevision         types.Number      `tfsdk:"policy_revision"`
	Disposition            types.String      `tfsdk:"disposition"`
	Freshness              types.String      `tfsdk:"freshness"`
	LastRefresh            types.Int64       `tfsdk:"last_refresh"`
	FreshUntil             types.Int64       `tfsdk:"fresh_until"`
	ChannelSequence        types.Number      `tfsdk:"channel_sequence"`
	Candidate              *osCandidateModel `tfsdk:"candidate"`
	Staged                 types.String      `tfsdk:"staged"`
	PreparedInactiveSlot   types.String      `tfsdk:"prepared_inactive_slot"`
	DeliveredTrial         types.String      `tfsdk:"delivered_trial"`
	RequestedTrial         types.String      `tfsdk:"requested_trial"`
	HoldUntil              types.Int64       `tfsdk:"hold_until"`
	SecurityDeadlineMissed types.Bool        `tfsdk:"security_deadline_missed"`
}

type osReleaseModel struct {
	Host       types.String   `tfsdk:"host_id"`
	Role       types.String   `tfsdk:"role"`
	Enrolled   types.Bool     `tfsdk:"enrolled"`
	ObservedAt types.Int64    `tfsdk:"observed_at"`
	Active     *osActiveModel `tfsdk:"recorded_active"`
	Check      *osCheckModel  `tfsdk:"last_check"`
}

func (p *osReleaseData) Read(ctx context.Context, req datasource.ReadRequest, res *datasource.ReadResponse) {
	var state osReleaseModel
	res.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if res.Diagnostics.HasError() {
		return
	}
	host, role := state.Host.ValueString(), state.Role.ValueString()
	if p.client == nil || !enrolledIdentity(host, serviceGuest) || !osRole(role) {
		res.Diagnostics.AddError("Invalid FVCA OS release request", "Supply the enrolled Host UUID and hypervisor or service-guest.")
		return
	}
	view, err := p.client.osRelease(ctx, host, role)
	if err != nil {
		res.Diagnostics.AddError("Could not read FVCA OS release", err.Error())
		return
	}
	state.Enrolled = types.BoolValue(*view.Enrolled)
	state.ObservedAt = types.Int64Value(view.ObservedAt)
	if active := view.Active; active != nil {
		state.Active = &osActiveModel{
			Epoch: number(active.Epoch), Sequence: number(active.Sequence), SHA256: types.StringValue(active.SHA256),
			Slot: types.StringPointerValue(active.Slot), GuestBundle: types.StringPointerValue(active.GuestBundle),
		}
	}
	if check := view.Check; check != nil {
		state.Check = &osCheckModel{
			Channel: types.StringValue(check.Channel), PolicyRevision: number(check.PolicyRevision),
			Disposition: types.StringValue(check.Disposition), Freshness: types.StringValue(check.Freshness),
			LastRefresh: types.Int64PointerValue(check.LastRefresh), FreshUntil: types.Int64PointerValue(check.FreshUntil),
			ChannelSequence: types.NumberNull(), Staged: types.StringPointerValue(check.Staged),
			PreparedInactiveSlot: types.StringPointerValue(check.PreparedInactiveSlot),
			DeliveredTrial:       types.StringPointerValue(check.DeliveredTrial), RequestedTrial: types.StringPointerValue(check.RequestedTrial),
			HoldUntil: types.Int64PointerValue(check.HoldUntil), SecurityDeadlineMissed: types.BoolValue(*check.SecurityDeadlineMissed),
		}
		if check.ChannelSequence != nil {
			state.Check.ChannelSequence = number(*check.ChannelSequence)
		}
		if candidate := check.Candidate; candidate != nil {
			state.Check.Candidate = &osCandidateModel{
				Epoch: number(candidate.Epoch), SHA256: types.StringValue(candidate.SHA256),
				Urgency: types.StringValue(candidate.Urgency), ActivateBy: types.Int64PointerValue(candidate.ActivateBy),
			}
		}
	}
	res.Diagnostics.Append(res.State.Set(ctx, &state)...)
}
