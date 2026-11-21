package main

import (
	"context"
	"errors"
	"regexp"
	"unicode"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type firmwareActivation struct {
	Transaction   string                 `json:"transaction"`
	Device        string                 `json:"device_id"`
	Offer         string                 `json:"offer_sha256"`
	Phase         string                 `json:"phase"`
	Qualification *firmwareQualification `json:"qualification"`
}

type firmwareStage struct {
	Device        string                 `json:"device_id"`
	Offer         string                 `json:"offer_sha256"`
	Archive       string                 `json:"archive_sha256"`
	From          string                 `json:"qualified_from"`
	Target        string                 `json:"target"`
	Eligibility   *string                `json:"eligibility"`
	Qualification *firmwareQualification `json:"qualification"`
}

type firmwareQualification struct {
	QualifiedAt int64 `json:"qualified_at"`
	ObservedAt  int64 `json:"observed_at"`
	AgeSeconds  int64 `json:"age_seconds"`
}

func (q *firmwareQualification) valid() bool {
	return q != nil && q.QualifiedAt > 0 && q.ObservedAt >= q.QualifiedAt &&
		q.AgeSeconds == q.ObservedAt-q.QualifiedAt
}

type firmwareCheck struct {
	Disposition string              `json:"disposition"`
	CheckedAt   int64               `json:"checked_at"`
	Sequence    *uint64             `json:"channel_sequence"`
	FreshUntil  *int64              `json:"fresh_until"`
	Stage       *firmwareStage      `json:"staged"`
	Operation   *firmwareActivation `json:"operation"`
	Assessment  *string             `json:"assessment"`
}

type firmwareStatus struct {
	Schema      string              `json:"schema"`
	Enrolled    *bool               `json:"enrolled"`
	Activation  *firmwareActivation `json:"activation"`
	Check       *firmwareCheck      `json:"last_check"`
	Unavailable *bool               `json:"last_check_unavailable"`
}

var firmwareDeviceID = regexp.MustCompile(`^[0-9a-f]{40}$`)

func (active *firmwareActivation) valid() bool {
	return active == nil || (uuid.MatchString(active.Transaction) &&
		firmwareDeviceID.MatchString(active.Device) && isDigest(active.Offer) && firmwarePhase(active.Phase) &&
		(active.Qualification == nil || active.Qualification.valid()))
}

func firmwarePhase(value string) bool {
	switch value {
	case "draining", "flashing", "reboot-pending", "power-transition-pending", "outcome-unknown":
		return true
	}
	return false
}

func firmwareVersion(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func (stage *firmwareStage) valid() bool {
	if !firmwareDeviceID.MatchString(stage.Device) || !isDigest(stage.Offer) ||
		!isDigest(stage.Archive) || !firmwareVersion(stage.From) || !firmwareVersion(stage.Target) ||
		stage.From == stage.Target || !stage.Qualification.valid() {
		return false
	}
	if stage.Eligibility == nil {
		return true
	}
	switch *stage.Eligibility {
	case "blocked", "recovery-needed", "awaiting-maintenance", "checks-satisfied":
		return true
	}
	return false
}

func (status *firmwareStatus) valid() bool {
	if status == nil || status.Schema != "fvca-host-firmware-status-v2" ||
		status.Enrolled == nil || status.Unavailable == nil || (*status.Unavailable && status.Check != nil) {
		return false
	}
	if !*status.Enrolled {
		return status.Activation == nil && status.Check == nil && !*status.Unavailable
	}
	if !status.Activation.valid() {
		return false
	}
	check := status.Check
	if check == nil {
		return true
	}
	switch check.Disposition {
	case "checking", "no-offer", "staged", "blocked", "failed", "verified-success":
	default:
		if !firmwarePhase(check.Disposition) {
			return false
		}
	}
	if check.CheckedAt <= 0 || (check.Sequence != nil && *check.Sequence == 0) ||
		(check.Stage != nil) != (check.Disposition == "staged") ||
		(check.Stage != nil && !check.Stage.valid()) || !check.Operation.valid() {
		return false
	}
	if check.Assessment == nil {
		return true
	}
	switch *check.Assessment {
	case "target-reported", "attempt-failed", "no-matching-attempt", "conflicting-reports", "transition-pending", "version-only":
		return true
	}
	return false
}

func (c *client) firmware(ctx context.Context, host string) (*firmwareStatus, error) {
	view, err := c.exchange(ctx, host, serviceGuest, struct {
		Type string `json:"type"`
	}{"host-firmware-status"})
	if err != nil {
		return nil, err
	}
	if view.Result != "host-firmware-status" || !view.Firmware.valid() || view.Inventory != nil || view.Code != "" ||
		view.BootConfiguration != nil || view.ConfigurationEnrolled != nil || view.HostTrial != nil ||
		view.Observed != nil || view.Configuration != nil || view.Activation != "" ||
		view.OperationID != "" || view.OperationState != "" {
		return nil, errors.New("Host returned invalid firmware status")
	}
	return view.Firmware, nil
}

type hostFirmware struct {
	client *client
}

func (p *hostFirmware) Metadata(_ context.Context, req datasource.MetadataRequest, res *datasource.MetadataResponse) {
	res.TypeName = req.ProviderTypeName + "_host_firmware"
}

func (p *hostFirmware) Schema(_ context.Context, _ datasource.SchemaRequest, res *datasource.SchemaResponse) {
	computedString := schema.StringAttribute{Computed: true}
	seconds := schema.Int64Attribute{Computed: true}
	qualification := schema.SingleNestedAttribute{Computed: true, Attributes: map[string]schema.Attribute{
		"qualified_at": seconds, "observed_at": seconds, "age_seconds": seconds,
	}}
	operation := schema.SingleNestedAttribute{Computed: true, Attributes: map[string]schema.Attribute{
		"transaction": computedString, "device_id": computedString,
		"offer_sha256": computedString, "phase": computedString, "qualification": qualification,
	}}
	res.Schema = schema.Schema{
		Description: "Read the enrolled Hypervisor's firmware activation and last discovery result.",
		Attributes: map[string]schema.Attribute{
			"host_id":                schema.StringAttribute{Required: true},
			"enrolled":               schema.BoolAttribute{Computed: true},
			"last_check_unavailable": schema.BoolAttribute{Computed: true},
			"activation":             operation,
			"last_check": schema.SingleNestedAttribute{Computed: true, Attributes: map[string]schema.Attribute{
				"disposition":      computedString,
				"checked_at":       schema.Int64Attribute{Computed: true},
				"channel_sequence": schema.NumberAttribute{Computed: true},
				"fresh_until":      schema.Int64Attribute{Computed: true},
				"assessment":       computedString,
				"operation":        operation,
				"staged": schema.SingleNestedAttribute{Computed: true, Attributes: map[string]schema.Attribute{
					"device_id": computedString, "offer_sha256": computedString, "archive_sha256": computedString,
					"qualified_from": computedString, "target": computedString, "eligibility": computedString,
					"qualification": qualification,
				}},
			}},
		},
	}
}

func (p *hostFirmware) Configure(_ context.Context, req datasource.ConfigureRequest, res *datasource.ConfigureResponse) {
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

type activationModel struct {
	Transaction   types.String        `tfsdk:"transaction"`
	Device        types.String        `tfsdk:"device_id"`
	Offer         types.String        `tfsdk:"offer_sha256"`
	Phase         types.String        `tfsdk:"phase"`
	Qualification *qualificationModel `tfsdk:"qualification"`
}

type qualificationModel struct {
	QualifiedAt types.Int64 `tfsdk:"qualified_at"`
	ObservedAt  types.Int64 `tfsdk:"observed_at"`
	AgeSeconds  types.Int64 `tfsdk:"age_seconds"`
}

func (q *firmwareQualification) model() *qualificationModel {
	if q == nil {
		return nil
	}
	return &qualificationModel{
		QualifiedAt: types.Int64Value(q.QualifiedAt),
		ObservedAt:  types.Int64Value(q.ObservedAt),
		AgeSeconds:  types.Int64Value(q.AgeSeconds),
	}
}

func (active *firmwareActivation) model() *activationModel {
	if active == nil {
		return nil
	}
	return &activationModel{
		Transaction: types.StringValue(active.Transaction), Device: types.StringValue(active.Device),
		Offer: types.StringValue(active.Offer), Phase: types.StringValue(active.Phase),
		Qualification: active.Qualification.model(),
	}
}

type stageModel struct {
	Device        types.String        `tfsdk:"device_id"`
	Offer         types.String        `tfsdk:"offer_sha256"`
	Archive       types.String        `tfsdk:"archive_sha256"`
	From          types.String        `tfsdk:"qualified_from"`
	Target        types.String        `tfsdk:"target"`
	Eligibility   types.String        `tfsdk:"eligibility"`
	Qualification *qualificationModel `tfsdk:"qualification"`
}

type checkModel struct {
	Disposition types.String     `tfsdk:"disposition"`
	CheckedAt   types.Int64      `tfsdk:"checked_at"`
	Sequence    types.Number     `tfsdk:"channel_sequence"`
	FreshUntil  types.Int64      `tfsdk:"fresh_until"`
	Assessment  types.String     `tfsdk:"assessment"`
	Stage       *stageModel      `tfsdk:"staged"`
	Operation   *activationModel `tfsdk:"operation"`
}

type hostFirmwareModel struct {
	Host        types.String     `tfsdk:"host_id"`
	Enrolled    types.Bool       `tfsdk:"enrolled"`
	Activation  *activationModel `tfsdk:"activation"`
	Check       *checkModel      `tfsdk:"last_check"`
	Unavailable types.Bool       `tfsdk:"last_check_unavailable"`
}

func (p *hostFirmware) Read(ctx context.Context, req datasource.ReadRequest, res *datasource.ReadResponse) {
	var state hostFirmwareModel
	res.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if res.Diagnostics.HasError() {
		return
	}
	host := state.Host.ValueString()
	if p.client == nil || !enrolledIdentity(host, serviceGuest) {
		res.Diagnostics.AddError("Invalid FVCA Host", "Supply a configured provider and the enrolled Host UUID.")
		return
	}
	view, err := p.client.firmware(ctx, host)
	if err != nil {
		res.Diagnostics.AddError("Could not read FVCA firmware status", err.Error())
		return
	}
	state.Enrolled = types.BoolValue(*view.Enrolled)
	state.Unavailable = types.BoolValue(*view.Unavailable)
	state.Activation = view.Activation.model()
	if check := view.Check; check != nil {
		state.Check = &checkModel{
			Disposition: types.StringValue(check.Disposition), CheckedAt: types.Int64Value(check.CheckedAt),
			Sequence: types.NumberNull(), FreshUntil: types.Int64PointerValue(check.FreshUntil),
			Assessment: types.StringPointerValue(check.Assessment),
			Operation:  check.Operation.model(),
		}
		if check.Sequence != nil {
			state.Check.Sequence = number(*check.Sequence)
		}
		if stage := check.Stage; stage != nil {
			state.Check.Stage = &stageModel{
				Device: types.StringValue(stage.Device), Offer: types.StringValue(stage.Offer),
				Archive: types.StringValue(stage.Archive), From: types.StringValue(stage.From),
				Target: types.StringValue(stage.Target), Eligibility: types.StringPointerValue(stage.Eligibility),
				Qualification: stage.Qualification.model(),
			}
		}
	}
	res.Diagnostics.Append(res.State.Set(ctx, &state)...)
}
