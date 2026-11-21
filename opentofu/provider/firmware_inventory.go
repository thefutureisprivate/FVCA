package main

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const inventoryLimit = 128

type inventoryCursor struct {
	Generation string `json:"generation_sha256"`
	After      string `json:"after"`
}

type inventoryPage struct {
	Version    string           `json:"fwupd_version"`
	CheckedAt  int64            `json:"checked_at"`
	Generation string           `json:"generation_sha256"`
	Device     *inventoryDevice `json:"device"`
	Next       *inventoryCursor `json:"next"`
}

type inventoryDevice struct {
	ID              string   `json:"device_id"`
	Plugin          string   `json:"plugin"`
	Name            *string  `json:"name"`
	GUIDs           []string `json:"guids"`
	Protocols       []string `json:"protocols"`
	Vendors         []string `json:"vendor_ids"`
	Version         *string  `json:"installed_version"`
	RawVersion      *uint64  `json:"installed_version_raw"`
	Format          *string  `json:"version_format"`
	Updatable       bool     `json:"updatable"`
	Inhibited       bool     `json:"inhibited"`
	NeedsReboot     bool     `json:"needs_reboot"`
	NeedsShutdown   bool     `json:"needs_shutdown"`
	NeedsActivation bool     `json:"needs_activation"`
}

func (page *inventoryPage) valid(after *inventoryCursor) bool {
	if page == nil || !firmwareVersion(page.Version) || page.CheckedAt <= 0 || !isDigest(page.Generation) ||
		(after != nil && page.Generation != after.Generation) {
		return false
	}
	if page.Device == nil {
		return after == nil && page.Next == nil
	}
	device := page.Device
	if !firmwareDeviceID.MatchString(device.ID) || (after != nil && device.ID <= after.After) ||
		(device.Plugin != "nvme" && device.Plugin != "uefi_capsule") ||
		(device.Version != nil && !firmwareVersion(*device.Version)) ||
		!inventoryLabels(device.GUIDs, 32, uuid.MatchString) ||
		!inventoryLabels(device.Protocols, 8, firmwareVersion) ||
		!inventoryLabels(device.Vendors, 8, firmwareVersion) {
		return false
	}
	return page.Next == nil || (page.Next.After == device.ID && page.Next.Generation == page.Generation)
}

func inventoryLabels(values []string, limit int, valid func(string) bool) bool {
	if values == nil || len(values) > limit || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !valid(value) || (index > 0 && values[index-1] == value) {
			return false
		}
	}
	return true
}

func (c *client) inventory(ctx context.Context, host string) ([]inventoryDeviceModel, *inventoryPage, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	devices := []inventoryDeviceModel{}
	var after *inventoryCursor
	var first *inventoryPage
	for range inventoryLimit {
		view, err := c.exchange(ctx, host, serviceGuest, struct {
			Type  string           `json:"type"`
			After *inventoryCursor `json:"after"`
		}{"host-firmware-inventory", after})
		if err != nil {
			return nil, nil, err
		}
		page := view.Inventory
		if view.Result != "host-firmware-inventory" || view.Code != "" || !page.valid(after) ||
			view.BootConfiguration != nil || view.ConfigurationEnrolled != nil || view.HostTrial != nil ||
			view.Observed != nil || view.Configuration != nil || view.Activation != "" ||
			view.OperationID != "" || view.OperationState != "" || view.Firmware != nil || view.OSRelease != nil ||
			(first != nil && page.Version != first.Version) {
			return nil, nil, errors.New("Host returned an invalid firmware inventory page")
		}
		if first == nil {
			first = page
		}
		if page.Device != nil {
			devices = append(devices, page.Device.model())
		}
		if page.Next == nil {
			return devices, first, nil
		}
		after = page.Next
	}
	return nil, nil, errors.New("Host firmware inventory exceeds its page bound")
}

type hostFirmwareInventory struct {
	client *client
}

func (p *hostFirmwareInventory) Metadata(_ context.Context, req datasource.MetadataRequest, res *datasource.MetadataResponse) {
	res.TypeName = req.ProviderTypeName + "_host_firmware_inventory"
}

func (p *hostFirmwareInventory) Schema(_ context.Context, _ datasource.SchemaRequest, res *datasource.SchemaResponse) {
	str := schema.StringAttribute{Computed: true}
	boolean := schema.BoolAttribute{Computed: true}
	strings := schema.ListAttribute{Computed: true, ElementType: types.StringType}
	res.Schema = schema.Schema{
		Description: "Read installed firmware and device state from the enrolled Hypervisor.",
		Attributes: map[string]schema.Attribute{
			"host_id":           schema.StringAttribute{Required: true},
			"fwupd_version":     str,
			"generation_sha256": str,
			"checked_at":        schema.Int64Attribute{Computed: true},
			"devices": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"device_id": str, "plugin": str, "name": str,
					"guids": strings, "protocols": strings, "vendor_ids": strings,
					"installed_version": str, "version_format": str,
					"installed_version_raw": schema.NumberAttribute{Computed: true},
					"updatable":             boolean, "inhibited": boolean, "needs_reboot": boolean,
					"needs_shutdown": boolean, "needs_activation": boolean,
				}},
			},
		},
	}
}

func (p *hostFirmwareInventory) Configure(_ context.Context, req datasource.ConfigureRequest, res *datasource.ConfigureResponse) {
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

type inventoryDeviceModel struct {
	ID              types.String `tfsdk:"device_id"`
	Plugin          types.String `tfsdk:"plugin"`
	Name            types.String `tfsdk:"name"`
	GUIDs           []string     `tfsdk:"guids"`
	Protocols       []string     `tfsdk:"protocols"`
	Vendors         []string     `tfsdk:"vendor_ids"`
	Version         types.String `tfsdk:"installed_version"`
	RawVersion      types.Number `tfsdk:"installed_version_raw"`
	Format          types.String `tfsdk:"version_format"`
	Updatable       types.Bool   `tfsdk:"updatable"`
	Inhibited       types.Bool   `tfsdk:"inhibited"`
	NeedsReboot     types.Bool   `tfsdk:"needs_reboot"`
	NeedsShutdown   types.Bool   `tfsdk:"needs_shutdown"`
	NeedsActivation types.Bool   `tfsdk:"needs_activation"`
}

func (device *inventoryDevice) model() inventoryDeviceModel {
	raw := types.NumberNull()
	if device.RawVersion != nil {
		raw = number(*device.RawVersion)
	}
	return inventoryDeviceModel{
		ID: types.StringValue(device.ID), Plugin: types.StringValue(device.Plugin), Name: types.StringPointerValue(device.Name),
		GUIDs: device.GUIDs, Protocols: device.Protocols, Vendors: device.Vendors,
		Version: types.StringPointerValue(device.Version), RawVersion: raw, Format: types.StringPointerValue(device.Format),
		Updatable: types.BoolValue(device.Updatable), Inhibited: types.BoolValue(device.Inhibited),
		NeedsReboot: types.BoolValue(device.NeedsReboot), NeedsShutdown: types.BoolValue(device.NeedsShutdown),
		NeedsActivation: types.BoolValue(device.NeedsActivation),
	}
}

type inventoryModel struct {
	Host       types.String           `tfsdk:"host_id"`
	Version    types.String           `tfsdk:"fwupd_version"`
	CheckedAt  types.Int64            `tfsdk:"checked_at"`
	Generation types.String           `tfsdk:"generation_sha256"`
	Devices    []inventoryDeviceModel `tfsdk:"devices"`
}

func (p *hostFirmwareInventory) Read(ctx context.Context, req datasource.ReadRequest, res *datasource.ReadResponse) {
	var state inventoryModel
	res.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if res.Diagnostics.HasError() {
		return
	}
	host := state.Host.ValueString()
	if p.client == nil || !enrolledIdentity(host, serviceGuest) {
		res.Diagnostics.AddError("Invalid FVCA Host", "Supply a configured provider and the enrolled Host UUID.")
		return
	}
	devices, first, err := p.client.inventory(ctx, host)
	if err != nil {
		res.Diagnostics.AddError("Could not read FVCA firmware inventory", err.Error())
		return
	}
	state.Version = types.StringValue(first.Version)
	state.Generation = types.StringValue(first.Generation)
	state.CheckedAt = types.Int64Value(first.CheckedAt)
	state.Devices = devices
	res.Diagnostics.Append(res.State.Set(ctx, &state)...)
}
