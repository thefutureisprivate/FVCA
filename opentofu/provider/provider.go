package main

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type fvcaProvider struct{}

func newProvider() provider.Provider { return &fvcaProvider{} }

func (p *fvcaProvider) Metadata(_ context.Context, _ provider.MetadataRequest, res *provider.MetadataResponse) {
	res.TypeName = "fvca"
	res.Version = version
}

func (p *fvcaProvider) Schema(_ context.Context, _ provider.SchemaRequest, res *provider.SchemaResponse) {
	res.Schema = schema.Schema{
		Description: "Authenticated off-node planning for an enrolled FVCA Hypervisor.",
		Attributes: map[string]schema.Attribute{
			"address": schema.StringAttribute{
				Required: true, Description: "Enrolled literal private IP and port.",
			},
			"server_name": schema.StringAttribute{
				Required: true, Description: "TLS server name covered by the enrolled certificate.",
			},
			"tls_certificate_sha256": schema.StringAttribute{
				Required: true, Description: "SHA-256 of the enrolled leaf certificate in DER form.",
			},
		},
	}
}

type providerConfig struct {
	Address     types.String `tfsdk:"address"`
	ServerName  types.String `tfsdk:"server_name"`
	Certificate types.String `tfsdk:"tls_certificate_sha256"`
}

func (p *fvcaProvider) Configure(ctx context.Context, req provider.ConfigureRequest, res *provider.ConfigureResponse) {
	var config providerConfig
	res.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if res.Diagnostics.HasError() {
		return
	}
	c, err := newClient(config.Address.ValueString(), config.ServerName.ValueString(),
		config.Certificate.ValueString(), os.Getenv("FVCA_MANAGEMENT_CA_FILE"), os.Getenv("FVCA_OPERATOR_KEY_FILE"))
	if err != nil {
		res.Diagnostics.AddError("Invalid FVCA provider configuration", err.Error())
		return
	}
	res.DataSourceData = c
}

func (p *fvcaProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{func() datasource.DataSource { return &guestConfigurationPlan{} }}
}

func (p *fvcaProvider) Resources(_ context.Context) []func() resource.Resource { return nil }
