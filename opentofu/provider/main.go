package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

const version = "0.3.0"

func main() {
	if err := providerserver.Serve(context.Background(), newProvider, providerserver.ServeOpts{
		Address:         "registry.opentofu.org/thefutureisprivate/fvca",
		ProtocolVersion: 6,
	}); err != nil {
		log.Fatal(err)
	}
}
