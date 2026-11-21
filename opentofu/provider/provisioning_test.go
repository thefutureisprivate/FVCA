package main

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestProvisioningReceiptBindsSavedOffer(t *testing.T) {
	const operation = "ec15af20d83dcff71f70ff63b32b5ca350a59831f07a666e2af1deb6939be2ea"
	bundle, seed := strings.Repeat("a", 64), strings.Repeat("b", 64)
	saved := provisioningState{
		HostID:  types.StringValue("367f5cbc-c46a-437d-af72-5d96d805d234"),
		GuestID: types.StringValue(serviceGuest), OperationID: types.StringValue(operation),
		BundleSHA: types.StringValue(bundle), SeedSHA: types.StringValue(seed),
		DiskBytes: types.Int64Value(67108864), VCPUs: types.Int64Value(2), MemoryMiB: types.Int64Value(2048),
	}
	offer := provisioningReceipt{
		OperationID: operation, State: "pending", BundleSHA: bundle, SeedSHA: seed, DiskBytes: 67108864,
		Configuration: &settings{VCPUs: 2, MemoryMiB: 2048},
	}
	if _, err := saved.requireReceipt(response{Result: "guest-provisioning", Provisioning: &offer}); err != nil {
		t.Fatal(err)
	}
	for _, update := range []func(*provisioningReceipt){
		func(reply *provisioningReceipt) { reply.OperationID = bundle },
		func(reply *provisioningReceipt) { reply.BundleSHA = seed },
		func(reply *provisioningReceipt) { reply.SeedSHA = bundle },
		func(reply *provisioningReceipt) { reply.DiskBytes += 512 },
		func(reply *provisioningReceipt) { reply.Configuration = &settings{VCPUs: 3, MemoryMiB: 2048} },
		func(reply *provisioningReceipt) { reply.State = "unknown" },
	} {
		modified := offer
		update(&modified)
		if _, err := saved.requireReceipt(response{Result: "guest-provisioning", Provisioning: &modified}); err == nil {
			t.Fatalf("accepted an unexpected receipt: %+v", modified)
		}
	}
}
