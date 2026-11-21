package main

import (
	"math"
	"strings"
	"testing"
)

func TestFirmwareStatusKeepsPendingAndRecordedOperationSeparate(t *testing.T) {
	enrolled, unavailable := true, false
	operation := &firmwareActivation{
		Transaction: "dce9f9d8-344d-418c-870b-8784cbdf76ef", Device: strings.Repeat("b", 40),
		Offer: strings.Repeat("c", 64), Phase: "outcome-unknown",
	}
	view := &firmwareStatus{Schema: "fvca-host-firmware-status-v1", Enrolled: &enrolled,
		Unavailable: &unavailable, Activation: operation,
		Check: &firmwareCheck{Disposition: "outcome-unknown", CheckedAt: 100, Operation: operation}}
	if !view.valid() {
		t.Fatal("rejected an unresolved operation")
	}
	view.Activation = nil
	if !view.valid() {
		t.Fatal("expected retained observation to be independent of current activation")
	}
	view.Check.Disposition = "staged"
	if view.valid() {
		t.Fatal("accepted an unidentified staged offer")
	}
	view.Check = nil
	view.Activation = operation
	unavailable = true
	if !view.valid() {
		t.Fatal("invalid last-check history hid an active operation")
	}
}

func TestFirmwareInventoryBindsPaginationToOneGeneration(t *testing.T) {
	generation := strings.Repeat("c", 64)
	device := inventoryDevice{
		ID: strings.Repeat("b", 40), Plugin: "nvme",
		GUIDs: []string{}, Protocols: []string{"org.nvmexpress"}, Vendors: []string{},
	}
	page := inventoryPage{Version: "2.1.10", CheckedAt: 100, Generation: generation, Device: &device}
	after := inventoryCursor{Generation: generation, After: strings.Repeat("a", 40)}
	if !page.valid(&after) {
		t.Fatal("rejected a later device within the same inventory")
	}
	page.Next = &after
	if page.valid(nil) {
		t.Fatal("accepted a continuation that does not follow the device")
	}
	page.Next = nil
	page.Generation = strings.Repeat("d", 64)
	if page.valid(&after) {
		t.Fatal("accepted a continuation from a changed inventory")
	}
}

func TestPreflightBindsFullConfiguration(t *testing.T) {
	defaults := settings{VCPUs: 2, MemoryMiB: 2048}
	revision := uint64(1)
	digest := "d1bfe17ab1d4bba583943189bf1a98f40381038bf6b768d6d7ab0d4979b62b99"
	candidate := settings{VCPUs: 3, MemoryMiB: 2560, Revision: &revision, SHA256: &digest}
	if !candidate.valid(serviceGuest) {
		t.Fatal("expected canonical first revision")
	}
	if err := requireIntent(serviceGuest, defaults, candidate, "host-trial"); err != nil {
		t.Fatal(err)
	}
	if err := requireIntent(serviceGuest, candidate, candidate, "none"); err != nil {
		t.Fatal(err)
	}
	if err := requireIntent(serviceGuest, candidate, candidate, "host-trial"); err == nil {
		t.Fatal("accepted a reboot for unchanged intent")
	}
	forged := candidate
	forged.MemoryMiB = 3072
	if forged.valid(serviceGuest) || requireIntent(serviceGuest, defaults, forged, "host-trial") == nil {
		t.Fatal("accepted altered resources under the same digest")
	}
	overflow := uint64(math.MaxUint64)
	exhausted := settings{VCPUs: 2, MemoryMiB: 2048, Revision: &overflow, SHA256: &digest}
	if requireIntent(serviceGuest, exhausted, candidate, "host-trial") == nil {
		t.Fatal("accepted a revision after exhaustion")
	}
}
