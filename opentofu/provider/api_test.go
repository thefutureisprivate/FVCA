package main

import (
	"math"
	"strings"
	"testing"
)

func TestOSReleaseFreshnessAndRole(t *testing.T) {
	enrolled, missed := true, false
	slot, staged := "a", strings.Repeat("b", 64)
	refresh, expiry, deadline := int64(100), int64(300), int64(200)
	sequence := uint64(3)
	view := osReleaseStatus{
		Schema: "fvca-os-release-observation-v1", Role: "hypervisor", Enrolled: &enrolled, ObservedAt: expiry,
		Active: &recordedOSRelease{
			release: release{Epoch: 1, Sequence: 2, SHA256: strings.Repeat("a", 64)}, Role: "hypervisor", Slot: &slot,
		},
		Check: &osCheck{
			Channel: "stable", PolicyRevision: 1, Disposition: "ready", Freshness: "expired",
			LastRefresh: &refresh, FreshUntil: &expiry, ChannelSequence: &sequence, Staged: &staged,
			Candidate:              &osCandidate{Epoch: 2, SHA256: staged, Urgency: "security", ActivateBy: &deadline},
			SecurityDeadlineMissed: &missed,
		},
	}
	if !view.valid("hypervisor") || view.valid("service-guest") {
		t.Fatal("expected an expired observation scoped to its requested role")
	}
	view.Check.Freshness = "fresh"
	if view.valid("hypervisor") {
		t.Fatal("accepted a report at the exclusive expiry boundary as fresh")
	}
	view.Check.Freshness = "superseded"
	view.Active = nil
	if !view.valid("hypervisor") {
		t.Fatal("rejected a historical check after its active record disappeared")
	}
}

func TestFirmwareStatusKeepsPendingAndRecordedOperationSeparate(t *testing.T) {
	enrolled, unavailable := true, false
	operation := &firmwareActivation{
		Transaction: "dce9f9d8-344d-418c-870b-8784cbdf76ef", Device: strings.Repeat("b", 40),
		Offer: strings.Repeat("c", 64), Phase: "outcome-unknown",
		Qualification: &firmwareQualification{QualifiedAt: 80, ObservedAt: 105, AgeSeconds: 25},
	}
	view := &firmwareStatus{Schema: "fvca-host-firmware-status-v2", Enrolled: &enrolled,
		Unavailable: &unavailable, Activation: operation,
		Check: &firmwareCheck{Disposition: "outcome-unknown", CheckedAt: 100, Operation: operation}}
	if !view.valid() {
		t.Fatal("rejected an unresolved operation")
	}
	operation.Qualification.AgeSeconds = 0
	if view.valid() {
		t.Fatal("accepted a qualification age inconsistent with its signed and observed dates")
	}
	operation.Qualification.AgeSeconds = 25
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
