package main

import (
	"math"
	"testing"
)

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
