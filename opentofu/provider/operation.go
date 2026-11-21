package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"time"
)

const planValiditySeconds int64 = 900

type submission struct {
	Expected    *binding `json:"expected"`
	Next        binding  `json:"next"`
	VCPUs       int64    `json:"vcpus"`
	MemoryMiB   int64    `json:"memory_mib"`
	PlannedAt   int64    `json:"planned_at"`
	PlanExpires int64    `json:"plan_expires"`
}

// The data source captures this nonsecret proposal once in the encrypted plan.
// The resource's write-only input lets OpenTofu carry it into final planning
// without treating fresh observations as a change to managed settings.
type proposal struct {
	Host  string     `json:"host"`
	Guest string     `json:"guest"`
	Scope string     `json:"scope"`
	Plan  submission `json:"plan"`
}

func captureProposal(host, guest string, cpu, memory int64, planned plan) proposal {
	now := time.Now().Unix()
	value := proposal{Host: host, Guest: guest, Scope: planned.Scope, Plan: submission{
		Expected: planned.Active.binding(), VCPUs: cpu, MemoryMiB: memory,
		PlannedAt: now, PlanExpires: now + planValiditySeconds,
	}}
	if desired := planned.Desired.binding(); desired != nil {
		value.Plan.Next = *desired
	}
	return value
}

func (p proposal) validIntent() bool {
	s := p.Plan
	if s.Expected != nil && (s.Expected.Revision == 0 || !isDigest(s.Expected.SHA256)) {
		return false
	}
	if s.Next.Revision != 0 &&
		s.Next.SHA256 != configurationDigest(p.Guest, s.Next.Revision, s.VCPUs, s.MemoryMiB) {
		return false
	}
	switch p.Scope {
	case "none":
		if s.Expected != nil {
			return s.Next == *s.Expected
		}
		return s.Next == (binding{}) && s.VCPUs == 2 && s.MemoryMiB == 2048
	case "host-trial":
		if s.Expected != nil {
			return s.Expected.Revision != math.MaxUint64 && s.Next.Revision == s.Expected.Revision+1
		}
		return s.Next.Revision == 1
	default:
		return false
	}
}

func operationID(host, guest string, previous *binding, next binding) string {
	prior := "default"
	if previous != nil {
		prior = fmt.Sprintf("%d,%s", previous.Revision, previous.SHA256)
	}
	identity := fmt.Sprintf("FVCA-GUEST-CONFIGURATION-INTENT-1\nhost=%s\nguest=%s\nprevious=%s\nnext=%d,%s\n",
		host, guest, prior, next.Revision, next.SHA256)
	digest := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(digest[:])
}

func (s submission) validAt(now int64) bool {
	return s.PlannedAt > 0 && s.PlannedAt <= math.MaxInt64-planValiditySeconds &&
		s.PlanExpires == s.PlannedAt+planValiditySeconds && s.PlannedAt <= now && now < s.PlanExpires
}

func requireReceipt(r response, id, guest string, next binding, cpu, memory int64) error {
	if r.Result != "configuration-operation" || r.OperationID != id || r.Code != "" ||
		r.BootConfiguration != nil || r.ConfigurationEnrolled != nil ||
		r.HostTrial != nil || r.Observed != nil || r.Firmware != nil || r.Inventory != nil || r.OSRelease != nil || r.Activation != "" ||
		r.Configuration == nil || !r.Configuration.valid(guest) {
		return errors.New("Host did not return the exact configuration operation")
	}
	if selected := r.Configuration.binding(); selected == nil || *selected != next ||
		r.Configuration.VCPUs != cpu || r.Configuration.MemoryMiB != memory {
		return errors.New("Host operation settings differ from the saved plan")
	}
	switch r.OperationState {
	case "pending-activation", "in-trial", "active", "superseded":
		return nil
	default:
		return errors.New("Host returned an unknown configuration operation state")
	}
}

func (c *client) inspect(ctx context.Context, host, guest, id string, next binding, cpu, memory int64) (string, error) {
	r, err := c.exchange(ctx, host, guest, struct {
		Type string `json:"type"`
		ID   string `json:"operation_id"`
	}{"configuration-operation", id})
	if err != nil {
		return "", err
	}
	if err := requireReceipt(r, id, guest, next, cpu, memory); err != nil {
		return "", err
	}
	return r.OperationState, nil
}

func (c *client) submit(ctx context.Context, host, guest, id string, s submission) (string, error) {
	state, err := c.inspect(ctx, host, guest, id, s.Next, s.VCPUs, s.MemoryMiB)
	if err == nil {
		if state == "superseded" {
			return "", errors.New("the saved operation was superseded; create a new plan")
		}
		return state, nil
	}
	if !errors.Is(err, errUnknownOperation) {
		return "", err
	}
	if !s.validAt(time.Now().Unix()) {
		return "", errors.New("the saved configuration plan expired; create a new plan")
	}
	signer, err := loadSigner(os.Getenv("FVCA_APPLY_OPERATOR_KEY_FILE"))
	if err != nil {
		return "", errors.New("FVCA_APPLY_OPERATOR_KEY_FILE must name the runner's private PKCS#8 Ed25519 submitter key with mode 0600")
	}
	defer clear(signer)
	r, err := c.signedExchange(ctx, host, guest, struct {
		Type string     `json:"type"`
		Plan submission `json:"plan"`
	}{"apply-configuration", s}, signer)
	if err != nil {
		// The broker can finish its durable write after the connection fails.
		state, inspectErr := c.inspect(ctx, host, guest, id, s.Next, s.VCPUs, s.MemoryMiB)
		if inspectErr == nil && state != "superseded" {
			return state, nil
		}
		return "", fmt.Errorf("operation %s: %w", id, err)
	}
	if err := requireReceipt(r, id, guest, s.Next, s.VCPUs, s.MemoryMiB); err != nil {
		return "", err
	}
	if r.OperationState == "superseded" {
		return "", errors.New("the Host reported a superseded operation; create a new plan")
	}
	return r.OperationState, nil
}
