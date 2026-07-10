package conformance

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestCRLWorkflowInvariants pins the security-critical properties of the CRL
// workflow: ledger reads/writes serialized under the SAME concurrency group as
// the issuer/revocation bots and never cancelled (enrollment spec §2), the daily
// regeneration cadence (attestation-and-crl spec §3.1), and minimal permissions
// (design §10).
func TestCRLWorkflowInvariants(t *testing.T) {
	raw := mustRead(t, repoPath(".github", "workflows", "crl.yml"))

	var wf workflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parse crl.yml: %v", err)
	}

	if wf.Concurrency.Group != "ledger-write" {
		t.Errorf("crl.yml: concurrency.group = %q, want ledger-write (shared, spec §2)", wf.Concurrency.Group)
	}
	if wf.Concurrency.CancelInProgress {
		t.Error("crl.yml: cancel-in-progress must be false (spec §2)")
	}

	const wantCron = "0 0 * * *"
	found := false
	for _, s := range wf.On.Schedule {
		if s.Cron == wantCron {
			found = true
		}
	}
	if !found {
		t.Errorf("crl.yml: expected daily schedule cron %q (spec §3.1)", wantCron)
	}

	// Minimal permissions: contents:write only (design §10).
	if wf.Permissions["contents"] != "write" {
		t.Errorf("crl.yml: permissions[contents] = %q, want write", wf.Permissions["contents"])
	}
	for key := range wf.Permissions {
		if key != "contents" {
			t.Errorf("crl.yml: unexpected permission %q (keep minimal, design §10)", key)
		}
	}

	// Actions must be SHA-pinned (repo checklist).
	for _, line := range strings.Split(string(raw), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "- uses:") && !strings.Contains(l, "@") {
			t.Errorf("crl.yml: uses without a pinned ref: %q", l)
		}
	}
}
