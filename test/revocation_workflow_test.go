package conformance

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/DeepDiver1975/developer-certificates/internal/revoke"
)

// TestRevocationWorkflowInvariants pins the security-critical properties of the
// revocation workflow: ledger writes serialized under the SAME concurrency group
// as the issuer and never cancelled (spec §2), the 10-minute poll cadence (§11),
// and minimal permissions (design §10).
func TestRevocationWorkflowInvariants(t *testing.T) {
	raw := mustRead(t, repoPath(".github", "workflows", "revocation.yml"))

	var wf workflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parse revocation.yml: %v", err)
	}

	// Must share the issuer's ledger-write group so the two bots serialize (§2).
	if wf.Concurrency.Group != "ledger-write" {
		t.Errorf("revocation.yml: concurrency.group = %q, want ledger-write (shared with issuer, spec §2)", wf.Concurrency.Group)
	}
	if wf.Concurrency.CancelInProgress {
		t.Error("revocation.yml: cancel-in-progress must be false (spec §2)")
	}

	const wantCron = "*/10 * * * *"
	found := false
	for _, s := range wf.On.Schedule {
		if s.Cron == wantCron {
			found = true
		}
	}
	if !found {
		t.Errorf("revocation.yml: expected schedule cron %q (spec §11)", wantCron)
	}

	for key, want := range map[string]string{"issues": "write", "contents": "write"} {
		if wf.Permissions[key] != want {
			t.Errorf("revocation.yml: permissions[%q] = %q, want %q", key, wf.Permissions[key], want)
		}
	}
	for key := range wf.Permissions {
		if key != "issues" && key != "contents" {
			t.Errorf("revocation.yml: unexpected permission %q (keep minimal, design §10)", key)
		}
	}

	body := string(raw)
	for _, line := range strings.Split(body, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "- uses:") && !strings.Contains(l, "@") {
			t.Errorf("revocation.yml: uses without a pinned ref: %q", l)
		}
	}
}

// TestRevocationLabels pins the revocation bot's label vocabulary to the spec §9
// values so a rename cannot silently diverge.
func TestRevocationLabels(t *testing.T) {
	want := map[string]string{
		"invalid": revoke.LabelInvalid,
		"revoked": revoke.LabelRevoked,
	}
	for spec, got := range want {
		if spec != got {
			t.Errorf("revoke label constant = %q, want spec §9 value %q", got, spec)
		}
	}
}
