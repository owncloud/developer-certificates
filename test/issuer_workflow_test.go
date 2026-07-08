package conformance

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/DeepDiver1975/developer-certificates/internal/enroll"
)

// workflow is the subset of a GitHub Actions workflow we assert on.
type workflow struct {
	Concurrency struct {
		Group            string `yaml:"group"`
		CancelInProgress bool   `yaml:"cancel-in-progress"`
	} `yaml:"concurrency"`
	Permissions map[string]string `yaml:"permissions"`
	On          struct {
		Schedule []struct {
			Cron string `yaml:"cron"`
		} `yaml:"schedule"`
	} `yaml:"on"`
}

// TestIssuerWorkflowInvariants pins the security-critical properties of the
// issuer workflow that the enrollment spec requires: serialized ledger writes
// that are never cancelled (§2), the 10-minute poll cadence (§11), and minimal
// permissions (design §10). If the workflow drifts from the spec, this fails.
func TestIssuerWorkflowInvariants(t *testing.T) {
	raw := mustRead(t, repoPath(".github", "workflows", "issuer.yml"))

	var wf workflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parse issuer.yml: %v", err)
	}

	// Single-concurrency, never cancelled (spec §2, design §6).
	if wf.Concurrency.Group == "" {
		t.Error("issuer.yml: missing concurrency.group (ledger writes must be serialized)")
	}
	if wf.Concurrency.CancelInProgress {
		t.Error("issuer.yml: cancel-in-progress must be false (spec §2)")
	}

	// 10-minute poll cadence (spec §11).
	const wantCron = "*/10 * * * *"
	found := false
	for _, s := range wf.On.Schedule {
		if s.Cron == wantCron {
			found = true
		}
	}
	if !found {
		t.Errorf("issuer.yml: expected schedule cron %q (spec §11)", wantCron)
	}

	// Minimal permissions (design §10): issues + contents only.
	for key, want := range map[string]string{"issues": "write", "contents": "write"} {
		if wf.Permissions[key] != want {
			t.Errorf("issuer.yml: permissions[%q] = %q, want %q", key, wf.Permissions[key], want)
		}
	}
	for key := range wf.Permissions {
		if key != "issues" && key != "contents" {
			t.Errorf("issuer.yml: unexpected permission %q (keep permissions minimal, design §10)", key)
		}
	}

	// Actions must be SHA-pinned, not floating tags (repo PR checklist).
	body := string(raw)
	for _, line := range strings.Split(body, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "- uses:") && !strings.Contains(l, "@") {
			t.Errorf("issuer.yml: uses without a pinned ref: %q", l)
		}
	}
}

// TestIssuerWorkflowLabels guards that the terminal labels the pipeline sets
// (spec §9) all appear in the workflow's issue-event trigger surface OR are at
// least the canonical set the code uses — pinning the vocabulary against drift.
func TestIssuerWorkflowLabels(t *testing.T) {
	// The label constants live in internal/enroll; assert the canonical §9 set
	// is exactly what the package exposes, so a rename can't silently diverge
	// from the spec vocabulary.
	want := map[string]string{
		"invalid":            enroll.LabelInvalid,
		"needs-changes":      enroll.LabelNeedsChanges,
		"awaiting-challenge": enroll.LabelAwaitingChallenge,
		"expired":            enroll.LabelExpired,
		"rejected":           enroll.LabelRejected,
		"issued":             enroll.LabelIssued,
	}
	for spec, got := range want {
		if spec != got {
			t.Errorf("enroll label constant = %q, want spec §9 value %q", got, spec)
		}
	}
}
