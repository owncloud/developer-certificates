package conformance

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestPrivilegedRevocationWorkflowInvariants pins the security-critical
// properties of the privileged revocation workflow (enrollment spec §5.2): it is
// workflow_dispatch-ONLY (no schedule, no issue trigger — external filing must
// never reach it), serialized under the shared ledger-write group (§2), and
// minimally permissioned (design §10).
func TestPrivilegedRevocationWorkflowInvariants(t *testing.T) {
	raw := mustRead(t, repoPath(".github", "workflows", "privileged-revocation.yml"))

	// Parse the `on:` triggers as a free-form map so we can assert presence/absence.
	var top struct {
		On          map[string]yaml.Node `yaml:"on"`
		Concurrency struct {
			Group            string `yaml:"group"`
			CancelInProgress bool   `yaml:"cancel-in-progress"`
		} `yaml:"concurrency"`
		Permissions map[string]string `yaml:"permissions"`
	}
	if err := yaml.Unmarshal(raw, &top); err != nil {
		t.Fatalf("parse privileged-revocation.yml: %v", err)
	}

	// workflow_dispatch is the ONLY trigger (the security property: dispatch-only, §5.2).
	if _, ok := top.On["workflow_dispatch"]; !ok {
		t.Error("privileged-revocation.yml: must have a workflow_dispatch trigger")
	}
	for key := range top.On {
		if key != "workflow_dispatch" {
			t.Errorf("privileged-revocation.yml: unexpected trigger %q (must be workflow_dispatch-ONLY, §5.2)", key)
		}
	}

	// Shared ledger-write group, never cancelled (§2).
	if top.Concurrency.Group != "ledger-write" {
		t.Errorf("concurrency.group = %q, want ledger-write (shared, §2)", top.Concurrency.Group)
	}
	if top.Concurrency.CancelInProgress {
		t.Error("cancel-in-progress must be false (§2)")
	}

	// Minimal permissions (design §10): the default GITHUB_TOKEN is used only by
	// actions/checkout, so it is read-only. The ledger write goes through the App token.
	if top.Permissions["contents"] != "read" {
		t.Errorf("permissions[contents] = %q, want read", top.Permissions["contents"])
	}
	for key := range top.Permissions {
		if key != "contents" {
			t.Errorf("unexpected permission %q (keep minimal, design §10)", key)
		}
	}

	// Actions SHA-pinned (repo checklist).
	for _, line := range strings.Split(string(raw), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "- uses:") && !strings.Contains(l, "@") {
			t.Errorf("uses without a pinned ref: %q", l)
		}
	}
}

// TestCRLRegeneratesAfterPrivilegedRevocation pins that crl.yml regenerates the
// CRL after a privileged revocation (spec §5.2 "Triggers CRL regeneration").
func TestCRLRegeneratesAfterPrivilegedRevocation(t *testing.T) {
	raw := mustRead(t, repoPath(".github", "workflows", "crl.yml"))
	var top struct {
		On struct {
			WorkflowRun struct {
				Workflows []string `yaml:"workflows"`
			} `yaml:"workflow_run"`
		} `yaml:"on"`
	}
	if err := yaml.Unmarshal(raw, &top); err != nil {
		t.Fatalf("parse crl.yml: %v", err)
	}
	found := false
	for _, w := range top.On.WorkflowRun.Workflows {
		if w == "privileged-revocation" {
			found = true
		}
	}
	if !found {
		t.Errorf("crl.yml workflow_run.workflows = %v, must include privileged-revocation (§5.2)", top.On.WorkflowRun.Workflows)
	}
}
