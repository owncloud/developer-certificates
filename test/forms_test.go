package conformance

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// issueForm is the subset of the GitHub issue-form schema we assert on.
type issueForm struct {
	Name        string     `yaml:"name"`
	Description string     `yaml:"description"`
	Title       string     `yaml:"title"`
	Labels      []string   `yaml:"labels"`
	Body        []formBody `yaml:"body"`
}

type formBody struct {
	Type        string            `yaml:"type"`
	ID          string            `yaml:"id"`
	Attributes  map[string]any    `yaml:"attributes"`
	Validations map[string]bool   `yaml:"validations"`
}

// appIdRegex is the security-critical appId grammar from design §4.1. The
// ledger FCFS check and the server CN==appId check must treat appIds
// identically, so this exact string must appear (and not drift) across the
// forms and the developer guide.
const appIdRegex = `^[a-z][a-z0-9_-]{1,63}$`

// challengePath is the fixed nonce-challenge file path (design §5.3).
const challengePath = "/.well-known/owncloud-codesigning-challenge.txt"

func loadForm(t *testing.T, name string) issueForm {
	t.Helper()
	path := repoPath(".github", "ISSUE_TEMPLATE", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read issue form %s: %v", name, err)
	}
	var f issueForm
	if err := yaml.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse issue form %s: %v", name, err)
	}
	return f
}

// bodyElement returns the first body element of the given type whose id
// matches, or ok=false.
func bodyElement(f issueForm, typ, id string) (formBody, bool) {
	for _, b := range f.Body {
		if b.Type == typ && b.ID == id {
			return b, true
		}
	}
	return formBody{}, false
}

func hasLabel(f issueForm, label string) bool {
	for _, l := range f.Labels {
		if l == label {
			return true
		}
	}
	return false
}

func TestCertificateRequestForm(t *testing.T) {
	f := loadForm(t, "certificate-request.yml")

	if !hasLabel(f, "cert-request") {
		t.Errorf("certificate-request.yml: expected label %q, got %v", "cert-request", f.Labels)
	}

	// Exactly two input body elements (design §5.2: exactly two fields): a CSR
	// textarea and a repo input. Markdown blocks are informational, not inputs.
	var inputs []formBody
	for _, b := range f.Body {
		if b.Type == "textarea" || b.Type == "input" {
			inputs = append(inputs, b)
		}
	}
	if len(inputs) != 2 {
		t.Errorf("certificate-request.yml: expected exactly 2 input fields, got %d", len(inputs))
	}

	csr, ok := bodyElement(f, "textarea", "csr")
	if !ok {
		t.Fatalf("certificate-request.yml: missing textarea field id=csr")
	}
	if !csr.Validations["required"] {
		t.Errorf("certificate-request.yml: csr field must be required")
	}

	repo, ok := bodyElement(f, "input", "repo")
	if !ok {
		t.Fatalf("certificate-request.yml: missing input field id=repo")
	}
	if !repo.Validations["required"] {
		t.Errorf("certificate-request.yml: repo field must be required")
	}

	// The appId regex must be surfaced to the developer in the form.
	if !strings.Contains(string(mustRead(t, repoPath(".github", "ISSUE_TEMPLATE", "certificate-request.yml"))), appIdRegex) {
		t.Errorf("certificate-request.yml: expected appId regex %q to appear in the form", appIdRegex)
	}
}

func TestRevocationRequestForm(t *testing.T) {
	f := loadForm(t, "revocation-request.yml")

	if !hasLabel(f, "revocation-request") {
		t.Errorf("revocation-request.yml: expected label %q, got %v", "revocation-request", f.Labels)
	}

	if _, ok := bodyElement(f, "input", "cert"); !ok {
		t.Errorf("revocation-request.yml: missing input field id=cert")
	}
	if _, ok := bodyElement(f, "textarea", "signed_request"); !ok {
		t.Errorf("revocation-request.yml: missing textarea field id=signed_request")
	}
}

func TestIssueTemplateConfig(t *testing.T) {
	raw := mustRead(t, repoPath(".github", "ISSUE_TEMPLATE", "config.yml"))
	var cfg struct {
		BlankIssuesEnabled bool `yaml:"blank_issues_enabled"`
		ContactLinks       []struct {
			Name string `yaml:"name"`
			URL  string `yaml:"url"`
		} `yaml:"contact_links"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("parse config.yml: %v", err)
	}
	if cfg.BlankIssuesEnabled {
		t.Errorf("config.yml: blank_issues_enabled must be false (only the two forms are valid intake)")
	}
	// A contact link must route abuse / lost-key reports to the Security
	// Advisory (VDP) — design §7.1 case 3.
	found := false
	for _, c := range cfg.ContactLinks {
		if strings.Contains(c.URL, "/security/advisories") {
			found = true
		}
	}
	if !found {
		t.Errorf("config.yml: expected a contact link to the Security Advisory (…/security/advisories…)")
	}
}

func TestDeveloperGuide(t *testing.T) {
	guide := string(mustRead(t, repoPath("docs", "developer-guide.md")))

	if !strings.Contains(guide, appIdRegex) {
		t.Errorf("developer-guide.md: expected appId regex %q (design §4.1) to appear", appIdRegex)
	}
	if !strings.Contains(guide, challengePath) {
		t.Errorf("developer-guide.md: expected challenge path %q (design §5.3) to appear", challengePath)
	}
	// The generic placeholder must be resolved to the real repo slug.
	if strings.Contains(guide, "<codesigning-repo>") {
		t.Errorf("developer-guide.md: unresolved <codesigning-repo> placeholder remains")
	}
	if !strings.Contains(guide, "DeepDiver1975/developer-certificates") {
		t.Errorf("developer-guide.md: expected resolved repo slug DeepDiver1975/developer-certificates")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}
