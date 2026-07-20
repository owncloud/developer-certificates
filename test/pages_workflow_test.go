package conformance

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestPagesWorkflowInvariants pins the security-critical properties of the Pages
// deploy workflow (design §13). The overriding invariant: the Pages site must
// expose ONLY the CRL, never the repository source tree. The workflow therefore
// uses the GitHub Actions Pages build (which serves exactly the uploaded
// artifact) and stages only the named CRL files — NOT a "deploy from a branch" of
// the whole repo. It also needs pages:write + id-token:write to deploy, and
// SHA-pinned actions per the repo checklist.
func TestPagesWorkflowInvariants(t *testing.T) {
	raw := mustRead(t, repoPath(".github", "workflows", "pages.yml"))
	body := string(raw)

	var wf workflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parse pages.yml: %v", err)
	}

	// Deploy grants required by the Actions Pages build; contents stays read.
	wantPerms := map[string]string{
		"contents": "read",
		"pages":    "write",
		"id-token": "write",
	}
	for key, want := range wantPerms {
		if wf.Permissions[key] != want {
			t.Errorf("pages.yml: permissions[%q] = %q, want %q", key, wf.Permissions[key], want)
		}
	}
	for key := range wf.Permissions {
		if _, ok := wantPerms[key]; !ok {
			t.Errorf("pages.yml: unexpected permission %q (keep minimal, design §10)", key)
		}
	}

	// The site must contain ONLY the CRLs. The staging step copies the dynamic leaf
	// CRL and the static intermediate/root CRLs explicitly (not a broad tree copy);
	// assert both copies are present and that no whole-repo publish has crept in.
	for _, need := range []string{
		"cp crl/developers.crl",              // dynamic leaf CRL (crlgen)
		"cp resources/codesigning/crl/*.crl", // static intermediate/root seeds
	} {
		if !strings.Contains(body, need) {
			t.Errorf("pages.yml: expected staging step to contain %q — the site must expose only the CRLs, not the repo", need)
		}
	}
	for _, forbidden := range []string{
		"cp -r .",   // copying the whole tree
		"cp -a .",   // ditto
		"path: .\n", // uploading the repo root as the Pages artifact
		"path: ./",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("pages.yml: found %q — must not publish the repository source, only crl/*.crl", forbidden)
		}
	}

	// Must use the Actions Pages build (upload-pages-artifact + deploy-pages), not
	// a branch source — the branch source would serve the whole repo.
	for _, need := range []string{
		"actions/upload-pages-artifact@",
		"actions/deploy-pages@",
	} {
		if !strings.Contains(body, need) {
			t.Errorf("pages.yml: missing %q (Actions Pages build required so only the artifact is served)", need)
		}
	}

	// Actions must be SHA-pinned (repo checklist).
	for _, line := range strings.Split(body, "\n") {
		l := strings.TrimSpace(line)
		l = strings.TrimPrefix(l, "- ")
		if strings.HasPrefix(l, "uses:") && !strings.Contains(l, "@") {
			t.Errorf("pages.yml: uses without a pinned ref: %q", l)
		}
	}
}
