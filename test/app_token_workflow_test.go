package conformance

import (
	"strings"
	"testing"
)

// TestBotWorkflowsUseAppToken pins the write-path invariant introduced with the
// App-bypass approach (design §6): every bot workflow that writes to protected
// `main` must mint a GitHub App token via create-github-app-token and run under
// it (GITHUB_TOKEN = steps.apptoken.outputs.token), NOT the default
// secrets.GITHUB_TOKEN — only the codesign-bot App is a ruleset bypass actor, so
// the default token cannot write. A regression to secrets.GITHUB_TOKEN would
// silently break all bot writes, so guard it here across all four workflows.
func TestBotWorkflowsUseAppToken(t *testing.T) {
	for _, wf := range []string{
		"issuer.yml",
		"revocation.yml",
		"privileged-revocation.yml",
		"crl.yml",
	} {
		t.Run(wf, func(t *testing.T) {
			body := string(mustRead(t, repoPath(".github", "workflows", wf)))

			if !strings.Contains(body, "uses: actions/create-github-app-token@") {
				t.Errorf("%s: missing create-github-app-token step (App token required to write past the ruleset, design §6)", wf)
			}
			if !strings.Contains(body, "GITHUB_TOKEN: ${{ steps.apptoken.outputs.token }}") {
				t.Errorf("%s: run step must use the minted App token (GITHUB_TOKEN: ${{ steps.apptoken.outputs.token }})", wf)
			}
			if strings.Contains(body, "GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}") {
				t.Errorf("%s: still passes the default secrets.GITHUB_TOKEN — it is not a ruleset bypass actor and cannot write to main", wf)
			}
		})
	}
}
