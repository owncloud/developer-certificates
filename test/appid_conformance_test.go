package conformance

import (
	"strings"
	"testing"

	"github.com/DeepDiver1975/developer-certificates/internal/appid"
)

// TestAppIDPatternSingleSource guards the single source of truth for the appId
// grammar (design §4.1). The library constant, the harness's own appIdRegex
// (used by forms_test.go), and the string embedded in the issue form and
// developer guide must all be the same — otherwise the ledger/CN comparison and
// the developer-facing docs could drift apart.
func TestAppIDPatternSingleSource(t *testing.T) {
	if appid.Pattern != appIdRegex {
		t.Fatalf("appid.Pattern (%q) != harness appIdRegex (%q)", appid.Pattern, appIdRegex)
	}

	surfaces := []string{
		repoPath(".github", "ISSUE_TEMPLATE", "certificate-request.yml"),
		repoPath("docs", "developer-guide.md"),
	}
	for _, path := range surfaces {
		if !strings.Contains(string(mustRead(t, path)), appid.Pattern) {
			t.Errorf("%s: does not contain appId pattern %q", path, appid.Pattern)
		}
	}
}
