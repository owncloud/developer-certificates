package conformance

import (
	"strings"
	"testing"

	"github.com/owncloud/developer-certificates/internal/challenge"
)

// TestChallengePathSingleSource guards the single source of truth for the
// nonce-challenge file path (design §5.3). The library constant the issuer bot
// posts to developers, the harness's own challengePath (used by forms_test.go),
// and the path documented in the developer guide must all be the same string —
// otherwise the bot would instruct developers to commit a file at a path the
// docs don't describe.
func TestChallengePathSingleSource(t *testing.T) {
	if challenge.FilePath != challengePath {
		t.Fatalf("challenge.FilePath (%q) != harness challengePath (%q)", challenge.FilePath, challengePath)
	}
	guide := string(mustRead(t, repoPath("docs", "developer-guide.md")))
	if !strings.Contains(guide, challenge.FilePath) {
		t.Errorf("developer-guide.md does not contain challenge path %q", challenge.FilePath)
	}
}
