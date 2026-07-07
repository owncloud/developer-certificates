package conformance

import (
	"os"
	"testing"
)

// The six design/spec documents that form the archived design record
// (design "Companion specs" list). They are copied verbatim into docs/specs/
// and must all be present.
var specFiles = []string{
	"2026-07-06-owncloud-code-signing-pki-design.md",
	"2026-07-06-spec-enrollment-bot.md",
	"2026-07-06-spec-attestation-and-crl-workflows.md",
	"2026-07-06-spec-core-verifier.md",
	"2026-07-06-spec-go-signing-tool.md",
	"2026-07-06-spec-developer-documentation.md",
}

func TestSpecsPresent(t *testing.T) {
	for _, name := range specFiles {
		path := repoPath("docs", "specs", name)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("expected spec docs/specs/%s to exist: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("spec docs/specs/%s is empty", name)
		}
	}
}
