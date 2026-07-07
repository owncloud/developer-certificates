package ledger

import (
	"strings"
	"testing"
	"time"
)

// canonicalActive is a ledger in the exact canonical serialization Marshal
// produces: 2-space indent, struct field order, trailing newline. It mirrors
// the design §6 example (adapted to canonical timestamps).
const canonicalActive = `{
  "appId": "example-app",
  "owner": {
    "origin": "github",
    "repo": "example-org/example-app"
  },
  "claimedAt": "2026-07-06T10:00:00Z",
  "certificates": [
    {
      "serial": "0x1a2b",
      "fingerprint": "sha256:abcd",
      "notBefore": "2026-07-06T10:00:00Z",
      "notAfter": "2028-07-05T10:00:00Z",
      "requester": {
        "origin": "github",
        "login": "example-user",
        "userId": 12345
      },
      "issueRef": "example-org/intake#42",
      "status": "active"
    }
  ]
}
`

func TestRoundTripByteIdentical(t *testing.T) {
	l, err := Parse([]byte(canonicalActive))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	out, err := l.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(out) != canonicalActive {
		t.Errorf("round-trip not byte-identical:\n--- got ---\n%s\n--- want ---\n%s", out, canonicalActive)
	}
}

// canonicalRevoked pins the serialization of a revoked entry with its
// revocation metadata (enrollment spec §5).
const canonicalRevoked = `{
  "appId": "example-app",
  "owner": {
    "origin": "github",
    "repo": "example-org/example-app"
  },
  "claimedAt": "2026-07-06T10:00:00Z",
  "certificates": [
    {
      "serial": "0x1a2b",
      "fingerprint": "sha256:abcd",
      "notBefore": "2026-07-06T10:00:00Z",
      "notAfter": "2028-07-05T10:00:00Z",
      "requester": {
        "origin": "github",
        "login": "example-user",
        "userId": 12345
      },
      "issueRef": "example-org/intake#42",
      "status": "revoked",
      "revokedFrom": "2026-08-01T00:00:00Z",
      "reason": "self-service",
      "actor": "example-user"
    }
  ]
}
`

func TestRoundTripRevoked(t *testing.T) {
	l, err := Parse([]byte(canonicalRevoked))
	if err != nil {
		t.Fatalf("Parse revoked: %v", err)
	}
	if l.Certificates[0].RevokedFrom == nil {
		t.Fatalf("revokedFrom did not unmarshal")
	}
	out, err := l.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(out) != canonicalRevoked {
		t.Errorf("revoked round-trip not byte-identical:\n--- got ---\n%s\n--- want ---\n%s", out, canonicalRevoked)
	}
}

// TestRevokedRequiresRevokedFrom asserts a revoked cert without a revokedFrom
// date is rejected structurally.
func TestRevokedRequiresRevokedFrom(t *testing.T) {
	const bad = `{
  "appId": "example-app",
  "owner": { "origin": "github", "repo": "example-org/example-app" },
  "claimedAt": "2026-07-06T10:00:00Z",
  "certificates": [
    { "serial": "0x1", "fingerprint": "sha256:x", "notBefore": "2026-07-06T10:00:00Z",
      "notAfter": "2028-07-05T10:00:00Z",
      "requester": { "origin": "github", "login": "u", "userId": 1 },
      "issueRef": "r#1", "status": "revoked" }
  ]
}`
	if _, err := Parse([]byte(bad)); err == nil {
		t.Errorf("expected error for revoked cert without revokedFrom")
	}
}

func TestParseRejectsUnknownStatus(t *testing.T) {
	const bad = `{
  "appId": "example-app",
  "owner": { "origin": "github", "repo": "example-org/example-app" },
  "claimedAt": "2026-07-06T10:00:00Z",
  "certificates": [
    { "serial": "0x1", "fingerprint": "sha256:x", "notBefore": "2026-07-06T10:00:00Z",
      "notAfter": "2028-07-05T10:00:00Z",
      "requester": { "origin": "github", "login": "u", "userId": 1 },
      "issueRef": "r#1", "status": "pending" }
  ]
}`
	if _, err := Parse([]byte(bad)); err == nil {
		t.Errorf("expected error for unknown status")
	}
}

func TestParseRejectsInvalidAppID(t *testing.T) {
	const bad = `{
  "appId": "Example-App",
  "owner": { "origin": "github", "repo": "example-org/example-app" },
  "claimedAt": "2026-07-06T10:00:00Z",
  "certificates": []
}`
	if _, err := Parse([]byte(bad)); err == nil {
		t.Errorf("expected error for non-canonical appId")
	}
}

// TestTimestampAlwaysUTCZ ensures a timestamp given with an offset is
// normalized to the canonical "...Z" UTC form on marshal.
func TestTimestampAlwaysUTCZ(t *testing.T) {
	loc := time.FixedZone("PST", -8*3600)
	ts := Timestamp(time.Date(2026, 7, 6, 2, 0, 0, 0, loc)) // 10:00Z
	out, err := ts.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if got := string(out); got != `"2026-07-06T10:00:00Z"` {
		t.Errorf("Timestamp marshaled as %s, want canonical UTC Z form", got)
	}
}

func TestFileName(t *testing.T) {
	if got := FileName("example-app"); got != "example-app.json" {
		t.Errorf("FileName = %q, want example-app.json", got)
	}
}

func TestDecide(t *testing.T) {
	owned := &Ledger{Owner: Owner{Origin: OriginGitHub, Repo: "example-org/example-app"}}
	reserved := &Ledger{Reserved: true, Owner: Owner{Origin: OriginOwnCloud, Repo: "owncloud/core"}}

	cases := []struct {
		name       string
		existing   *Ledger
		targetRepo string
		want       Decision
	}{
		{"absent -> new claim", nil, "example-org/example-app", DecisionNewClaim},
		{"reserved -> rejected", reserved, "owncloud/core", DecisionRejectedReserved},
		{"reserved rejects even on repo match", reserved, "owncloud/core", DecisionRejectedReserved},
		{"same repo -> allowed", owned, "example-org/example-app", DecisionAllowed},
		{"different repo -> mismatch", owned, "someone-else/example-app", DecisionRejectedMismatch},
	}
	for _, c := range cases {
		if got := Decide(c.existing, c.targetRepo); got != c.want {
			t.Errorf("%s: Decide = %d, want %d", c.name, got, c.want)
		}
	}
}

// TestMarshalNoHTMLEscape confirms repo slugs with "/" are not escaped to
// "/" in the output.
func TestMarshalNoHTMLEscape(t *testing.T) {
	l := &Ledger{
		AppID:        "example-app",
		Owner:        Owner{Origin: OriginGitHub, Repo: "example-org/example-app"},
		Certificates: []Certificate{},
	}
	out, err := l.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(out), "example-org/example-app") {
		t.Errorf("repo slug was escaped; got:\n%s", out)
	}
}
