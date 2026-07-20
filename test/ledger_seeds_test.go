package conformance

import (
	"path/filepath"
	"testing"

	"github.com/owncloud/developer-certificates/internal/appid"
	"github.com/owncloud/developer-certificates/internal/ledger"
)

// TestLedgerSeeds pins the invariants of the committed first-party reservation
// files (design §15, §19 Phase 5). The ledger/ directory holds two kinds of
// file that the issuer distinguishes by the reserved flag: hand-committed
// first-party *reservations* (reserved=true), and *live* issued-cert ledgers
// the bot writes as apps enrol (reserved=false, one or more certificates).
// Every file must be schema-valid with a canonical <appId>.json filename;
// only the reservations carry the stricter seed invariants (owncloud-owned,
// no certificates), so the FCFS check (enrollment spec §4 step 8) rejects any
// third-party attempt to claim them.
func TestLedgerSeeds(t *testing.T) {
	matches, err := filepath.Glob(repoPath("ledger", "*.json"))
	if err != nil {
		t.Fatalf("glob ledger/*.json: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("no ledger files found under ledger/")
	}

	sawCore := false
	for _, path := range matches {
		base := filepath.Base(path)
		l, err := ledger.Load(path)
		if err != nil {
			t.Errorf("%s: load: %v", base, err)
			continue
		}
		// Universal invariants — every ledger file, seed or live entry:
		// AppId must be strictly valid (canonical lowercase — no folding).
		if _, err := appid.ValidateStrict(l.AppID); err != nil {
			t.Errorf("%s: appId %q not strictly valid: %v", base, l.AppID, err)
		}
		// Filename must be the canonical <appId>.json.
		if want := ledger.FileName(l.AppID); base != want {
			t.Errorf("%s: filename does not match canonical appId (want %q)", base, want)
		}

		// Live issued-cert ledgers (reserved=false) are written by the bot and
		// legitimately carry github-origin owners and certificates; the seed
		// invariants below apply only to first-party reservations.
		if !l.Reserved {
			continue
		}

		// Seed invariants: reservations are owncloud-owned and hold no certs.
		if l.Owner.Origin != ledger.OriginOwnCloud {
			t.Errorf("%s: seed owner.origin must be %q, got %q", base, ledger.OriginOwnCloud, l.Owner.Origin)
		}
		if len(l.Certificates) != 0 {
			t.Errorf("%s: reservation must carry no certificates, got %d", base, len(l.Certificates))
		}
		if l.AppID == "core" {
			sawCore = true
		}
	}
	if !sawCore {
		t.Errorf("expected a reservation for the core identity (ledger/core.json)")
	}
}
