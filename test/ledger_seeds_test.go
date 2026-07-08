package conformance

import (
	"path/filepath"
	"testing"

	"github.com/DeepDiver1975/developer-certificates/internal/appid"
	"github.com/DeepDiver1975/developer-certificates/internal/ledger"
)

// TestLedgerSeeds pins the invariants of the committed first-party reservation
// files (design §15, §19 Phase 5). Every ledger/*.json must be a schema-valid
// reservation whose filename matches its canonical appId, so the FCFS check
// (enrollment spec §4 step 8) rejects any third-party attempt to claim these.
func TestLedgerSeeds(t *testing.T) {
	matches, err := filepath.Glob(repoPath("ledger", "*.json"))
	if err != nil {
		t.Fatalf("glob ledger/*.json: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("no seed files found under ledger/")
	}

	sawCore := false
	for _, path := range matches {
		base := filepath.Base(path)
		l, err := ledger.Load(path)
		if err != nil {
			t.Errorf("%s: load: %v", base, err)
			continue
		}
		// AppId must be strictly valid (canonical lowercase — no folding).
		if _, err := appid.ValidateStrict(l.AppID); err != nil {
			t.Errorf("%s: appId %q not strictly valid: %v", base, l.AppID, err)
		}
		// Filename must be the canonical <appId>.json.
		if want := ledger.FileName(l.AppID); base != want {
			t.Errorf("%s: filename does not match canonical appId (want %q)", base, want)
		}
		// Seeds are reservations: reserved, owncloud-owned, and hold no certs.
		if !l.Reserved {
			t.Errorf("%s: seed must have reserved=true", base)
		}
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
