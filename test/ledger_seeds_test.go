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
// only the reservations carry the stricter seed invariant (owncloud-owned), so
// the FCFS check (enrollment spec §4 step 8) rejects any third-party attempt to
// claim them.
//
// A reservation MAY carry certificates: first-party leaves (core + core-bundled
// apps) are minted through the privileged path, which bypasses the FCFS check
// entirely, so recording the issued cert in the reservation ledger does not
// weaken the anti-squatting guard — ledger.Decide still returns
// DecisionRejectedReserved for any self-service attempt. The reservation's
// owncloud ownership is the load-bearing invariant, not an empty cert list.
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
		// invariant below applies only to first-party reservations.
		if !l.Reserved {
			continue
		}

		// Seed invariant: reservations are owncloud-owned. They MAY carry
		// certificates issued via the privileged path (see the doc comment);
		// the ownership origin is what the FCFS reservation guarantee rests on.
		if l.Owner.Origin != ledger.OriginOwnCloud {
			t.Errorf("%s: seed owner.origin must be %q, got %q", base, ledger.OriginOwnCloud, l.Owner.Origin)
		}
		if l.AppID == "core" {
			sawCore = true
		}
	}
	if !sawCore {
		t.Errorf("expected a reservation for the core identity (ledger/core.json)")
	}
}
