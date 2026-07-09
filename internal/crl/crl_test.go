package crl

import (
	"math/big"
	"testing"
	"time"

	"github.com/DeepDiver1975/developer-certificates/internal/ledger"
)

func ts(t time.Time) ledger.Timestamp { return ledger.Timestamp(t) }

// ledgerWith builds a ledger with the given certs for testing.
func ledgerWith(appID string, certs ...ledger.Certificate) *ledger.Ledger {
	return &ledger.Ledger{
		AppID:        appID,
		Owner:        ledger.Owner{Origin: ledger.OriginGitHub, Repo: "org/" + appID},
		Certificates: certs,
	}
}

func revokedCert(serial string, notBefore, revokedFrom time.Time) ledger.Certificate {
	rf := ts(revokedFrom)
	return ledger.Certificate{
		Serial: serial, Fingerprint: "sha256:x",
		NotBefore: ts(notBefore), NotAfter: ts(notBefore.Add(24 * time.Hour)),
		Status: ledger.StatusRevoked, RevokedFrom: &rf, Reason: "self-service",
	}
}

func activeCert(serial string, notBefore time.Time) ledger.Certificate {
	return ledger.Certificate{
		Serial: serial, Fingerprint: "sha256:y",
		NotBefore: ts(notBefore), NotAfter: ts(notBefore.Add(24 * time.Hour)),
		Status: ledger.StatusActive,
	}
}

func TestBuildOnlyRevoked(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	rf := now.Add(-48 * time.Hour)
	ls := []*ledger.Ledger{
		ledgerWith("app-a", activeCert("0x1", now), revokedCert("0x2", now, rf)),
		ledgerWith("app-b", revokedCert("0x3", now, rf)),
	}
	tmpl, err := Build(ls, now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(tmpl.RevokedCertificateEntries) != 2 {
		t.Fatalf("entries = %d, want 2 (only revoked)", len(tmpl.RevokedCertificateEntries))
	}
	// Entries sorted by serial: 0x2 (2) before 0x3 (3).
	if tmpl.RevokedCertificateEntries[0].SerialNumber.Cmp(big.NewInt(2)) != 0 {
		t.Errorf("first serial = %v, want 2", tmpl.RevokedCertificateEntries[0].SerialNumber)
	}
	if !tmpl.RevokedCertificateEntries[0].RevocationTime.Equal(rf.UTC()) {
		t.Errorf("revocationTime = %v, want %v", tmpl.RevokedCertificateEntries[0].RevocationTime, rf.UTC())
	}
	if !tmpl.NextUpdate.Equal(now.Add(7 * 24 * time.Hour)) {
		t.Errorf("nextUpdate = %v, want now+7d", tmpl.NextUpdate)
	}
	if !tmpl.ThisUpdate.Equal(now) {
		t.Errorf("thisUpdate = %v, want now", tmpl.ThisUpdate)
	}
	if tmpl.Number.Int64() != now.Unix() {
		t.Errorf("number = %d, want %d", tmpl.Number.Int64(), now.Unix())
	}
}

func TestBuildEmpty(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	tmpl, err := Build([]*ledger.Ledger{ledgerWith("app-a", activeCert("0x1", now))}, now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(tmpl.RevokedCertificateEntries) != 0 {
		t.Errorf("entries = %d, want 0 (valid empty CRL)", len(tmpl.RevokedCertificateEntries))
	}
	if tmpl.Number.Int64() != now.Unix() || !tmpl.NextUpdate.Equal(now.Add(7*24*time.Hour)) {
		t.Errorf("empty CRL still needs number/nextUpdate set: number=%d nextUpdate=%v", tmpl.Number.Int64(), tmpl.NextUpdate)
	}
}

func TestBuildDeterministicOrder(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	rf := now.Add(-time.Hour)
	// Same revoked serials, different input ledger order → identical entry order.
	a := Build2(t, []*ledger.Ledger{
		ledgerWith("app-a", revokedCert("0x9", now, rf)),
		ledgerWith("app-b", revokedCert("0x1", now, rf)),
	}, now)
	b := Build2(t, []*ledger.Ledger{
		ledgerWith("app-b", revokedCert("0x1", now, rf)),
		ledgerWith("app-a", revokedCert("0x9", now, rf)),
	}, now)
	if a[0].Cmp(b[0]) != 0 || a[1].Cmp(b[1]) != 0 {
		t.Errorf("entry order not deterministic: %v vs %v", a, b)
	}
	// Sorted ascending: 1 then 9.
	if a[0].Cmp(big.NewInt(1)) != 0 || a[1].Cmp(big.NewInt(9)) != 0 {
		t.Errorf("not sorted ascending by serial: %v", a)
	}
}

// Build2 is a helper returning just the serials for order assertions.
func Build2(t *testing.T, ls []*ledger.Ledger, now time.Time) []*big.Int {
	t.Helper()
	tmpl, err := Build(ls, now)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	out := make([]*big.Int, len(tmpl.RevokedCertificateEntries))
	for i, e := range tmpl.RevokedCertificateEntries {
		out[i] = e.SerialNumber
	}
	return out
}

func TestBuildBadSerial(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	bad := revokedCert("0xZZZ", now, now.Add(-time.Hour)) // ZZZ is not hex
	if _, err := Build([]*ledger.Ledger{ledgerWith("app-a", bad)}, now); err == nil {
		t.Error("expected error for unparseable serial, got nil")
	}
}
