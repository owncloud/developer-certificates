package revoke

import (
	"context"
	"testing"
	"time"

	ghfake "github.com/DeepDiver1975/developer-certificates/internal/ghclient/fake"
	"github.com/DeepDiver1975/developer-certificates/internal/ledger"
)

// privHarness seeds a ledger for cert and returns privileged deps + the gh fake.
func privHarness(t *testing.T, seed *ledger.Ledger, now time.Time) (PrivilegedDeps, *ghfake.Client) {
	t.Helper()
	gh := ghfake.New()
	if seed != nil {
		data, err := seed.Marshal()
		if err != nil {
			t.Fatalf("marshal seed: %v", err)
		}
		gh.SetLedger(seed.AppID, data)
	}
	return PrivilegedDeps{GH: gh, Clock: fixedClock{t: now}}, gh
}

func serialOf(l *ledger.Ledger) string { return l.Certificates[0].Serial }

func TestPrivilegedHappyPath(t *testing.T) {
	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	cert := makeCert(t, testAppID, now.Add(-24*time.Hour))
	seed := seededLedger(cert, now)
	d, gh := privHarness(t, seed, now)

	req := PrivilegedRequest{
		AppID: testAppID, Serial: serialOf(seed),
		Reason: "abuse report VDP-123", Actor: "org-admin",
	}
	if err := PrivilegedProcess(context.Background(), d, req); err != nil {
		t.Fatalf("PrivilegedProcess: %v", err)
	}
	out, _, _ := gh.GetLedger(context.Background(), testAppID)
	l, err := ledger.Parse(out)
	if err != nil {
		t.Fatalf("written ledger invalid: %v", err)
	}
	c := l.Certificates[0]
	if c.Status != ledger.StatusRevoked {
		t.Errorf("status = %q, want revoked", c.Status)
	}
	if c.Reason != "abuse report VDP-123" {
		t.Errorf("reason = %q, want operator reason", c.Reason)
	}
	if c.Actor != "org-admin" {
		t.Errorf("actor = %q, want org-admin", c.Actor)
	}
	// revokedFrom defaults to the cert's NotBefore when not supplied.
	if c.RevokedFrom == nil || time.Time(*c.RevokedFrom) != cert.NotBefore {
		t.Errorf("revokedFrom = %v, want notBefore %v", c.RevokedFrom, cert.NotBefore)
	}
	// No issue interaction on the privileged path.
	if len(gh.PostedComments) != 0 || len(gh.LabelsAdded) != 0 {
		t.Error("privileged path must not touch issues")
	}
}

func TestPrivilegedSuppliedRevokedFrom(t *testing.T) {
	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	cert := makeCert(t, testAppID, now.Add(-24*time.Hour))
	seed := seededLedger(cert, now)
	d, gh := privHarness(t, seed, now)

	rf := cert.NotBefore.Add(6 * time.Hour) // >= notBefore
	req := PrivilegedRequest{
		AppID: testAppID, Serial: serialOf(seed),
		Reason: "key compromise", RevokedFrom: &rf, Actor: "org-admin",
	}
	if err := PrivilegedProcess(context.Background(), d, req); err != nil {
		t.Fatalf("PrivilegedProcess: %v", err)
	}
	out, _, _ := gh.GetLedger(context.Background(), testAppID)
	l, _ := ledger.Parse(out)
	if got := time.Time(*l.Certificates[0].RevokedFrom); !got.Equal(rf.UTC()) {
		t.Errorf("revokedFrom = %v, want supplied %v", got, rf.UTC())
	}
}

func TestPrivilegedRevokedFromBeforeNotBefore(t *testing.T) {
	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	cert := makeCert(t, testAppID, now.Add(-24*time.Hour))
	seed := seededLedger(cert, now)
	d, gh := privHarness(t, seed, now)

	_, shaBefore, _ := gh.GetLedger(context.Background(), testAppID)
	rf := cert.NotBefore.Add(-time.Hour) // < notBefore → invalid
	req := PrivilegedRequest{
		AppID: testAppID, Serial: serialOf(seed),
		Reason: "typo", RevokedFrom: &rf, Actor: "org-admin",
	}
	if err := PrivilegedProcess(context.Background(), d, req); err == nil {
		t.Error("expected error for revokedFrom < notBefore, got nil")
	}
	_, shaAfter, _ := gh.GetLedger(context.Background(), testAppID)
	if shaBefore != shaAfter {
		t.Error("ledger must be unchanged when revokedFrom is invalid")
	}
}

func TestPrivilegedOverwritesAlreadyRevoked(t *testing.T) {
	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	cert := makeCert(t, testAppID, now.Add(-24*time.Hour))
	seed := seededLedger(cert, now)
	// Pre-revoke with old values.
	oldRF := seed.Certificates[0].NotBefore
	seed.Certificates[0].Status = ledger.StatusRevoked
	seed.Certificates[0].RevokedFrom = &oldRF
	seed.Certificates[0].Reason = "self-service"
	d, gh := privHarness(t, seed, now)

	newRF := cert.NotBefore.Add(2 * time.Hour)
	req := PrivilegedRequest{
		AppID: testAppID, Serial: serialOf(seed),
		Reason: "authoritative correction", RevokedFrom: &newRF, Actor: "org-admin",
	}
	if err := PrivilegedProcess(context.Background(), d, req); err != nil {
		t.Fatalf("PrivilegedProcess: %v", err)
	}
	out, _, _ := gh.GetLedger(context.Background(), testAppID)
	l, _ := ledger.Parse(out)
	c := l.Certificates[0]
	if c.Reason != "authoritative correction" || c.Actor != "org-admin" {
		t.Errorf("overwrite failed: reason=%q actor=%q", c.Reason, c.Actor)
	}
	if got := time.Time(*c.RevokedFrom); !got.Equal(newRF.UTC()) {
		t.Errorf("revokedFrom = %v, want overwritten %v", got, newRF.UTC())
	}
}

func TestPrivilegedSerialNotFound(t *testing.T) {
	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	cert := makeCert(t, testAppID, now.Add(-24*time.Hour))
	seed := seededLedger(cert, now)
	d, gh := privHarness(t, seed, now)

	_, shaBefore, _ := gh.GetLedger(context.Background(), testAppID)
	req := PrivilegedRequest{
		AppID: testAppID, Serial: "0xdeadbeef", Reason: "x", Actor: "org-admin",
	}
	if err := PrivilegedProcess(context.Background(), d, req); err == nil {
		t.Error("expected error for unknown serial, got nil")
	}
	_, shaAfter, _ := gh.GetLedger(context.Background(), testAppID)
	if shaBefore != shaAfter {
		t.Error("ledger must be unchanged when serial not found")
	}
}

func TestPrivilegedAbsentLedger(t *testing.T) {
	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	d, _ := privHarness(t, nil, now)
	req := PrivilegedRequest{AppID: testAppID, Serial: "0x1", Reason: "x", Actor: "a"}
	if err := PrivilegedProcess(context.Background(), d, req); err == nil {
		t.Error("expected error for absent ledger, got nil")
	}
}

func TestPrivilegedValidation(t *testing.T) {
	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	cert := makeCert(t, testAppID, now.Add(-24*time.Hour))
	seed := seededLedger(cert, now)
	base := PrivilegedRequest{AppID: testAppID, Serial: serialOf(seed), Reason: "r", Actor: "a"}

	cases := map[string]func(PrivilegedRequest) PrivilegedRequest{
		"blank appId":  func(r PrivilegedRequest) PrivilegedRequest { r.AppID = ""; return r },
		"bad appId":    func(r PrivilegedRequest) PrivilegedRequest { r.AppID = "Not_Valid!"; return r },
		"blank serial": func(r PrivilegedRequest) PrivilegedRequest { r.Serial = ""; return r },
		"blank reason": func(r PrivilegedRequest) PrivilegedRequest { r.Reason = ""; return r },
		"blank actor":  func(r PrivilegedRequest) PrivilegedRequest { r.Actor = ""; return r },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			d, _ := privHarness(t, seed, now)
			if err := PrivilegedProcess(context.Background(), d, mut(base)); err == nil {
				t.Errorf("%s: expected validation error, got nil", name)
			}
		})
	}
}

func TestPrivilegedConflictRetry(t *testing.T) {
	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	cert := makeCert(t, testAppID, now.Add(-24*time.Hour))
	seed := seededLedger(cert, now)
	d, gh := privHarness(t, seed, now)
	gh.FailNextPutWithConflict = true

	req := PrivilegedRequest{AppID: testAppID, Serial: serialOf(seed), Reason: "r", Actor: "a"}
	if err := PrivilegedProcess(context.Background(), d, req); err != nil {
		t.Fatalf("PrivilegedProcess with conflict: %v", err)
	}
	out, _, _ := gh.GetLedger(context.Background(), testAppID)
	l, _ := ledger.Parse(out)
	if l.Certificates[0].Status != ledger.StatusRevoked {
		t.Error("cert not revoked after conflict-retry")
	}
}
