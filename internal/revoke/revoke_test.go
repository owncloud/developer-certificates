package revoke

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/owncloud/developer-certificates/internal/cms"
	cmsfake "github.com/owncloud/developer-certificates/internal/cms/fake"
	"github.com/owncloud/developer-certificates/internal/ghclient"
	ghfake "github.com/owncloud/developer-certificates/internal/ghclient/fake"
	"github.com/owncloud/developer-certificates/internal/ledger"
	"github.com/owncloud/developer-certificates/internal/signer"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

const (
	testAppID = "example-app"
	testIssue = 42
)

// makeCert builds a self-signed EC P-384 leaf with CN=cn and returns the parsed
// cert plus its DER. The revocation flow matches on CN (=appId) + fingerprint.
func makeCert(t *testing.T, cn string, notBefore time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func revocationBodyFor() string {
	return "### CMS revocation request (PEM)\n\n```\n-----BEGIN CMS-----\nMIIABC==\n-----END CMS-----\n```\n"
}

// harness wires the fakes with a CMS verifier that returns cert, plus a seeded
// ledger for appID (nil = no ledger file). Returns Deps, the gh fake, and the
// stored ledger SHA.
func harness(t *testing.T, cert *x509.Certificate, seed *ledger.Ledger, now time.Time) (Deps, *ghfake.Client) {
	t.Helper()
	gh := ghfake.New()
	if seed != nil {
		data, err := seed.Marshal()
		if err != nil {
			t.Fatalf("marshal seed ledger: %v", err)
		}
		gh.SetLedger(seed.AppID, data)
	}
	cv := cmsfake.New()
	if cert != nil {
		cv.Result = &cms.Result{SignerCert: cert, Content: []byte("revoke")}
	}
	return Deps{GH: gh, CMS: cv, Clock: fixedClock{t: now}}, gh
}

func newIssue(labels ...string) ghclient.Issue {
	return ghclient.Issue{
		Number: testIssue,
		Body:   revocationBodyFor(),
		Author: ghclient.Author{Login: "example-user", UserID: 12345},
		Labels: labels,
	}
}

// seededLedger builds an active-cert ledger for cert.
func seededLedger(cert *x509.Certificate, now time.Time) *ledger.Ledger {
	return &ledger.Ledger{
		AppID:     testAppID,
		Owner:     ledger.Owner{Origin: ledger.OriginGitHub, Repo: "example-org/example-app"},
		ClaimedAt: ledger.Timestamp(now.Add(-48 * time.Hour)),
		Certificates: []ledger.Certificate{{
			Serial:      signer.FormatSerial(cert.SerialNumber),
			Fingerprint: signer.Fingerprint(cert.Raw),
			NotBefore:   ledger.Timestamp(cert.NotBefore),
			NotAfter:    ledger.Timestamp(cert.NotAfter),
			Requester:   ledger.Requester{Origin: ledger.OriginGitHub, Login: "example-user", UserID: 12345},
			IssueRef:    "#1",
			Status:      ledger.StatusActive,
		}},
	}
}

func TestProcessHappyPath(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	cert := makeCert(t, testAppID, now.Add(-24*time.Hour))
	d, gh := harness(t, cert, seededLedger(cert, now), now)

	if err := Process(context.Background(), d, newIssue()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !hasLabel(gh.LabelsAdded[testIssue], LabelRevoked) {
		t.Errorf("labels = %v, want %s", gh.LabelsAdded[testIssue], LabelRevoked)
	}
	if !gh.Closed[testIssue] {
		t.Error("issue not closed after revocation")
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
	if c.RevokedFrom == nil || time.Time(*c.RevokedFrom) != cert.NotBefore {
		t.Errorf("revokedFrom = %v, want notBefore %v", c.RevokedFrom, cert.NotBefore)
	}
	if c.Reason != "self-service" {
		t.Errorf("reason = %q, want self-service", c.Reason)
	}
}

func TestProcessAlreadyRevoked(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	cert := makeCert(t, testAppID, now.Add(-24*time.Hour))
	seed := seededLedger(cert, now)
	rf := seed.Certificates[0].NotBefore
	seed.Certificates[0].Status = ledger.StatusRevoked
	seed.Certificates[0].RevokedFrom = &rf
	seed.Certificates[0].Reason = "self-service"
	d, gh := harness(t, cert, seed, now)

	// Capture ledger SHA before Process to verify idempotent no-op
	_, shaBefore, err := gh.GetLedger(context.Background(), testAppID)
	if err != nil {
		t.Fatalf("GetLedger before Process: %v", err)
	}

	if err := Process(context.Background(), d, newIssue()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !hasLabel(gh.LabelsAdded[testIssue], LabelRevoked) {
		t.Errorf("labels = %v, want %s", gh.LabelsAdded[testIssue], LabelRevoked)
	}
	if !gh.Closed[testIssue] {
		t.Error("already-revoked issue should be closed")
	}

	// Verify ledger was not rewritten (idempotent no-op)
	_, shaAfter, err := gh.GetLedger(context.Background(), testAppID)
	if err != nil {
		t.Fatalf("GetLedger after Process: %v", err)
	}
	if shaBefore != shaAfter {
		t.Errorf("ledger was rewritten on an already-revoked cert (want idempotent no-op): SHA before=%s, after=%s", shaBefore, shaAfter)
	}
}

func TestProcessNoMatchingCert(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	cert := makeCert(t, testAppID, now.Add(-24*time.Hour))
	// Seed a ledger for the appId but with a different cert (no fingerprint match).
	other := makeCert(t, testAppID, now.Add(-72*time.Hour))
	d, gh := harness(t, cert, seededLedger(other, now), now)

	if err := Process(context.Background(), d, newIssue()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !hasLabel(gh.LabelsAdded[testIssue], LabelInvalid) {
		t.Errorf("labels = %v, want %s", gh.LabelsAdded[testIssue], LabelInvalid)
	}
	if gh.Closed[testIssue] {
		t.Error("invalid issue must stay open")
	}
}

func TestProcessAbsentLedger(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	cert := makeCert(t, testAppID, now.Add(-24*time.Hour))
	d, gh := harness(t, cert, nil, now) // no ledger file

	if err := Process(context.Background(), d, newIssue()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !hasLabel(gh.LabelsAdded[testIssue], LabelInvalid) {
		t.Errorf("labels = %v, want %s", gh.LabelsAdded[testIssue], LabelInvalid)
	}
}

func TestProcessInvalidCMS(t *testing.T) {
	now := time.Now().UTC()
	d, gh := harness(t, nil, nil, now)
	d.CMS.(*cmsfake.Verifier).Err = cms.ErrInvalidCMS

	if err := Process(context.Background(), d, newIssue()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !hasLabel(gh.LabelsAdded[testIssue], LabelInvalid) {
		t.Errorf("labels = %v, want %s", gh.LabelsAdded[testIssue], LabelInvalid)
	}
}

func TestProcessMalformedForm(t *testing.T) {
	now := time.Now().UTC()
	d, gh := harness(t, nil, nil, now)
	iss := newIssue()
	iss.Body = "no cms block here"

	if err := Process(context.Background(), d, iss); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !hasLabel(gh.LabelsAdded[testIssue], LabelInvalid) {
		t.Errorf("labels = %v, want %s", gh.LabelsAdded[testIssue], LabelInvalid)
	}
}

func TestProcessInfraErrorPropagates(t *testing.T) {
	now := time.Now().UTC()
	d, _ := harness(t, nil, nil, now)
	d.CMS.(*cmsfake.Verifier).Err = errors.New("openssl exploded")

	if err := Process(context.Background(), d, newIssue()); err == nil {
		t.Error("expected infrastructure error to propagate, got nil")
	}
}

func TestProcessIdempotentRevoked(t *testing.T) {
	now := time.Now().UTC()
	d, gh := harness(t, nil, nil, now)
	iss := newIssue(LabelRevoked)

	if err := Process(context.Background(), d, iss); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(gh.PostedComments[testIssue]) != 0 || len(gh.LabelsAdded[testIssue]) != 0 {
		t.Error("already-revoked issue was not a no-op")
	}
}

func TestProcessConflictRetry(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	cert := makeCert(t, testAppID, now.Add(-24*time.Hour))
	d, gh := harness(t, cert, seededLedger(cert, now), now)

	// Inject a one-shot conflict to exercise the retry loop.
	gh.FailNextPutWithConflict = true

	if err := Process(context.Background(), d, newIssue()); err != nil {
		t.Fatalf("Process with conflict retry: %v", err)
	}

	// Verify the revocation persisted through the retry.
	out, _, err := gh.GetLedger(context.Background(), testAppID)
	if err != nil {
		t.Fatalf("GetLedger: %v", err)
	}
	l, err := ledger.Parse(out)
	if err != nil {
		t.Fatalf("parse written ledger: %v", err)
	}
	c := l.Certificates[0]
	if c.Status != ledger.StatusRevoked {
		t.Errorf("status = %q, want revoked (after retry)", c.Status)
	}
	if c.RevokedFrom == nil || time.Time(*c.RevokedFrom) != cert.NotBefore {
		t.Errorf("revokedFrom = %v, want notBefore %v", c.RevokedFrom, cert.NotBefore)
	}
}
