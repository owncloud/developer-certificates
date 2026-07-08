package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/DeepDiver1975/developer-certificates/internal/challenge"
	"github.com/DeepDiver1975/developer-certificates/internal/ghclient"
	"github.com/DeepDiver1975/developer-certificates/internal/ghclient/fake"
	"github.com/DeepDiver1975/developer-certificates/internal/ledger"
	"github.com/DeepDiver1975/developer-certificates/internal/signer/local"
)

// fixedClock is a deterministic Clock.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

const (
	testRepo    = "example-org/example-app"
	testAppID   = "example-app"
	testInfoXML = `<?xml version="1.0"?><info><id>example-app</id></info>`
)

// makeCSR builds a valid EC P-384 CSR with the given CN and returns its PEM.
func makeCSR(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// issueBody renders a certificate-request issue body the way GitHub does for
// the form fields (### heading sections).
func issueBody(csrPEM, repo string) string {
	return "### Certificate Signing Request (PEM)\n\n```\n" + csrPEM + "\n```\n\n" +
		"### App repository (owner/name)\n\n" + repo + "\n"
}

// harness wires the fake GitHub + local signer + fixed clock + deterministic
// rand, and returns the Deps plus the fake for assertions.
func harness(t *testing.T, now time.Time) (Deps, *fake.Client) {
	t.Helper()
	s, err := local.New(rand.Reader, now)
	if err != nil {
		t.Fatalf("local signer: %v", err)
	}
	gh := fake.New()
	d := Deps{
		GH:     gh,
		Signer: s,
		Clock:  fixedClock{t: now},
		Rand:   rand.Reader,
	}
	return d, gh
}

func newIssue(csrPEM, repo string, labels ...string) ghclient.Issue {
	return ghclient.Issue{
		Number: 42,
		Body:   issueBody(csrPEM, repo),
		Author: ghclient.Author{Login: "example-user", UserID: 12345},
		Labels: labels,
	}
}

func lastComment(t *testing.T, gh *fake.Client, issue int) string {
	t.Helper()
	c := gh.PostedComments[issue]
	if len(c) == 0 {
		t.Fatalf("no comments posted on issue %d", issue)
	}
	return c[len(c)-1]
}

// runToChallenge drives an issue up to and past the challenge-posting step,
// then satisfies the challenge, returning the fake ready for the issuance poll.
func satisfyChallenge(t *testing.T, d Deps, gh *fake.Client, iss ghclient.Issue) {
	t.Helper()
	// First poll: posts the challenge and labels awaiting-challenge.
	if err := Process(context.Background(), d, iss); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	comment := lastComment(t, gh, iss.Number)
	nonce, ok := challenge.ParseNonce(comment)
	if !ok {
		t.Fatal("challenge comment has no nonce marker")
	}
	// Record the bot comment so priorChallenge recovers it next poll.
	gh.OwnCommentsByIssue[iss.Number] = []ghclient.Comment{{Body: comment, CreatedAt: d.Clock.Now()}}
	// Developer commits the nonce.
	gh.SetFile(testRepo, challenge.FilePath, []byte(nonce+"\n"))
}

func TestProcessInvalidForm(t *testing.T) {
	d, gh := harness(t, time.Now())
	iss := ghclient.Issue{Number: 1, Body: "no csr here", Author: ghclient.Author{Login: "u"}}
	if err := Process(context.Background(), d, iss); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !contains(gh.LabelsAdded[1], LabelInvalid) {
		t.Errorf("labels = %v, want %s", gh.LabelsAdded[1], LabelInvalid)
	}
}

func TestProcessBadCSRKey(t *testing.T) {
	d, gh := harness(t, time.Now())
	// P-256 key is rejected by internal/csr.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: testAppID}}, key)
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	iss := newIssue(csrPEM, testRepo)
	if err := Process(context.Background(), d, iss); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !contains(gh.LabelsAdded[42], LabelInvalid) {
		t.Errorf("labels = %v, want %s", gh.LabelsAdded[42], LabelInvalid)
	}
}

func TestProcessInfoXMLMismatch(t *testing.T) {
	d, gh := harness(t, time.Now())
	gh.SetFile(testRepo, "appinfo/info.xml", []byte(`<info><id>other-app</id></info>`))
	iss := newIssue(makeCSR(t, testAppID), testRepo)
	if err := Process(context.Background(), d, iss); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !contains(gh.LabelsAdded[42], LabelNeedsChanges) {
		t.Errorf("labels = %v, want %s", gh.LabelsAdded[42], LabelNeedsChanges)
	}
}

func TestProcessMissingInfoXML(t *testing.T) {
	d, gh := harness(t, time.Now())
	iss := newIssue(makeCSR(t, testAppID), testRepo) // no info.xml set
	if err := Process(context.Background(), d, iss); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !contains(gh.LabelsAdded[42], LabelNeedsChanges) {
		t.Errorf("labels = %v, want %s", gh.LabelsAdded[42], LabelNeedsChanges)
	}
}

func TestProcessPostsChallenge(t *testing.T) {
	d, gh := harness(t, time.Now())
	gh.SetFile(testRepo, "appinfo/info.xml", []byte(testInfoXML))
	iss := newIssue(makeCSR(t, testAppID), testRepo)
	if err := Process(context.Background(), d, iss); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !contains(gh.LabelsAdded[42], LabelAwaitingChallenge) {
		t.Errorf("labels = %v, want %s", gh.LabelsAdded[42], LabelAwaitingChallenge)
	}
	if _, ok := challenge.ParseNonce(lastComment(t, gh, 42)); !ok {
		t.Error("challenge comment missing nonce marker")
	}
}

func TestProcessChallengeExpired(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	d, gh := harness(t, now)
	gh.SetFile(testRepo, "appinfo/info.xml", []byte(testInfoXML))
	iss := newIssue(makeCSR(t, testAppID), testRepo, LabelAwaitingChallenge)
	// A prior bot comment posted 73h ago.
	nonce, _ := challenge.Generate(rand.Reader)
	gh.OwnCommentsByIssue[42] = []ghclient.Comment{{Body: challenge.CommentBody(nonce), CreatedAt: now.Add(-73 * time.Hour)}}
	if err := Process(context.Background(), d, iss); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !contains(gh.LabelsAdded[42], LabelExpired) {
		t.Errorf("labels = %v, want %s", gh.LabelsAdded[42], LabelExpired)
	}
}

func TestProcessRejectedReserved(t *testing.T) {
	now := time.Now()
	d, gh := harness(t, now)
	gh.SetFile(testRepo, "appinfo/info.xml", []byte(testInfoXML))
	// Seed a reserved ledger entry for the appId.
	reserved := &ledger.Ledger{
		AppID:     testAppID,
		Owner:     ledger.Owner{Origin: ledger.OriginOwnCloud, Repo: "owncloud/core"},
		ClaimedAt: ledger.Timestamp(now),
		Reserved:  true,
	}
	data, _ := reserved.Marshal()
	gh.SetLedger(testAppID, data)

	iss := newIssue(makeCSR(t, testAppID), testRepo)
	satisfyChallenge(t, d, gh, iss)
	iss.Labels = []string{LabelAwaitingChallenge}
	if err := Process(context.Background(), d, iss); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !contains(gh.LabelsAdded[42], LabelRejected) {
		t.Errorf("labels = %v, want %s", gh.LabelsAdded[42], LabelRejected)
	}
}

func TestProcessMismatchOwner(t *testing.T) {
	now := time.Now()
	d, gh := harness(t, now)
	gh.SetFile(testRepo, "appinfo/info.xml", []byte(testInfoXML))
	other := &ledger.Ledger{
		AppID:     testAppID,
		Owner:     ledger.Owner{Origin: ledger.OriginGitHub, Repo: "someone-else/example-app"},
		ClaimedAt: ledger.Timestamp(now),
	}
	data, _ := other.Marshal()
	gh.SetLedger(testAppID, data)

	iss := newIssue(makeCSR(t, testAppID), testRepo)
	satisfyChallenge(t, d, gh, iss)
	iss.Labels = []string{LabelAwaitingChallenge}
	if err := Process(context.Background(), d, iss); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !contains(gh.LabelsAdded[42], LabelRejected) {
		t.Errorf("labels = %v, want %s", gh.LabelsAdded[42], LabelRejected)
	}
}

// TestProcessIssuesNewClaim is the happy path: no prior ledger, challenge
// satisfied, a leaf is issued, the ledger is created, and the issue closes.
func TestProcessIssuesNewClaim(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	d, gh := harness(t, now)
	gh.SetFile(testRepo, "appinfo/info.xml", []byte(testInfoXML))

	iss := newIssue(makeCSR(t, testAppID), testRepo)
	satisfyChallenge(t, d, gh, iss)
	iss.Labels = []string{LabelAwaitingChallenge}
	if err := Process(context.Background(), d, iss); err != nil {
		t.Fatalf("Process: %v", err)
	}

	if !contains(gh.LabelsAdded[42], LabelIssued) {
		t.Fatalf("labels = %v, want %s", gh.LabelsAdded[42], LabelIssued)
	}
	if !gh.Closed[42] {
		t.Error("issue not closed after issuance")
	}

	// A ledger entry now exists, is schema-valid, and records the requester.
	data, _, err := gh.GetLedger(context.Background(), testAppID)
	if err != nil {
		t.Fatalf("ledger not written: %v", err)
	}
	l, err := ledger.Parse(data)
	if err != nil {
		t.Fatalf("written ledger invalid: %v", err)
	}
	if l.Owner.Repo != testRepo || len(l.Certificates) != 1 {
		t.Errorf("ledger = %+v, want owner %s and 1 cert", l, testRepo)
	}
	cert := l.Certificates[0]
	if cert.Status != ledger.StatusActive || cert.Requester.Login != "example-user" || cert.Requester.UserID != 12345 {
		t.Errorf("cert entry = %+v", cert)
	}
	if !strings.HasPrefix(cert.Serial, "0x") || !strings.HasPrefix(cert.Fingerprint, "sha256:") {
		t.Errorf("serial/fingerprint format: %s / %s", cert.Serial, cert.Fingerprint)
	}

	// The delivered comment carries a certificate chain (two PEM blocks).
	deliver := lastComment(t, gh, 42)
	if n := strings.Count(deliver, "BEGIN CERTIFICATE"); n != 2 {
		t.Errorf("delivery has %d certificate blocks, want 2 (leaf + intermediate)", n)
	}
}

// TestProcessRenewalAppends confirms an additional cert for the same repo is
// appended (DecisionAllowed).
func TestProcessRenewalAppends(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	d, gh := harness(t, now)
	gh.SetFile(testRepo, "appinfo/info.xml", []byte(testInfoXML))
	existing := &ledger.Ledger{
		AppID:     testAppID,
		Owner:     ledger.Owner{Origin: ledger.OriginGitHub, Repo: testRepo},
		ClaimedAt: ledger.Timestamp(now.Add(-24 * time.Hour)),
		Certificates: []ledger.Certificate{{
			Serial: "0xdead", Fingerprint: "sha256:old",
			NotBefore: ledger.Timestamp(now.Add(-24 * time.Hour)), NotAfter: ledger.Timestamp(now),
			Requester: ledger.Requester{Origin: ledger.OriginGitHub, Login: "example-user", UserID: 12345},
			IssueRef:  "#1", Status: ledger.StatusActive,
		}},
	}
	data, _ := existing.Marshal()
	gh.SetLedger(testAppID, data)

	iss := newIssue(makeCSR(t, testAppID), testRepo)
	satisfyChallenge(t, d, gh, iss)
	iss.Labels = []string{LabelAwaitingChallenge}
	if err := Process(context.Background(), d, iss); err != nil {
		t.Fatalf("Process: %v", err)
	}
	out, _, _ := gh.GetLedger(context.Background(), testAppID)
	l, _ := ledger.Parse(out)
	if len(l.Certificates) != 2 {
		t.Errorf("certificates = %d, want 2 (appended renewal)", len(l.Certificates))
	}
}

// TestProcessIdempotentIssued confirms an already-issued issue is a no-op.
func TestProcessIdempotentIssued(t *testing.T) {
	d, gh := harness(t, time.Now())
	iss := newIssue(makeCSR(t, testAppID), testRepo, LabelIssued)
	if err := Process(context.Background(), d, iss); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(gh.PostedComments[42]) != 0 || len(gh.LabelsAdded[42]) != 0 {
		t.Error("already-issued issue was not a no-op")
	}
}

// contains reports exact membership; hasLabel is the package's own predicate.
func contains(ss []string, want string) bool {
	return hasLabel(ss, want)
}
