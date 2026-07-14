package local

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/owncloud/developer-certificates/internal/certtmpl"
	"github.com/owncloud/developer-certificates/internal/signer"
)

// TestSignAndVerify issues a leaf through the local signer and verifies the
// full chain (leaf -> in-memory intermediate) with the CodeSigning EKU — the
// end-to-end proof that steps 9–11 work without a real CA.
func TestSignAndVerify(t *testing.T) {
	nb := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	s, err := New(rand.Reader, nb)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	subjectKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("subject key: %v", err)
	}

	tmpl, err := certtmpl.Leaf(rand.Reader, certtmpl.Inputs{
		AppID:     "example-app",
		Owner:     "example-org",
		Origin:    "github",
		PublicKey: &subjectKey.PublicKey,
		NotBefore: nb,
		Issuer:    s.IssuerCertificate(),
	})
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}

	der, err := s.Sign(context.Background(), tmpl, &subjectKey.PublicKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse issued leaf: %v", err)
	}
	if leaf.Subject.CommonName != "example-app" {
		t.Errorf("issued CN = %q, want example-app", leaf.Subject.CommonName)
	}

	// Verify the chain with the in-memory intermediate as the trust anchor,
	// requiring the CodeSigning EKU.
	roots := x509.NewCertPool()
	roots.AddCert(s.IssuerCertificate())
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: nb.Add(24 * time.Hour),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		t.Fatalf("chain verification failed: %v", err)
	}
}

// TestFormatHelpers pins the ledger-canonical serial and fingerprint forms.
func TestFormatHelpers(t *testing.T) {
	nb := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	s, err := New(rand.Reader, nb)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tmpl, err := certtmpl.Leaf(rand.Reader, certtmpl.Inputs{
		AppID: "example-app", Owner: "example-org", Origin: "github",
		PublicKey: &subjectKey.PublicKey, NotBefore: nb, Issuer: s.IssuerCertificate(),
	})
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	der, err := s.Sign(context.Background(), tmpl, &subjectKey.PublicKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if got := signer.FormatSerial(tmpl.SerialNumber); !strings.HasPrefix(got, "0x") {
		t.Errorf("FormatSerial = %q, want 0x-prefixed", got)
	}
	fp := signer.Fingerprint(der)
	if !strings.HasPrefix(fp, "sha256:") || len(fp) != len("sha256:")+64 {
		t.Errorf("Fingerprint = %q, want sha256:<64 hex>", fp)
	}
	pemBytes := signer.EncodePEM(der)
	if !strings.HasPrefix(string(pemBytes), "-----BEGIN CERTIFICATE-----") {
		t.Errorf("EncodePEM did not produce a CERTIFICATE block")
	}
}

// requireOpenSSL skips when the openssl CLI is unavailable, so the suite stays
// green without it while still cross-checking CRL interop in CI.
func requireOpenSSL(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not on PATH; skipping CRL interop")
	}
}

// TestSignCRLRoundTrip signs a CRL with two revoked serials, parses it back,
// verifies the signature chains to the intermediate, and checks the entries and
// validity window (attestation-and-crl spec §3.2).
func TestSignCRLRoundTrip(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	s, err := New(rand.Reader, now)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	revokedAt := now.Add(-48 * time.Hour)
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(now.Unix()),
		ThisUpdate: now,
		NextUpdate: now.Add(7 * 24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(0xabc), RevocationTime: revokedAt},
			{SerialNumber: big.NewInt(0xdef), RevocationTime: revokedAt},
		},
	}

	der, err := s.SignCRL(context.Background(), tmpl)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}

	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if err := crl.CheckSignatureFrom(s.IssuerCertificate()); err != nil {
		t.Fatalf("CRL signature does not verify against issuer: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 2 {
		t.Fatalf("entries = %d, want 2", len(crl.RevokedCertificateEntries))
	}
	if !crl.NextUpdate.Equal(crl.ThisUpdate.Add(7 * 24 * time.Hour)) {
		t.Errorf("nextUpdate = %v, want thisUpdate+7d (%v)", crl.NextUpdate, crl.ThisUpdate)
	}
	if crl.Number.Int64() != now.Unix() {
		t.Errorf("crlNumber = %d, want %d", crl.Number.Int64(), now.Unix())
	}
}

// TestSignCRLOpenSSLInterop proves the DER CRL is standard, not Go-only, by
// parsing it with the openssl CLI (attestation-and-crl spec §4).
func TestSignCRLOpenSSLInterop(t *testing.T) {
	requireOpenSSL(t)
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	s, err := New(rand.Reader, now)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(now.Unix()),
		ThisUpdate: now,
		NextUpdate: now.Add(7 * 24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(0xabc), RevocationTime: now.Add(-time.Hour)},
		},
	}
	der, err := s.SignCRL(context.Background(), tmpl)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}

	cmd := exec.Command("openssl", "crl", "-inform", "DER", "-noout", "-text")
	cmd.Stdin = bytes.NewReader(der)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("openssl crl parse failed: %v: %s", err, errb.String())
	}
	// openssl prints the serial as hex; match case-insensitively (it may render
	// as "ABC" uppercase). strings is already imported by this file.
	if !strings.Contains(strings.ToLower(out.String()), "abc") {
		t.Errorf("openssl output missing revoked serial abc:\n%s", out.String())
	}
}
