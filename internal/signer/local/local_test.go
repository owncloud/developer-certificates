package local

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/DeepDiver1975/developer-certificates/internal/certtmpl"
	"github.com/DeepDiver1975/developer-certificates/internal/signer"
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
