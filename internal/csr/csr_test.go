package csr

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// TestParseAccepts covers the key allowlist positive cases: EC P-384 and RSA at
// or above the 3072-bit floor. Each fixture is a real openssl-generated CSR, so
// this also exercises proof-of-possession end to end.
func TestParseAccepts(t *testing.T) {
	for _, name := range []string{"valid-p384.csr", "valid-rsa3072.csr", "valid-rsa4096.csr"} {
		t.Run(name, func(t *testing.T) {
			req, err := Parse(readFixture(t, name))
			if err != nil {
				t.Fatalf("Parse(%s) unexpected err: %v", name, err)
			}
			if req.Subject.CommonName != "example-app" {
				t.Errorf("CommonName = %q, want %q", req.Subject.CommonName, "example-app")
			}
		})
	}
}

// TestParseRejectsKey covers the allowlist negative cases: a curve that is not
// P-384, and an RSA key below the floor.
func TestParseRejectsKey(t *testing.T) {
	for _, name := range []string{"reject-p256.csr", "reject-rsa2048.csr"} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(readFixture(t, name))
			if !errors.Is(err, ErrUnsupportedKey) {
				t.Errorf("Parse(%s) err = %v, want ErrUnsupportedKey", name, err)
			}
		})
	}
}

// TestParseNotPEM rejects input that is not a PEM CERTIFICATE REQUEST block,
// and a PEM block of the wrong type.
func TestParseNotPEM(t *testing.T) {
	if _, err := Parse(readFixture(t, "not-pem.txt")); !errors.Is(err, ErrNotPEM) {
		t.Errorf("Parse(not-pem) err = %v, want ErrNotPEM", err)
	}

	wrongType := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("nope")})
	if _, err := Parse(wrongType); !errors.Is(err, ErrNotPEM) {
		t.Errorf("Parse(wrong PEM type) err = %v, want ErrNotPEM", err)
	}
}

// TestParseTamperedSignature flips a byte in the CSR's signature to prove the
// self-signature check (proof of possession) actually fails. The fixture is
// re-encoded from a known-good CSR so the DER stays parseable but the signature
// no longer verifies.
func TestParseTamperedSignature(t *testing.T) {
	block, _ := pem.Decode(readFixture(t, "valid-p384.csr"))
	if block == nil {
		t.Fatal("could not decode base fixture")
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse base fixture: %v", err)
	}
	if len(req.Signature) == 0 {
		t.Fatal("base fixture has no signature")
	}

	// Corrupt the raw DER at the last byte, which lands inside the trailing
	// signature BIT STRING, then re-wrap as PEM.
	der := append([]byte(nil), block.Bytes...)
	der[len(der)-1] ^= 0xFF
	tampered := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der})

	if _, err := Parse(tampered); !errors.Is(err, ErrBadSignature) {
		t.Errorf("Parse(tampered) err = %v, want ErrBadSignature", err)
	}
}
