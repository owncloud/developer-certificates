package certtmpl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/owncloud/developer-certificates/internal/appid"
)

// testKey returns a throwaway EC P-384 public key to stand in for a CSR
// subject key.
func testKey(t *testing.T) any {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &k.PublicKey
}

// issuer builds a minimal issuer cert with the given notAfter for cap tests.
func issuer(notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{NotAfter: notAfter}
}

func baseInputs(t *testing.T, notBefore time.Time, issuerNotAfter time.Time) Inputs {
	return Inputs{
		AppID:     "example-app",
		Owner:     "example-org",
		Origin:    "github",
		PublicKey: testKey(t),
		NotBefore: notBefore,
		Issuer:    issuer(issuerNotAfter),
	}
}

// TestLeafProfile asserts every field of the §2.3 leaf profile.
func TestLeafProfile(t *testing.T) {
	nb := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	// Issuer outlives the leaf so notAfter is the full 2 years.
	tmpl, err := Leaf(rand.Reader, baseInputs(t, nb, nb.Add(10*365*24*time.Hour)))
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}

	if tmpl.Subject.CommonName != "example-app" {
		t.Errorf("CN = %q, want example-app", tmpl.Subject.CommonName)
	}
	if got := tmpl.Subject.Organization; len(got) != 1 || got[0] != "example-org" {
		t.Errorf("O = %v, want [example-org]", got)
	}
	if got := tmpl.Subject.OrganizationalUnit; len(got) != 1 || got[0] != "github" {
		t.Errorf("OU = %v, want [github]", got)
	}
	if tmpl.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %v, want DigitalSignature only", tmpl.KeyUsage)
	}
	if len(tmpl.ExtKeyUsage) != 1 || tmpl.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning {
		t.Errorf("ExtKeyUsage = %v, want [CodeSigning]", tmpl.ExtKeyUsage)
	}
	if tmpl.IsCA || !tmpl.BasicConstraintsValid {
		t.Errorf("BasicConstraints: IsCA=%v valid=%v, want CA:FALSE critical", tmpl.IsCA, tmpl.BasicConstraintsValid)
	}
	if tmpl.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Errorf("SignatureAlgorithm = %v, want ECDSAWithSHA384", tmpl.SignatureAlgorithm)
	}
	if len(tmpl.CRLDistributionPoints) != 1 || tmpl.CRLDistributionPoints[0] != CRLDistributionPoint {
		t.Errorf("CRL DP = %v, want [%s]", tmpl.CRLDistributionPoints, CRLDistributionPoint)
	}
	if !tmpl.NotBefore.Equal(nb) {
		t.Errorf("NotBefore = %v, want %v", tmpl.NotBefore, nb)
	}
	if want := nb.Add(leafValidity); !tmpl.NotAfter.Equal(want) {
		t.Errorf("NotAfter = %v, want %v (full 2y)", tmpl.NotAfter, want)
	}
	if tmpl.SerialNumber == nil || tmpl.SerialNumber.Sign() <= 0 {
		t.Errorf("SerialNumber = %v, want positive", tmpl.SerialNumber)
	}
	if bits := tmpl.SerialNumber.BitLen(); bits > 128 {
		t.Errorf("SerialNumber has %d bits, want <= 128", bits)
	}
}

// TestNotAfterCap verifies the leaf never outlives the issuing intermediate.
func TestNotAfterCap(t *testing.T) {
	nb := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	// Issuer expires in 1 year — sooner than the 2-year leaf default.
	issuerNotAfter := nb.Add(365 * 24 * time.Hour)
	tmpl, err := Leaf(rand.Reader, baseInputs(t, nb, issuerNotAfter))
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	if !tmpl.NotAfter.Equal(issuerNotAfter) {
		t.Errorf("NotAfter = %v, want capped to issuer %v", tmpl.NotAfter, issuerNotAfter)
	}
}

// TestLeafRejectsBadInputs covers the defensive validation.
func TestLeafRejectsBadInputs(t *testing.T) {
	nb := time.Now()

	// Non-canonical CN (uppercase) is rejected strictly.
	bad := baseInputs(t, nb, nb.Add(leafValidity))
	bad.AppID = "Example-App"
	if _, err := Leaf(rand.Reader, bad); !errors.Is(err, appid.ErrInvalid) {
		t.Errorf("Leaf(bad CN) err = %v, want appid.ErrInvalid", err)
	}

	// Nil issuer.
	nilIssuer := baseInputs(t, nb, nb.Add(leafValidity))
	nilIssuer.Issuer = nil
	if _, err := Leaf(rand.Reader, nilIssuer); err == nil {
		t.Error("Leaf(nil issuer) err = nil, want error")
	}

	// Nil public key.
	nilPub := baseInputs(t, nb, nb.Add(leafValidity))
	nilPub.PublicKey = nil
	if _, err := Leaf(rand.Reader, nilPub); err == nil {
		t.Error("Leaf(nil pubkey) err = nil, want error")
	}
}
