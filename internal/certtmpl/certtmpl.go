// Package certtmpl builds the X.509 leaf-certificate template for the issuer
// bot, following the developer/app leaf profile in the PKI design (§2.3). It is
// signer-agnostic: it produces an *x509.Certificate template only. The
// internal/signer package turns that template into a signed DER certificate,
// whether the issuing key is an in-memory test key or HashiCorp Vault Transit.
//
// Only CN is authoritative (the server authorizes on CN==appId, design §2.3,
// §6); O and OU are cosmetic. The template is validated defensively — the CN
// must be a strict, canonical appId even though the caller is expected to have
// canonicalized it already.
package certtmpl

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/owncloud/developer-certificates/internal/appid"
)

// CRLDistributionPoint is the developer/leaf CRL URL (design §6, §13). It is
// present for external tooling; the core verifier ignores it (design §9). The
// CRL is served from owncloud.dev (not the owncloud.github.io path, which
// 301-redirects org-wide to owncloud.dev — design §13).
const CRLDistributionPoint = "https://owncloud.dev/developer-certificates/crl/developers.crl"

// leafValidity is the leaf lifetime (design §2.3, §7). The actual notAfter is
// capped so it never exceeds the issuing intermediate's notAfter.
const leafValidity = 2 * 365 * 24 * time.Hour

// serialBits is the certificate serial size (design §2.3: random 128-bit).
const serialBits = 128

// Inputs are the caller-supplied values for a leaf certificate. AppID must be a
// canonical appId (it becomes the authoritative CN); Owner and Origin populate
// the cosmetic O and OU fields.
type Inputs struct {
	AppID     string            // authoritative CN; must be a canonical appId
	Owner     string            // O — repo owner org (cosmetic, not trusted)
	Origin    string            // OU — "github"/"gitlab"/"partner" (cosmetic)
	PublicKey any               // the CSR subject public key
	NotBefore time.Time         // validity start (typically issuance time)
	Issuer    *x509.Certificate // the intermediate; caps notAfter and sets AKI
}

// Leaf builds the §2.3 leaf certificate template. It generates a random 128-bit
// serial from rand and caps notAfter to min(notBefore+2y, issuer.notAfter). The
// returned template is not yet signed; pass it to a signer.Signer.
func Leaf(rand io.Reader, in Inputs) (*x509.Certificate, error) {
	if _, err := appid.ValidateStrict(in.AppID); err != nil {
		return nil, fmt.Errorf("certtmpl: CN %q: %w", in.AppID, err)
	}
	if in.Issuer == nil {
		return nil, fmt.Errorf("certtmpl: nil issuer certificate")
	}
	if in.PublicKey == nil {
		return nil, fmt.Errorf("certtmpl: nil subject public key")
	}

	serial, err := randomSerial(rand)
	if err != nil {
		return nil, err
	}

	notAfter := in.NotBefore.Add(leafValidity)
	if notAfter.After(in.Issuer.NotAfter) {
		notAfter = in.Issuer.NotAfter // never outlive the issuing intermediate
	}

	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         in.AppID,
			Organization:       []string{in.Owner},
			OrganizationalUnit: []string{in.Origin},
		},
		NotBefore: in.NotBefore,
		NotAfter:  notAfter,
		// KeyUsage extension is emitted critical by x509; digitalSignature only.
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		// BasicConstraints critical, CA:FALSE.
		BasicConstraintsValid: true,
		IsCA:                  false,
		// Leaf signatures are always ecdsa-with-SHA384 (the intermediate key is
		// EC P-384) regardless of the subject key type.
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		CRLDistributionPoints: []string{CRLDistributionPoint},
		// SKI is auto-computed and AKI auto-set from the issuer by
		// x509.CreateCertificate.
	}, nil
}

// randomSerial draws a positive random serial of serialBits bits from r.
func randomSerial(r io.Reader) (*big.Int, error) {
	// limit = 2^serialBits; the serial is in [1, limit).
	limit := new(big.Int).Lsh(big.NewInt(1), serialBits)
	for {
		n, err := rand.Int(r, limit)
		if err != nil {
			return nil, fmt.Errorf("certtmpl: serial: %w", err)
		}
		if n.Sign() > 0 {
			return n, nil
		}
		// n == 0 is vanishingly unlikely; redraw to keep the serial positive.
	}
}
