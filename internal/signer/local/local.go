// Package local implements signer.Signer with an in-memory EC P-384
// intermediate CA. It exists so the whole issuer pipeline is exercisable today,
// before the CA bootstrap ceremony (design §19) has produced the real
// intermediate and before HashiCorp Vault is available. It is intended for
// tests and local dry-runs only — never for production issuance.
package local

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/DeepDiver1975/developer-certificates/internal/signer"
)

// intermediateValidity mirrors the design §2.2 intermediate lifetime (5y), so
// leaf notAfter-capping behaves as it will in production.
const intermediateValidity = 5 * 365 * 24 * time.Hour

// Signer is an in-memory intermediate CA. The zero value is not usable; call
// New.
type Signer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var _ signer.Signer = (*Signer)(nil)

// New generates a fresh self-signed EC P-384 intermediate CA whose validity
// starts at notBefore. Randomness is drawn from r (pass crypto/rand.Reader in
// production-like use; a deterministic reader in tests).
func New(r io.Reader, notBefore time.Time) (*Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), r)
	if err != nil {
		return nil, fmt.Errorf("local: generate intermediate key: %w", err)
	}
	serial, err := rand.Int(r, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("local: intermediate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Country:      []string{"DE"},
			Organization: []string{"ownCloud GmbH"},
			CommonName:   "ownCloud Code Signing Intermediate CA G2 (LOCAL TEST)",
		},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(intermediateValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
	}
	// Self-signed: this test intermediate acts as its own trust anchor.
	der, err := x509.CreateCertificate(r, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("local: self-sign intermediate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("local: parse intermediate: %w", err)
	}
	return &Signer{cert: cert, key: key}, nil
}

// IssuerCertificate returns the in-memory intermediate certificate.
func (s *Signer) IssuerCertificate() *x509.Certificate {
	return s.cert
}

// Sign signs the leaf template under the in-memory intermediate and returns the
// DER certificate.
func (s *Signer) Sign(_ context.Context, template *x509.Certificate, subjectPub any) ([]byte, error) {
	der, err := x509.CreateCertificate(rand.Reader, template, s.cert, subjectPub, s.key)
	if err != nil {
		return nil, fmt.Errorf("local: sign leaf: %w", err)
	}
	return der, nil
}
