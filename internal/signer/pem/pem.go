// Package pem implements signer.Signer by loading the intermediate CA private
// key from a PEM string (a GitHub Actions secret) into the runner process.
//
// This is design §19's explicitly weaker fallback ("pulling the raw PEM into
// the runner ... to avoid if possible"): unlike internal/signer/vault, the
// intermediate private key IS present in the runner's memory. It is used only
// when no Vault is available. See docs/superpowers/specs/2026-07-14-ca-bootstrap-design.md
// (risk R1) for the accepted risk. The preferred production path remains vault.
package pem

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/DeepDiver1975/developer-certificates/internal/signer"
)

// Config wires the PEM-backed signer.
type Config struct {
	KeyPEM string            // PEM-encoded EC private key (from INTERMEDIATE_KEY_PEM)
	Issuer *x509.Certificate // the public intermediate cert (from INTERMEDIATE_CERT)
}

// Signer issues leaves and CRLs under an in-process intermediate key.
type Signer struct {
	key    *ecdsa.PrivateKey
	issuer *x509.Certificate
}

var _ signer.Signer = (*Signer)(nil)

// New parses and validates the key, and confirms it matches the issuer cert.
func New(cfg Config) (*Signer, error) {
	if cfg.KeyPEM == "" {
		return nil, fmt.Errorf("pem: KeyPEM is required")
	}
	if cfg.Issuer == nil {
		return nil, fmt.Errorf("pem: Issuer certificate is required")
	}
	key, err := parseECKey(cfg.KeyPEM)
	if err != nil {
		return nil, err
	}
	if key.Curve != elliptic.P384() {
		return nil, fmt.Errorf("pem: intermediate key must be EC P-384 (design §3)")
	}
	issuerPub, ok := cfg.Issuer.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("pem: issuer certificate public key is not ECDSA")
	}
	if !key.PublicKey.Equal(issuerPub) {
		return nil, fmt.Errorf("pem: private key does not match issuer certificate public key")
	}
	return &Signer{key: key, issuer: cfg.Issuer}, nil
}

// parseECKey decodes a PEM EC private key, accepting SEC1 ("EC PRIVATE KEY")
// and PKCS#8 ("PRIVATE KEY").
func parseECKey(keyPEM string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("pem: KeyPEM is not valid PEM")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pem: parse PKCS#8: %w", err)
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("pem: PKCS#8 key is not ECDSA")
		}
		return ec, nil
	default:
		return nil, fmt.Errorf("pem: unexpected PEM block %q, want EC PRIVATE KEY or PRIVATE KEY", block.Type)
	}
}

// IssuerCertificate returns the configured intermediate certificate.
func (s *Signer) IssuerCertificate() *x509.Certificate { return s.issuer }

// Sign signs the leaf template under the intermediate and returns DER.
func (s *Signer) Sign(_ context.Context, template *x509.Certificate, subjectPub any) ([]byte, error) {
	der, err := x509.CreateCertificate(rand.Reader, template, s.issuer, subjectPub, s.key)
	if err != nil {
		return nil, fmt.Errorf("pem: create certificate: %w", err)
	}
	return der, nil
}

// SignCRL signs the CRL template under the intermediate and returns DER.
func (s *Signer) SignCRL(_ context.Context, template *x509.RevocationList) ([]byte, error) {
	der, err := x509.CreateRevocationList(rand.Reader, template, s.issuer, s.key)
	if err != nil {
		return nil, fmt.Errorf("pem: create crl: %w", err)
	}
	return der, nil
}
