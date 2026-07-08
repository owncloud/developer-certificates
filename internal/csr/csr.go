// Package csr parses and validates the certificate signing requests submitted
// through the CSR intake issue form (enrollment spec §4 steps 1–2). It enforces
// the key allowlist from the PKI design (§3: EC P-384 primary, RSA-4096
// documented fallback) and verifies the CSR self-signature as proof that the
// requester holds the corresponding private key.
//
// Parsing here is deliberately narrow: it returns the parsed request and the
// raw Subject CommonName only. Canonicalization and appId validation are the
// caller's job via internal/appid.ValidateStrict, which keeps the strict
// (cert-CN) vs. fold (info.xml) asymmetry the design mandates in one place.
package csr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// minRSABits is the smallest accepted RSA modulus. The design documents
// RSA-4096 as the preferred developer/HSM fallback; 3072 is the floor.
const minRSABits = 3072

// Sentinel errors so callers (and tests) can classify failures precisely.
var (
	// ErrNotPEM is returned when the input is not a PEM-encoded CERTIFICATE
	// REQUEST block.
	ErrNotPEM = errors.New("csr: input is not a PEM CERTIFICATE REQUEST")
	// ErrUnsupportedKey is returned when the CSR's public key is not on the
	// allowlist (EC P-384, or RSA >= 3072).
	ErrUnsupportedKey = errors.New("csr: unsupported public key")
	// ErrBadSignature is returned when the CSR self-signature does not verify
	// (proof of possession failed).
	ErrBadSignature = errors.New("csr: signature verification failed")
)

// pemType is the only PEM block type accepted for a CSR.
const pemType = "CERTIFICATE REQUEST"

// Parse decodes a PEM certificate signing request, enforces the key allowlist,
// and verifies its self-signature (proof of possession). On success it returns
// the parsed request; read the appId from req.Subject.CommonName and validate
// it with appid.ValidateStrict.
func Parse(data []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemType {
		return nil, ErrNotPEM
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("csr: parse: %w", err)
	}
	if err := checkKey(req.PublicKey); err != nil {
		return nil, err
	}
	// Proof of possession: the CSR must be signed by the private key matching
	// its embedded public key.
	if err := req.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	return req, nil
}

// checkKey enforces the design §3 allowlist: EC P-384 (primary) or RSA with a
// modulus of at least minRSABits. Every other key type, curve, or size is
// rejected.
func checkKey(pub any) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P384() {
			return fmt.Errorf("%w: EC curve %s (only P-384 is accepted)", ErrUnsupportedKey, curveName(k.Curve))
		}
		return nil
	case *rsa.PublicKey:
		if bits := k.N.BitLen(); bits < minRSABits {
			return fmt.Errorf("%w: RSA-%d (minimum is RSA-%d)", ErrUnsupportedKey, bits, minRSABits)
		}
		return nil
	default:
		return fmt.Errorf("%w: %T", ErrUnsupportedKey, pub)
	}
}

// curveName renders a curve for error messages without assuming it is non-nil.
func curveName(c elliptic.Curve) string {
	if c == nil || c.Params() == nil {
		return "unknown"
	}
	return c.Params().Name
}
