// Package signer defines the seam between the issuer pipeline and the CA
// signing key. The pipeline builds a leaf template (internal/certtmpl) and asks
// a Signer to sign it under the intermediate CA; the Signer hides where the
// intermediate private key lives.
//
// Two implementations exist: internal/signer/local (an ephemeral in-memory
// intermediate, used by tests and dry-runs — the CA bootstrap ceremony, design
// §19, has not run yet) and, later, a HashiCorp Vault Transit implementation
// that signs through Vault so the key never lands in the runner. Both satisfy
// this interface, so the pipeline is identical regardless of which one is
// wired in.
package signer

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
)

// Signer issues a leaf certificate under the intermediate CA.
type Signer interface {
	// IssuerCertificate returns the intermediate CA certificate that leaves
	// chain to. It supplies the issuer/AKI when signing and is delivered to the
	// requester as the chain certificate.
	IssuerCertificate() *x509.Certificate

	// Sign signs the given leaf template (from certtmpl.Leaf) under the
	// intermediate, binding subjectPub as the certificate's public key. It
	// returns the signed certificate in DER form.
	Sign(ctx context.Context, template *x509.Certificate, subjectPub any) (der []byte, err error)
}

// FormatSerial renders a certificate serial as the ledger's canonical
// "0x<hex>" form (design §6). The hex is lowercase with no leading zero beyond
// what big.Int emits; zero renders as "0x0".
func FormatSerial(serial *big.Int) string {
	return "0x" + serial.Text(16)
}

// Fingerprint computes the ledger's canonical "sha256:<hex>" fingerprint
// (design §6) over the certificate DER.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// EncodePEM wraps a DER certificate in a PEM CERTIFICATE block, as delivered to
// the requester (enrollment spec §4 step 11).
func EncodePEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
