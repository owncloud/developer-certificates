// Package openssl implements cms.Verifier by shelling out to the openssl CLI.
// Using openssl directly guarantees byte-for-byte interoperability with the
// `openssl cms -sign` command developers run to produce a revocation request
// (enrollment spec §5.1, §10), and keeps the module free of a Go CMS
// dependency.
package openssl

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/DeepDiver1975/developer-certificates/internal/cms"
)

// binary is the openssl executable name; resolved via PATH.
const binary = "openssl"

// Verifier verifies CMS requests with the openssl CLI.
type Verifier struct{}

var _ cms.Verifier = (*Verifier)(nil)

// New returns an openssl-backed Verifier.
func New() *Verifier { return &Verifier{} }

// Verify runs `openssl cms -verify -noverify` over the PEM request, reading the
// blob from stdin and capturing the verified content from stdout and the
// verified signer certificate via -signer. The signer flag writes ONLY the
// certificate(s) that actually verified a SignerInfo — i.e. the true signer
// whose key produced the signature, not merely bundled certs. -noverify skips
// signer-cert chain building (spec §5.1: we match the embedded cert to the
// ledger, not a chain); the CMS signature itself is still verified. A non-zero
// openssl exit (*exec.ExitError) means the blob is malformed or the signature
// failed -> ErrInvalidCMS. Any other failure (openssl missing, I/O) is returned
// as an infrastructure error so the next poll re-enters.
func (v *Verifier) Verify(ctx context.Context, pemRequest []byte) (*cms.Result, error) {
	signerOut, err := os.CreateTemp("", "cms-signer-*.pem")
	if err != nil {
		return nil, fmt.Errorf("openssl: temp file: %w", err)
	}
	defer os.Remove(signerOut.Name())
	signerOut.Close()

	cmd := exec.CommandContext(ctx, binary, "cms", "-verify", "-noverify",
		"-inform", "PEM", "-signer", signerOut.Name())
	cmd.Stdin = bytes.NewReader(pemRequest)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("%w: %s", cms.ErrInvalidCMS, bytes.TrimSpace(stderr.Bytes()))
		}
		return nil, fmt.Errorf("openssl: run cms -verify: %w", err)
	}

	pemCerts, err := os.ReadFile(signerOut.Name())
	if err != nil {
		return nil, fmt.Errorf("openssl: read signer: %w", err)
	}
	signer, err := onlyCertificate(pemCerts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", cms.ErrInvalidCMS, err)
	}
	return &cms.Result{SignerCert: signer, Content: stdout.Bytes()}, nil
}

// onlyCertificate parses all PEM CERTIFICATE blocks from data and returns an
// error unless there is EXACTLY ONE. This enforces that the CMS signer output
// contains precisely one verified signer (the cert that validated the signature),
// rejecting ambiguous or invalid requests with zero or multiple signers.
func onlyCertificate(data []byte) (*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}
		data = rest
	}
	switch len(certs) {
	case 0:
		return nil, fmt.Errorf("no signer certificate in CMS output")
	case 1:
		return certs[0], nil
	default:
		return nil, fmt.Errorf("CMS has %d signer certificates; exactly one required", len(certs))
	}
}
