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
// embedded signer certificate via -certsout. -noverify skips signer-cert chain
// building (spec §5.1: we match the embedded cert to the ledger, not a chain);
// the CMS signature itself is still verified. A non-zero openssl exit
// (*exec.ExitError) means the blob is malformed or the signature failed ->
// ErrInvalidCMS. Any other failure (openssl missing, I/O) is returned as an
// infrastructure error so the next poll re-enters.
func (v *Verifier) Verify(ctx context.Context, pemRequest []byte) (*cms.Result, error) {
	certsOut, err := os.CreateTemp("", "cms-signer-*.pem")
	if err != nil {
		return nil, fmt.Errorf("openssl: temp file: %w", err)
	}
	defer os.Remove(certsOut.Name())
	certsOut.Close()

	cmd := exec.CommandContext(ctx, binary, "cms", "-verify", "-noverify",
		"-inform", "PEM", "-certsout", certsOut.Name())
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

	pemCerts, err := os.ReadFile(certsOut.Name())
	if err != nil {
		return nil, fmt.Errorf("openssl: read certsout: %w", err)
	}
	signer, err := firstCertificate(pemCerts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", cms.ErrInvalidCMS, err)
	}
	return &cms.Result{SignerCert: signer, Content: stdout.Bytes()}, nil
}

// firstCertificate parses the first PEM CERTIFICATE block from data.
func firstCertificate(data []byte) (*x509.Certificate, error) {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("no certificate found in CMS output")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
		data = rest
	}
}
