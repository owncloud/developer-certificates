// Package cms is the CMS/PKCS#7 SignedData verification seam for the revocation
// bot (enrollment spec §5.1). A developer proves possession of a certificate's
// private key by signing a CMS blob with it; the bot verifies that blob and
// reads the signer certificate embedded in it.
//
// Following the internal/signer pattern, the pipeline depends only on the
// Verifier interface here. The production adapter (internal/cms/openssl) shells
// out to the openssl CLI so verification is byte-for-byte interoperable with the
// `openssl cms -sign` command developers run (spec §10); an in-memory fake keeps
// pipeline tests hermetic.
package cms

import (
	"context"
	"crypto/x509"
	"errors"
)

// ErrInvalidCMS is an expected verification failure: the blob is malformed or
// its signature does not verify. The pipeline maps it to an `invalid` terminal.
// It is distinct from an infrastructure error (e.g. the verifier could not run),
// which the pipeline surfaces as a Go error so the next poll re-enters.
var ErrInvalidCMS = errors.New("cms: verification failed")

// Result is a successfully verified CMS SignedData.
type Result struct {
	// SignerCert is the certificate embedded in the CMS structure whose key
	// produced the signature. The pipeline matches it to the ledger.
	SignerCert *x509.Certificate
	// Content is the verified inner (signed) content — e.g. the literal "revoke".
	Content []byte
}

// Verifier verifies a PEM CMS revocation request.
type Verifier interface {
	// Verify checks the CMS SignedData signature against the certificate
	// embedded in the structure (no chain validation — spec §5.1). On a
	// verification failure it returns ErrInvalidCMS; on success it returns the
	// embedded signer cert and the verified content.
	Verify(ctx context.Context, pemRequest []byte) (*Result, error)
}
