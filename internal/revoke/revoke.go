// Package revoke is the self-service revocation bot pipeline (enrollment spec
// §5.1). It turns an open revocation-request issue — carrying a CMS/PKCS#7
// SignedData blob signed with a certificate's private key — into a `revoked`
// entry in the ledger.
//
// It mirrors internal/enroll: every dependency is an interface (ghclient.GitHub,
// cms.Verifier, Clock), so the whole pipeline runs hermetically in tests against
// the in-memory fakes with no network, no secrets, and no real crypto. cmd/revoker
// wires the real adapters and runs Process under the single-concurrency
// ledger lock shared with the issuer (spec §2).
//
// The ledger flip is the authoritative revocation record. CRL regeneration
// (spec §5.1 step 4) is a separate deliverable (attestation-and-crl spec §3)
// that reads ledger state on its own schedule; this pipeline does not trigger it.
package revoke

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/DeepDiver1975/developer-certificates/internal/appid"
	"github.com/DeepDiver1975/developer-certificates/internal/cms"
	"github.com/DeepDiver1975/developer-certificates/internal/ghclient"
	"github.com/DeepDiver1975/developer-certificates/internal/ledger"
	"github.com/DeepDiver1975/developer-certificates/internal/signer"
)

// Labels are the terminal states this bot sets (enrollment spec §9). `invalid`
// leaves the issue open for correction; `revoked` closes it.
const (
	LabelInvalid = "invalid"
	LabelRevoked = "revoked"
)

// Clock supplies the current time; injected so tests are deterministic.
type Clock interface {
	Now() time.Time
}

// Deps are the pipeline's injected collaborators. Unlike the issuer, revocation
// mints nothing, so there is no Signer and no randomness source.
type Deps struct {
	GH    ghclient.GitHub
	CMS   cms.Verifier
	Clock Clock
}

// Process runs one poll iteration for a single revocation-request issue (spec
// §5.1). It is idempotent: an already-`revoked` issue is a no-op, and a replayed
// valid CMS re-enters, finds the entry already revoked, and closes cleanly. It
// returns an error only for unexpected infrastructure failures; expected
// terminal outcomes are surfaced as bot comments + labels.
func Process(ctx context.Context, d Deps, issue ghclient.Issue) error {
	// Idempotency: never reprocess a terminally-revoked issue.
	if hasLabel(issue.Labels, LabelRevoked) {
		return nil
	}

	// Step 1: parse the form.
	f, err := parseForm(issue.Body)
	if err != nil {
		return terminal(ctx, d, issue, LabelInvalid,
			fmt.Sprintf("Could not read a CMS revocation request from this issue: %v.", err))
	}

	// Step 2: verify the CMS signature against the embedded signer cert.
	res, err := d.CMS.Verify(ctx, []byte(f.CMS))
	if err != nil {
		if errors.Is(err, cms.ErrInvalidCMS) {
			return terminal(ctx, d, issue, LabelInvalid,
				"The CMS revocation request could not be verified. Ensure it was produced by `openssl cms -sign` with your certificate's private key.")
		}
		return fmt.Errorf("revoke: verify cms: %w", err)
	}

	// Step 3: match the embedded cert to the ledger. Our issued leaf's CN is the
	// appId, so the ledger file is located directly — no scan.
	appID, err := appid.Canonicalize(res.SignerCert.Subject.CommonName)
	if err != nil {
		return terminal(ctx, d, issue, LabelInvalid,
			fmt.Sprintf("The certificate CommonName %q is not a valid appId; it cannot be one of our issued certificates.", res.SignerCert.Subject.CommonName))
	}
	fp := signer.Fingerprint(res.SignerCert.Raw)

	l, prevSHA, err := d.loadLedger(ctx, appID)
	if err != nil {
		return err
	}
	idx := findByFingerprint(l, fp)
	if idx < 0 {
		return terminal(ctx, d, issue, LabelInvalid,
			fmt.Sprintf("No matching issued certificate (%s) was found in the ledger for `%s`.", fp, appID))
	}
	if l.Certificates[idx].Status == ledger.StatusRevoked {
		// Already revoked: idempotent terminal — comment, label, close.
		if err := terminal(ctx, d, issue, LabelRevoked, "This certificate is already revoked; nothing to do."); err != nil {
			return err
		}
		return d.GH.CloseIssue(ctx, issue.Number)
	}

	// Step 4: flip to revoked (conflict-retried).
	serial, revokedFrom, err := d.revokeInLedger(ctx, appID, fp, l, prevSHA)
	if err != nil {
		return err
	}

	// Step 5: deliver — comment, label revoked, close.
	body := fmt.Sprintf("Certificate `%s` for `%s` has been revoked, effective %s.",
		serial, appID, time.Time(revokedFrom).UTC().Format("2006-01-02T15:04:05Z"))
	if err := d.GH.PostComment(ctx, issue.Number, body); err != nil {
		return fmt.Errorf("revoke: post revoked comment: %w", err)
	}
	if err := d.GH.SetLabels(ctx, issue.Number, []string{LabelRevoked}, nil); err != nil {
		return fmt.Errorf("revoke: set revoked label: %w", err)
	}
	return d.GH.CloseIssue(ctx, issue.Number)
}
