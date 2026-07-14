// Package enroll is the issuer bot pipeline (enrollment spec §4): it turns an
// open certificate-request issue into an issued leaf certificate recorded in
// the ledger. It is the orchestrator that wires together the pure building
// blocks — internal/csr, internal/appinfo, internal/appid, internal/challenge,
// internal/certtmpl, internal/signer and internal/ledger — behind the
// internal/ghclient.GitHub and internal/signer.Signer interfaces plus an
// injected Clock and randomness source.
//
// Because every dependency is an interface, the whole pipeline runs
// hermetically in tests against internal/ghclient/fake and
// internal/signer/local, with no network, no secrets, and no real CA. The
// caller (cmd/issuer, a later PR) is responsible only for wiring the real
// adapters and running Process under the single-concurrency ledger lock
// (spec §2).
package enroll

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/owncloud/developer-certificates/internal/appid"
	"github.com/owncloud/developer-certificates/internal/appinfo"
	"github.com/owncloud/developer-certificates/internal/challenge"
	"github.com/owncloud/developer-certificates/internal/csr"
	"github.com/owncloud/developer-certificates/internal/ghclient"
	"github.com/owncloud/developer-certificates/internal/ledger"
	"github.com/owncloud/developer-certificates/internal/signer"
)

// Labels are the issue-state vocabulary (spec §9). Every terminal state has an
// explanatory bot comment.
const (
	LabelInvalid           = "invalid"
	LabelNeedsChanges      = "needs-changes"
	LabelAwaitingChallenge = "awaiting-challenge"
	LabelExpired           = "expired"
	LabelRejected          = "rejected"
	LabelIssued            = "issued"
)

// maxLedgerRetries bounds the read-modify-write conflict-retry loop (spec §2).
const maxLedgerRetries = 5

// Clock supplies the current time; injected so tests are deterministic.
type Clock interface {
	Now() time.Time
}

// Deps are the pipeline's injected collaborators.
type Deps struct {
	GH     ghclient.GitHub
	Signer signer.Signer
	Clock  Clock
	Rand   io.Reader
}

// Process runs one poll iteration for a single certificate-request issue,
// advancing it through the spec §4 pipeline. It is idempotent: an already
// `issued` issue is a no-op, and the nonce-challenge phase re-enters safely
// across polls. It reports an error only for unexpected infrastructure
// failures; expected terminal outcomes (invalid CSR, mismatch, rejection,
// expiry) are surfaced as bot comments + labels, not errors.
func Process(ctx context.Context, d Deps, issue ghclient.Issue) error {
	// Idempotency: never reprocess a terminally-issued issue.
	if hasLabel(issue.Labels, LabelIssued) {
		return nil
	}

	// Step 1: parse the form.
	f, err := parseForm(issue.Body)
	if err != nil {
		return terminal(ctx, d, issue, LabelInvalid, fmt.Sprintf("Could not process this request: %v.", err))
	}

	// Steps 2–3: validate the CSR and derive the appId from its CN.
	req, err := csr.Parse([]byte(f.CSR))
	if err != nil {
		return terminal(ctx, d, issue, LabelInvalid, fmt.Sprintf("CSR rejected: %v.", err))
	}
	csrAppID, err := appid.ValidateStrict(req.Subject.CommonName)
	if err != nil {
		return terminal(ctx, d, issue, LabelInvalid,
			fmt.Sprintf("The CSR CommonName %q is not a valid appId (%s).", req.Subject.CommonName, appid.Pattern))
	}

	// Step 4: fetch and parse appinfo/info.xml from the target repo.
	infoXML, _, err := d.GH.GetFile(ctx, f.Repo, "appinfo/info.xml")
	if err != nil {
		if errors.Is(err, ghclient.ErrNotFound) {
			return terminal(ctx, d, issue, LabelNeedsChanges,
				fmt.Sprintf("Could not find `appinfo/info.xml` on the default branch of `%s`.", f.Repo))
		}
		return fmt.Errorf("enroll: fetch info.xml: %w", err)
	}
	rawID, err := appinfo.ExtractID(infoXML)
	if err != nil {
		return terminal(ctx, d, issue, LabelNeedsChanges,
			fmt.Sprintf("`appinfo/info.xml` in `%s` has no usable `<id>` (%v).", f.Repo, err))
	}
	infoAppID, err := appid.Canonicalize(rawID)
	if err != nil {
		return terminal(ctx, d, issue, LabelNeedsChanges,
			fmt.Sprintf("The `info.xml` id %q is not a valid appId (%s).", rawID, appid.Pattern))
	}

	// Step 5: reconcile. The canonical CSR CN must equal the canonical id.
	if csrAppID != infoAppID {
		return terminal(ctx, d, issue, LabelNeedsChanges,
			fmt.Sprintf("The CSR CommonName (%q) does not match your `info.xml` id (%q). They must be the same appId.", csrAppID, infoAppID))
	}
	appID := csrAppID // canonical henceforth; the issued cert CN is exactly this

	// Steps 6–7: the nonce challenge. Recover any prior nonce from the bot's
	// own comments; otherwise post a fresh one and wait for the next poll.
	nonce, postedAt, found, err := d.priorChallenge(ctx, issue.Number)
	if err != nil {
		return err
	}
	if !found {
		return d.postChallenge(ctx, issue.Number)
	}
	if challenge.Expired(postedAt, d.Clock.Now()) {
		return terminal(ctx, d, issue, LabelExpired,
			"The repository-control challenge expired (72h). Open a new request to try again.")
	}
	got, _, err := d.GH.GetFile(ctx, f.Repo, challenge.FilePath)
	if err != nil {
		if errors.Is(err, ghclient.ErrNotFound) {
			return nil // still awaiting; stay on awaiting-challenge, re-check next poll
		}
		return fmt.Errorf("enroll: fetch challenge file: %w", err)
	}
	if !challenge.Match(nonce, string(got)) {
		return nil // present but wrong; keep waiting within the 72h window
	}

	// Step 8: FCFS ledger check.
	existing, prevSHA, err := d.loadLedger(ctx, appID)
	if err != nil {
		return err
	}
	switch ledger.Decide(existing, f.Repo) {
	case ledger.DecisionRejectedReserved:
		return terminal(ctx, d, issue, LabelRejected,
			fmt.Sprintf("`%s` is a reserved first-party appId and cannot be claimed.", appID))
	case ledger.DecisionRejectedMismatch:
		return terminal(ctx, d, issue, LabelRejected,
			fmt.Sprintf("The appId `%s` is already owned by a different repository. Contact us for genuine disputes.", appID))
	case ledger.DecisionNewClaim, ledger.DecisionAllowed:
		// proceed to issuance
	}

	// Steps 9–11: issue, record, deliver.
	return d.issue(ctx, issue, f, appID, req.PublicKey, existing, prevSHA)
}
