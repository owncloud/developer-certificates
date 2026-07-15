package enroll

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/owncloud/developer-certificates/internal/certtmpl"
	"github.com/owncloud/developer-certificates/internal/challenge"
	"github.com/owncloud/developer-certificates/internal/ghclient"
	"github.com/owncloud/developer-certificates/internal/ledger"
	"github.com/owncloud/developer-certificates/internal/signer"
)

// priorChallenge recovers a previously-posted nonce and its comment timestamp
// from the bot's own comments (spec §2: only bot-authored comments are read).
// If several exist, the most recent wins.
func (d Deps) priorChallenge(ctx context.Context, issue int) (nonce string, postedAt time.Time, found bool, err error) {
	comments, err := d.GH.OwnComments(ctx, issue)
	if err != nil {
		return "", time.Time{}, false, fmt.Errorf("enroll: read own comments: %w", err)
	}
	for _, c := range comments { // oldest first; keep the last match
		if n, ok := challenge.ParseNonce(c.Body); ok {
			nonce, postedAt, found = n, c.CreatedAt, true
		}
	}
	return nonce, postedAt, found, nil
}

// postChallenge generates a fresh nonce, posts the instruction comment, and
// labels the issue awaiting-challenge (spec §4 step 6).
func (d Deps) postChallenge(ctx context.Context, issue int) error {
	nonce, err := challenge.Generate(d.Rand)
	if err != nil {
		return fmt.Errorf("enroll: generate nonce: %w", err)
	}
	if err := d.GH.PostComment(ctx, issue, challenge.CommentBody(nonce)); err != nil {
		return fmt.Errorf("enroll: post challenge: %w", err)
	}
	return d.GH.SetLabels(ctx, issue, []string{LabelAwaitingChallenge}, nil)
}

// loadLedger reads the current ledger entry for appID, returning (nil, "", nil)
// when none exists yet.
func (d Deps) loadLedger(ctx context.Context, appID string) (*ledger.Ledger, string, error) {
	data, sha, err := d.GH.GetLedger(ctx, appID)
	if errors.Is(err, ghclient.ErrNotFound) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("enroll: read ledger: %w", err)
	}
	l, err := ledger.Parse(data)
	if err != nil {
		return nil, "", fmt.Errorf("enroll: parse ledger %s: %w", appID, err)
	}
	return l, sha, nil
}

// issue mints the leaf, appends it to the ledger (with conflict-retry), and
// delivers the chain (spec §4 steps 9–11).
func (d Deps) issue(ctx context.Context, issue ghclient.Issue, f form, appID string, pub any, existing *ledger.Ledger, prevSHA string) error {
	now := d.Clock.Now()
	issuerCert := d.Signer.IssuerCertificate()

	tmpl, err := certtmpl.Leaf(d.Rand, certtmpl.Inputs{
		AppID:     appID,
		Owner:     ownerOf(f.Repo),
		Origin:    string(ledger.OriginGitHub),
		PublicKey: pub,
		NotBefore: now,
		Issuer:    issuerCert,
	})
	if err != nil {
		return fmt.Errorf("enroll: build leaf template: %w", err)
	}
	der, err := d.Signer.Sign(ctx, tmpl, pub)
	if err != nil {
		return fmt.Errorf("enroll: sign leaf: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("enroll: parse issued leaf: %w", err)
	}

	entry := ledger.Certificate{
		Serial:      signer.FormatSerial(leaf.SerialNumber),
		Fingerprint: signer.Fingerprint(der),
		NotBefore:   ledger.Timestamp(leaf.NotBefore),
		NotAfter:    ledger.Timestamp(leaf.NotAfter),
		Requester: ledger.Requester{
			Origin: ledger.OriginGitHub,
			Login:  issue.Author.Login,
			UserID: issue.Author.UserID,
		},
		IssueRef: fmt.Sprintf("#%d", issue.Number),
		Status:   ledger.StatusActive,
	}

	if err := d.commitLedger(ctx, appID, f.Repo, entry, existing, prevSHA); err != nil {
		return err
	}

	// Step 11: deliver the chain (leaf + intermediate) and close.
	chain := string(signer.EncodePEM(der)) + string(signer.EncodePEM(issuerCert.Raw))
	body := fmt.Sprintf("Certificate issued for `%s`. Your leaf certificate and the intermediate (chain) follow — save both.\n\n```\n%s```\n", appID, chain)
	if err := d.GH.PostComment(ctx, issue.Number, body); err != nil {
		return fmt.Errorf("enroll: deliver cert: %w", err)
	}
	if err := d.GH.SetLabels(ctx, issue.Number, []string{LabelIssued}, []string{LabelAwaitingChallenge}); err != nil {
		return fmt.Errorf("enroll: set issued label: %w", err)
	}
	return d.GH.CloseIssue(ctx, issue.Number)
}

// commitLedger appends entry to the appId's ledger and writes it back, retrying
// on a write conflict by re-reading and re-applying (spec §2, §4 step 10).
func (d Deps) commitLedger(ctx context.Context, appID, repo string, entry ledger.Certificate, existing *ledger.Ledger, prevSHA string) error {
	now := d.Clock.Now()
	for attempt := 0; attempt < maxLedgerRetries; attempt++ {
		l := existing
		if l == nil {
			// New claim: create the entry bound to the proven repo.
			l = &ledger.Ledger{
				AppID:     appID,
				Owner:     ledger.Owner{Origin: ledger.OriginGitHub, Repo: repo},
				ClaimedAt: ledger.Timestamp(now),
			}
		}
		l.Certificates = append(l.Certificates, entry)

		data, err := l.Marshal()
		if err != nil {
			return fmt.Errorf("enroll: marshal ledger: %w", err)
		}
		err = d.GH.PutLedger(ctx, appID, data, prevSHA, fmt.Sprintf("ledger: issue cert for %s", appID))
		if err == nil {
			return nil
		}
		if !errors.Is(err, ghclient.ErrConflict) {
			return fmt.Errorf("enroll: write ledger: %w", err)
		}
		// Conflict: another write landed first. Re-read and re-apply.
		existing, prevSHA, err = d.loadLedger(ctx, appID)
		if err != nil {
			return err
		}
	}
	return fmt.Errorf("enroll: ledger write for %s conflicted after %d retries", appID, maxLedgerRetries)
}
