package revoke

import (
	"context"
	"errors"
	"fmt"

	"github.com/DeepDiver1975/developer-certificates/internal/ghclient"
	"github.com/DeepDiver1975/developer-certificates/internal/ledger"
)

// maxLedgerRetries bounds the read-modify-write conflict-retry loop (spec §2),
// matching the issuer bot.
const maxLedgerRetries = 5

// loadLedger reads and parses the ledger entry for appID, returning
// (nil, "", nil) when none exists yet.
func (d Deps) loadLedger(ctx context.Context, appID string) (*ledger.Ledger, string, error) {
	data, sha, err := d.GH.GetLedger(ctx, appID)
	if errors.Is(err, ghclient.ErrNotFound) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("revoke: read ledger: %w", err)
	}
	l, err := ledger.Parse(data)
	if err != nil {
		return nil, "", fmt.Errorf("revoke: parse ledger %s: %w", appID, err)
	}
	return l, sha, nil
}

// findByFingerprint returns the index of the certificate with the given
// fingerprint, or -1.
func findByFingerprint(l *ledger.Ledger, fp string) int {
	if l == nil {
		return -1
	}
	for i := range l.Certificates {
		if l.Certificates[i].Fingerprint == fp {
			return i
		}
	}
	return -1
}

// revokeInLedger flips the certificate with fingerprint fp to revoked and
// commits, retrying on a write conflict by re-reading and re-applying (spec §2).
// The certificate's own NotBefore is the revokedFrom date (hard revoke, spec
// §5.1). It returns the revoked entry's serial for the delivery comment.
// Conflict-retry: re-read and re-apply on a stale-SHA write (spec §2).
// Exercised by TestProcessConflictRetry via the fake's one-shot conflict hook.
func (d Deps) revokeInLedger(ctx context.Context, appID, fp string, l *ledger.Ledger, prevSHA string) (serial string, revokedFrom ledger.Timestamp, err error) {
	for attempt := 0; attempt < maxLedgerRetries; attempt++ {
		idx := findByFingerprint(l, fp)
		if idx < 0 {
			return "", ledger.Timestamp{}, fmt.Errorf("revoke: cert %s vanished from ledger %s during retry", fp, appID)
		}
		cert := &l.Certificates[idx]
		nb := cert.NotBefore
		cert.Status = ledger.StatusRevoked
		cert.RevokedFrom = &nb
		cert.Reason = "self-service"

		data, mErr := l.Marshal()
		if mErr != nil {
			return "", ledger.Timestamp{}, fmt.Errorf("revoke: marshal ledger: %w", mErr)
		}
		wErr := d.GH.PutLedger(ctx, appID, data, prevSHA,
			fmt.Sprintf("ledger: revoke %s for %s", cert.Serial, appID))
		if wErr == nil {
			return cert.Serial, nb, nil
		}
		if !errors.Is(wErr, ghclient.ErrConflict) {
			return "", ledger.Timestamp{}, fmt.Errorf("revoke: write ledger: %w", wErr)
		}
		// Conflict: another write landed first. Re-read and re-apply.
		l, prevSHA, err = d.loadLedger(ctx, appID)
		if err != nil {
			return "", ledger.Timestamp{}, err
		}
	}
	return "", ledger.Timestamp{}, fmt.Errorf("revoke: ledger write for %s conflicted after %d retries", appID, maxLedgerRetries)
}
