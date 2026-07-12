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

// revocation is the set of fields a flip writes onto the matched certificate.
type revocation struct {
	Reason      string
	RevokedFrom ledger.Timestamp
	Actor       string // empty for self-service; github.actor for privileged
}

// findFunc locates the target certificate's index in a ledger, or -1.
type findFunc func(*ledger.Ledger) int

// applyRevocation flips the certificate located by find to revoked with the
// given revocation fields and commits, retrying on a write conflict by
// re-reading and re-applying (spec §2). It returns the revoked entry's serial.
// Shared by the self-service (§5.1) and privileged (§5.2) paths; the caller
// supplies the finder and the revocation values.
func (d Deps) applyRevocation(ctx context.Context, appID string, find findFunc, rev revocation, l *ledger.Ledger, prevSHA string) (serial string, err error) {
	for attempt := 0; attempt < maxLedgerRetries; attempt++ {
		idx := find(l)
		if idx < 0 {
			return "", fmt.Errorf("revoke: target cert vanished from ledger %s during retry", appID)
		}
		cert := &l.Certificates[idx]
		rf := rev.RevokedFrom
		cert.Status = ledger.StatusRevoked
		cert.RevokedFrom = &rf
		cert.Reason = rev.Reason
		cert.Actor = rev.Actor

		data, mErr := l.Marshal()
		if mErr != nil {
			return "", fmt.Errorf("revoke: marshal ledger: %w", mErr)
		}
		msg := fmt.Sprintf("ledger: revoke %s for %s", cert.Serial, appID)
		if rev.Actor != "" {
			msg = fmt.Sprintf("ledger: privileged revoke %s for %s (%s)", cert.Serial, appID, rev.Actor)
		}
		wErr := d.GH.PutLedger(ctx, appID, data, prevSHA, msg)
		if wErr == nil {
			return cert.Serial, nil
		}
		if !errors.Is(wErr, ghclient.ErrConflict) {
			return "", fmt.Errorf("revoke: write ledger: %w", wErr)
		}
		// Conflict: another write landed first. Re-read and re-apply.
		l, prevSHA, err = d.loadLedger(ctx, appID)
		if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("revoke: ledger write for %s conflicted after %d retries", appID, maxLedgerRetries)
}
