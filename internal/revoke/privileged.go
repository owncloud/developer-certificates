package revoke

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/owncloud/developer-certificates/internal/appid"
	"github.com/owncloud/developer-certificates/internal/ghclient"
	"github.com/owncloud/developer-certificates/internal/ledger"
)

// PrivilegedDeps are the privileged path's injected collaborators. No CMS
// (authorization is org membership via the workflow_dispatch write-access gate,
// spec §5.2) and no signer (revocation mints nothing).
type PrivilegedDeps struct {
	GH    ghclient.GitHub
	Clock Clock
}

// PrivilegedRequest is one authoritative revocation, populated by cmd/privrevoke
// from workflow_dispatch inputs + github.actor.
type PrivilegedRequest struct {
	AppID       string     // ledger filename; must be a canonical appId
	Serial      string     // target certificate serial ("0x…")
	Reason      string     // required: why (operator string)
	RevokedFrom *time.Time // optional; nil → default to the cert's NotBefore
	Actor       string     // github.actor (audit trail); required
}

// PrivilegedProcess performs an authoritative, org-gated revocation (spec §5.2):
// it locates the cert by appId + serial and flips it to revoked with the
// operator-supplied reason, revokedFrom (defaulting to the cert's NotBefore), and
// actor. It OVERWRITES an already-revoked entry (authoritative correction). Every
// failure is a hard error — there is no issue to comment on.
func PrivilegedProcess(ctx context.Context, d PrivilegedDeps, req PrivilegedRequest) error {
	// Step 1: validate inputs.
	if _, err := appid.ValidateStrict(req.AppID); err != nil {
		return fmt.Errorf("privrevoke: appId %q is not a valid appId: %w", req.AppID, err)
	}
	serial := strings.TrimSpace(req.Serial)
	if serial == "" {
		return fmt.Errorf("privrevoke: serial is required")
	}
	if req.Reason == "" {
		return fmt.Errorf("privrevoke: reason is required")
	}
	if req.Actor == "" {
		return fmt.Errorf("privrevoke: actor is required")
	}

	// Step 2: load the ledger (must exist).
	sd := Deps{GH: d.GH, Clock: d.Clock}
	l, prevSHA, err := sd.loadLedger(ctx, req.AppID)
	if err != nil {
		return err
	}
	if l == nil {
		return fmt.Errorf("privrevoke: no ledger for appId %q", req.AppID)
	}

	// Step 3: find the cert by serial.
	idx := findBySerial(l, serial)
	if idx < 0 {
		return fmt.Errorf("privrevoke: serial %q not found in ledger for %q", serial, req.AppID)
	}

	// Step 4: resolve revokedFrom (default: the cert's NotBefore; must be >= it).
	nb := l.Certificates[idx].NotBefore
	revokedFrom := nb
	if req.RevokedFrom != nil {
		rf := ledger.Timestamp(req.RevokedFrom.UTC())
		if time.Time(rf).Before(time.Time(nb)) {
			return fmt.Errorf("privrevoke: revokedFrom %s is before the cert's notBefore %s",
				time.Time(rf).Format(time.RFC3339), time.Time(nb).Format(time.RFC3339))
		}
		revokedFrom = rf
	}

	// Step 5: apply the flip (shared core, conflict-retried). Overwrites an
	// already-revoked entry — the finder matches by serial regardless of status.
	if _, err := sd.applyRevocation(ctx, req.AppID,
		func(lg *ledger.Ledger) int { return findBySerial(lg, serial) },
		revocation{Reason: req.Reason, RevokedFrom: revokedFrom, Actor: req.Actor},
		l, prevSHA); err != nil {
		return err
	}
	return nil
}

// findBySerial returns the index of the certificate with the given serial, or -1.
func findBySerial(l *ledger.Ledger, serial string) int {
	if l == nil {
		return -1
	}
	for i := range l.Certificates {
		if l.Certificates[i].Serial == serial {
			return i
		}
	}
	return -1
}
