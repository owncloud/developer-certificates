// Command privrevoke performs an authoritative, org-gated certificate revocation
// (enrollment spec §5.2). The GitHub Actions workflow_dispatch workflow runs it
// with operator-supplied inputs; because only users with write access to the repo
// can dispatch that workflow, that platform gate IS the org-member authorization.
// All business logic lives in internal/revoke.PrivilegedProcess; this file is
// configuration and IO. It writes the ledger via the GitHub Contents API (like
// the self-service revoker), so it needs a GitHub token — no Vault, no signing.
//
// Runs under the shared single-concurrency ledger lock (enrollment spec §2).
//
// Configuration (env, set by the workflow from inputs.* and github.actor):
//
//	GITHUB_TOKEN       bot/App token
//	GITHUB_REPOSITORY  codesigning repo "owner/name" (set by Actions)
//	ISSUER_BOT_LOGIN   bot identity (required by the REST client; unused here)
//	APP_ID             target appId (ledger filename)
//	SERIAL             target certificate serial ("0x…")
//	REASON             operator's revocation reason (required)
//	REVOKED_FROM       optional RFC3339 UTC date; blank → the cert's notBefore
//	ACTOR              github.actor (audit trail)
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/DeepDiver1975/developer-certificates/internal/ghclient/rest"
	"github.com/DeepDiver1975/developer-certificates/internal/revoke"
)

// realClock is the production Clock.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatalf("privrevoke: %v", err)
	}
}

func run(ctx context.Context) error {
	gh, err := rest.New(rest.Config{
		Token:    os.Getenv("GITHUB_TOKEN"),
		BotLogin: os.Getenv("ISSUER_BOT_LOGIN"), // required by rest.New; unused on this path
		Repo:     os.Getenv("GITHUB_REPOSITORY"),
	})
	if err != nil {
		return err
	}

	req := revoke.PrivilegedRequest{
		AppID:  os.Getenv("APP_ID"),
		Serial: os.Getenv("SERIAL"),
		Reason: os.Getenv("REASON"),
		Actor:  os.Getenv("ACTOR"),
	}
	if rf := os.Getenv("REVOKED_FROM"); rf != "" {
		t, err := time.Parse(time.RFC3339, rf)
		if err != nil {
			return fmt.Errorf("privrevoke: REVOKED_FROM %q is not RFC3339: %w", rf, err)
		}
		req.RevokedFrom = &t
	}

	deps := revoke.PrivilegedDeps{GH: gh, Clock: realClock{}}
	if err := revoke.PrivilegedProcess(ctx, deps, req); err != nil {
		return err
	}
	log.Printf("privrevoke: revoked serial %s for %s (actor %s)", req.Serial, req.AppID, req.Actor)
	return nil
}
