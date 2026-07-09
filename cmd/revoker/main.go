// Command revoker is the entry point the revocation GitHub Actions workflow runs
// each poll (enrollment spec §5.1, §11). It wires the real adapters —
// internal/ghclient/rest and internal/cms/openssl — and runs
// internal/revoke.Process over every open revocation-request issue. All business
// logic lives in internal/revoke; this file is only configuration and iteration.
//
// The workflow guarantees serialization via the same single-concurrency group as
// the issuer (spec §2, group "ledger-write"), so this command assumes it is the
// only ledger writer while it runs. It never signs, so no Vault configuration is
// needed.
//
// Configuration is read from the environment (set by the workflow):
//
//	GITHUB_TOKEN         bot/App token
//	GITHUB_REPOSITORY    codesigning repo "owner/name" (set by Actions)
//	ISSUER_BOT_LOGIN     the bot identity whose comments are trusted (spec §2)
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/DeepDiver1975/developer-certificates/internal/cms/openssl"
	"github.com/DeepDiver1975/developer-certificates/internal/ghclient/rest"
	"github.com/DeepDiver1975/developer-certificates/internal/revoke"
)

// realClock is the production Clock.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatalf("revoker: %v", err)
	}
}

func run(ctx context.Context) error {
	gh, err := rest.New(rest.Config{
		Token:    os.Getenv("GITHUB_TOKEN"),
		BotLogin: os.Getenv("ISSUER_BOT_LOGIN"),
		Repo:     os.Getenv("GITHUB_REPOSITORY"),
	})
	if err != nil {
		return err
	}

	deps := revoke.Deps{GH: gh, CMS: openssl.New(), Clock: realClock{}}

	issues, err := gh.ListOpenRevocationRequests(ctx)
	if err != nil {
		return fmt.Errorf("list open revocation requests: %w", err)
	}
	log.Printf("revoker: processing %d open revocation-request issue(s)", len(issues))

	var failures int
	for _, issue := range issues {
		if err := revoke.Process(ctx, deps, issue); err != nil {
			// One issue's infrastructure error must not stop the batch; the next
			// poll re-enters. Log and continue.
			failures++
			log.Printf("revoker: issue #%d: %v", issue.Number, err)
		}
	}
	if failures > 0 {
		return fmt.Errorf("%d of %d issue(s) failed this poll", failures, len(issues))
	}
	return nil
}
