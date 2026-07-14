// Command issuer is the entry point the GitHub Actions workflow runs each poll
// (enrollment spec §4, §11). It wires the real adapters — internal/ghclient/rest
// and internal/signer/vault — and runs internal/enroll.Process over every open
// certificate-request issue. All business logic lives in internal/enroll; this
// file is only configuration and iteration.
//
// The workflow guarantees serialization via a single-concurrency group
// (spec §2), so this command assumes it is the only writer while it runs.
//
// Configuration is read from the environment (set by the workflow from repo
// secrets / OIDC):
//
//	GITHUB_TOKEN         bot/App token
//	GITHUB_REPOSITORY    codesigning repo "owner/name" (set by Actions)
//	ISSUER_BOT_LOGIN     the bot identity whose comments are trusted (spec §2)
//	VAULT_ADDR           Vault base URL
//	VAULT_TOKEN          Vault token
//	VAULT_TRANSIT_KEY    Transit key name for the intermediate
//	INTERMEDIATE_CERT    path to the intermediate CA PEM (public)
//	INTERMEDIATE_KEY_PEM raw PEM intermediate private key (used when VAULT_ADDR unset)
package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/owncloud/developer-certificates/internal/enroll"
	"github.com/owncloud/developer-certificates/internal/ghclient/rest"
	"github.com/owncloud/developer-certificates/internal/signer"
	pemsigner "github.com/owncloud/developer-certificates/internal/signer/pem"
	"github.com/owncloud/developer-certificates/internal/signer/vault"
)

// realClock is the production Clock.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatalf("issuer: %v", err)
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

	sgn, err := newSigner()
	if err != nil {
		return err
	}

	deps := enroll.Deps{GH: gh, Signer: sgn, Clock: realClock{}, Rand: rand.Reader}

	issues, err := gh.ListOpenCertRequests(ctx)
	if err != nil {
		return fmt.Errorf("list open requests: %w", err)
	}
	log.Printf("issuer: processing %d open certificate-request issue(s)", len(issues))

	var failures int
	for _, issue := range issues {
		if err := enroll.Process(ctx, deps, issue); err != nil {
			// One issue's infrastructure error must not stop the batch; the next
			// poll re-enters. Log and continue.
			failures++
			log.Printf("issuer: issue #%d: %v", issue.Number, err)
		}
	}
	if failures > 0 {
		return fmt.Errorf("%d of %d issue(s) failed this poll", failures, len(issues))
	}
	return nil
}

// newSigner selects the signer by configuration (design §19 / bootstrap design §2.1):
//   - VAULT_ADDR set        → Vault Transit (preferred; key never enters runner)
//   - INTERMEDIATE_KEY_PEM  → raw PEM intermediate key (weaker fallback, risk R1)
//   - otherwise             → hard error (never sign with a throwaway key)
func newSigner() (signer.Signer, error) {
	issuerCert, err := loadCert(os.Getenv("INTERMEDIATE_CERT"))
	if err != nil {
		return nil, err
	}
	if os.Getenv("VAULT_ADDR") != "" {
		return vault.New(vault.Config{
			Address: os.Getenv("VAULT_ADDR"),
			Token:   os.Getenv("VAULT_TOKEN"),
			KeyName: os.Getenv("VAULT_TRANSIT_KEY"),
		}, issuerCert)
	}
	if os.Getenv("INTERMEDIATE_KEY_PEM") != "" {
		return pemsigner.New(pemsigner.Config{KeyPEM: os.Getenv("INTERMEDIATE_KEY_PEM"), Issuer: issuerCert})
	}
	return nil, fmt.Errorf("issuer: no signer configured (set VAULT_ADDR or INTERMEDIATE_KEY_PEM)")
}

// loadCert reads and parses a PEM certificate from path.
func loadCert(path string) (*x509.Certificate, error) {
	if path == "" {
		return nil, fmt.Errorf("INTERMEDIATE_CERT is not set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read intermediate cert: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("intermediate cert %q is not a PEM CERTIFICATE", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse intermediate cert: %w", err)
	}
	return cert, nil
}
