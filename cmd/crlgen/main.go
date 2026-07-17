// Command crlgen regenerates the leaf CRL (crl/developers.crl) from the public
// ledger (attestation-and-crl spec §3). The GitHub Actions workflow runs it daily
// and after each revocation, then publishes the result. It reads every
// ledger/<appId>.json from the checked-out tree, builds the RevocationList, signs
// it under the intermediate (via Vault Transit in production; an in-memory
// intermediate for dry-runs), and publishes the DER artifact. All business logic
// lives in internal/crl and internal/signer; this file is configuration and IO.
//
// `main` is protected — it forbids direct pushes (design §6, §13) — so when a
// GitHub App token is present, crlgen publishes crl/developers.crl via the
// Contents API (a GitHub-signed commit under the codesign-bot App, the ruleset
// bypass actor) instead of a raw git push. It writes only when the CRL changed.
// Without a token it just writes the file locally (dry-run).
//
// Runs under the shared single-concurrency ledger lock (enrollment spec §2), so
// it assumes it is the only ledger reader/CRL writer while it runs. It has no
// conflict-retry loop: a lost race fails the run and self-heals next regeneration.
//
// Configuration (env, set by the workflow):
//
//	VAULT_ADDR         Vault base URL       (production; when set, use Vault)
//	VAULT_TOKEN        Vault token
//	VAULT_TRANSIT_KEY  Transit key name for the intermediate
//	INTERMEDIATE_CERT  path to the intermediate CA PEM (public)
//	INTERMEDIATE_KEY_PEM raw PEM intermediate private key (used when VAULT_ADDR unset)
//	CRLGEN_ALLOW_LOCAL set to "1" to allow a fresh in-memory intermediate (dry-run only)
//	GITHUB_TOKEN       codesign-bot App token; when set (with GITHUB_REPOSITORY),
//	                   publish the CRL via the Contents API instead of writing locally
//	GITHUB_REPOSITORY  "owner/name" of the codesigning repo
//	ISSUER_BOT_LOGIN   bot identity (required by the REST client)
//
// When VAULT_ADDR is not set, crlgen next tries INTERMEDIATE_KEY_PEM (raw PEM
// intermediate key); failing that it requires CRLGEN_ALLOW_LOCAL=1 to use a fresh
// in-memory intermediate (dry-run / local only — never a real published CRL). Without
// any of these, missing Vault config will cause crlgen to fail.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/owncloud/developer-certificates/internal/crl"
	"github.com/owncloud/developer-certificates/internal/crl/store"
	"github.com/owncloud/developer-certificates/internal/ghclient"
	"github.com/owncloud/developer-certificates/internal/ghclient/rest"
	"github.com/owncloud/developer-certificates/internal/signer"
	"github.com/owncloud/developer-certificates/internal/signer/local"
	pemsigner "github.com/owncloud/developer-certificates/internal/signer/pem"
	"github.com/owncloud/developer-certificates/internal/signer/vault"
)

const (
	ledgerDir = "ledger"
	crlPath   = "crl/developers.crl"
)

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatalf("crlgen: %v", err)
	}
}

func run(ctx context.Context) error {
	now := time.Now().UTC()
	sgn, err := newSigner(now)
	if err != nil {
		return err
	}

	ledgers, err := store.LoadAll(ledgerDir)
	if err != nil {
		return err
	}
	log.Printf("crlgen: loaded %d ledger(s)", len(ledgers))

	tmpl, err := crl.Build(ledgers, now)
	if err != nil {
		return err
	}
	log.Printf("crlgen: %d revoked certificate(s) in CRL", len(tmpl.RevokedCertificateEntries))

	der, err := sgn.SignCRL(ctx, tmpl)
	if err != nil {
		return fmt.Errorf("sign crl: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(crlPath), 0o755); err != nil {
		return fmt.Errorf("create crl dir: %w", err)
	}
	if err := os.WriteFile(crlPath, der, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", crlPath, err)
	}
	log.Printf("crlgen: wrote %s (%d bytes)", crlPath, len(der))

	// Publish to the protected repo via the Contents API when a bot token is
	// configured; otherwise the local write above is all a dry-run needs.
	token, repo := os.Getenv("GITHUB_TOKEN"), os.Getenv("GITHUB_REPOSITORY")
	if token == "" || repo == "" {
		log.Printf("crlgen: GITHUB_TOKEN/GITHUB_REPOSITORY unset — wrote CRL locally only (no publish)")
		return nil
	}
	gh, err := rest.New(rest.Config{
		Token:    token,
		BotLogin: os.Getenv("ISSUER_BOT_LOGIN"),
		Repo:     repo,
	})
	if err != nil {
		return fmt.Errorf("crlgen: init github client: %w", err)
	}
	return publishCRL(ctx, gh, repo, der)
}

// crlPublisher is the subset of ghclient.GitHub crlgen needs to publish the CRL.
type crlPublisher interface {
	GetFile(ctx context.Context, repo, path string) (content []byte, commitSHA string, err error)
	PutFile(ctx context.Context, repo, path string, content []byte, prevSHA, message string) error
}

// publishCRL writes der to crlPath in repo via the Contents API, but only when
// it differs from the current published CRL. The commit is signed under the
// token's App identity, satisfying required_signatures on protected main
// (design §6, §13). A missing remote file is treated as "create".
func publishCRL(ctx context.Context, gh crlPublisher, repo string, der []byte) error {
	current, sha, err := gh.GetFile(ctx, repo, crlPath)
	switch {
	case errors.Is(err, ghclient.ErrNotFound):
		sha = "" // first publish — create
	case err != nil:
		return fmt.Errorf("crlgen: read published CRL: %w", err)
	case bytes.Equal(current, der):
		log.Printf("crlgen: %s unchanged; nothing to publish", crlPath)
		return nil
	}
	if err := gh.PutFile(ctx, repo, crlPath, der, sha, "chore: regenerate crl/developers.crl"); err != nil {
		return fmt.Errorf("crlgen: publish %s: %w", crlPath, err)
	}
	log.Printf("crlgen: published %s (%d bytes)", crlPath, len(der))
	return nil
}

// newSigner selects the signer based on configuration:
//   - If VAULT_ADDR is set: use Vault Transit with the issuer certificate from INTERMEDIATE_CERT
//   - Else if INTERMEDIATE_KEY_PEM is set: use the raw PEM intermediate key (weaker fallback)
//   - Else if CRLGEN_ALLOW_LOCAL=1: use a fresh in-memory intermediate (dry-run only, logs warning)
//   - Otherwise: return an error (production workflow must never downgrade silently)
func newSigner(now time.Time) (signer.Signer, error) {
	if os.Getenv("VAULT_ADDR") != "" {
		issuer, err := loadCert(os.Getenv("INTERMEDIATE_CERT"))
		if err != nil {
			return nil, err
		}
		return vault.New(vault.Config{
			Address: os.Getenv("VAULT_ADDR"),
			Token:   os.Getenv("VAULT_TOKEN"),
			KeyName: os.Getenv("VAULT_TRANSIT_KEY"),
		}, issuer)
	}
	if os.Getenv("INTERMEDIATE_KEY_PEM") != "" {
		issuer, err := loadCert(os.Getenv("INTERMEDIATE_CERT"))
		if err != nil {
			return nil, err
		}
		return pemsigner.New(pemsigner.Config{KeyPEM: os.Getenv("INTERMEDIATE_KEY_PEM"), Issuer: issuer})
	}
	if os.Getenv("CRLGEN_ALLOW_LOCAL") == "1" {
		log.Printf("crlgen: VAULT_ADDR unset — using an in-memory intermediate (DRY-RUN ONLY; do not publish)")
		return local.New(rand.Reader, now)
	}
	return nil, fmt.Errorf("crlgen: VAULT_ADDR is not set; refusing to sign with a throwaway key (set CRLGEN_ALLOW_LOCAL=1 for a local dry-run)")
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
