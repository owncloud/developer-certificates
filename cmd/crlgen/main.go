// Command crlgen regenerates the leaf CRL (crl/developers.crl) from the public
// ledger (attestation-and-crl spec §3). The GitHub Actions workflow runs it daily
// and after each revocation, then commits the result. It reads every
// ledger/<appId>.json from the checked-out tree, builds the RevocationList, signs
// it under the intermediate (via Vault Transit in production; an in-memory
// intermediate for dry-runs), and writes the DER artifact. All business logic
// lives in internal/crl and internal/signer; this file is configuration and IO.
//
// Runs under the shared single-concurrency ledger lock (enrollment spec §2), so
// it assumes it is the only ledger reader/CRL writer while it runs.
//
// Configuration (env, set by the workflow):
//
//	VAULT_ADDR         Vault base URL       (production; when set, use Vault)
//	VAULT_TOKEN        Vault token
//	VAULT_TRANSIT_KEY  Transit key name for the intermediate
//	INTERMEDIATE_CERT  path to the intermediate CA PEM (public)
//	INTERMEDIATE_KEY_PEM raw PEM intermediate private key (used when VAULT_ADDR unset)
//	CRLGEN_ALLOW_LOCAL set to "1" to allow a fresh in-memory intermediate (dry-run only)
//
// When VAULT_ADDR is not set, crlgen next tries INTERMEDIATE_KEY_PEM (raw PEM
// intermediate key); failing that it requires CRLGEN_ALLOW_LOCAL=1 to use a fresh
// in-memory intermediate (dry-run / local only — never a real published CRL). Without
// any of these, missing Vault config will cause crlgen to fail.
package main

import (
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
	ledgerDir   = "ledger"
	crlPath     = "crl/developers.crl"
	crlRepoPath = "crl/developers.crl"
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

	repo := os.Getenv("GITHUB_REPOSITORY")
	if repo != "" && os.Getenv("GITHUB_TOKEN") != "" {
		gh, err := rest.New(rest.Config{
			Token:    os.Getenv("GITHUB_TOKEN"),
			BotLogin: os.Getenv("ISSUER_BOT_LOGIN"),
			Repo:     repo,
		})
		if err != nil {
			return err
		}
		if err := publishCRL(ctx, gh, repo, der); err != nil {
			return fmt.Errorf("publish crl: %w", err)
		}
		log.Printf("crlgen: proposed and merged %s (%d bytes)", crlRepoPath, len(der))
		return nil
	}
	// Dry-run / local: no repo configured — write to disk, do not publish.
	if err := os.MkdirAll(filepath.Dir(crlPath), 0o755); err != nil {
		return fmt.Errorf("create crl dir: %w", err)
	}
	if err := os.WriteFile(crlPath, der, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", crlPath, err)
	}
	log.Printf("crlgen: wrote %s (%d bytes) — NOT published (no GITHUB_REPOSITORY/TOKEN)", crlPath, len(der))
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

// publishCRL proposes crl/developers.crl as an auto-merged PR, basing the change
// on the current published blob SHA (empty if absent) for concurrency safety.
func publishCRL(ctx context.Context, gh ghclient.GitHub, repo string, der []byte) error {
	var prevSHA string
	if _, sha, err := gh.GetFile(ctx, repo, crlRepoPath); err == nil {
		prevSHA = sha
	} else if !errors.Is(err, ghclient.ErrNotFound) {
		return fmt.Errorf("crlgen: read current CRL: %w", err)
	}
	_, err := gh.ProposeChange(ctx, ghclient.ChangeSet{
		Branch:  "bot/crl",
		Message: "chore: regenerate crl/developers.crl",
		Body:    "Automated CRL regeneration from the ledger.",
		Files:   []ghclient.FileChange{{Path: crlRepoPath, Content: der, PrevSHA: prevSHA}},
	})
	return err
}
