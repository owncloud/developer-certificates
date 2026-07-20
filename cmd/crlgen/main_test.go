package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/owncloud/developer-certificates/internal/ghclient/fake"
)

const testRepo = "owncloud/developer-certificates"

// TestPublishCRLCreatesWhenAbsent verifies the first publish creates the file
// (no prevSHA) via PutFile.
func TestPublishCRLCreatesWhenAbsent(t *testing.T) {
	gh := fake.New()
	der := []byte("der-v1")

	if err := publishCRL(context.Background(), gh, testRepo, der); err != nil {
		t.Fatalf("publishCRL: %v", err)
	}

	got, _, err := gh.GetFile(context.Background(), testRepo, crlPath)
	if err != nil {
		t.Fatalf("GetFile after publish: %v", err)
	}
	if string(got) != string(der) {
		t.Errorf("published content = %q, want %q", got, der)
	}
}

// TestPublishCRLUpdatesExisting verifies an existing CRL is overwritten using
// the current blob SHA (optimistic-concurrency update path).
func TestPublishCRLUpdatesExisting(t *testing.T) {
	gh := fake.New()
	gh.SetFile(testRepo, crlPath, []byte("der-v1"))

	if err := publishCRL(context.Background(), gh, testRepo, []byte("der-v2")); err != nil {
		t.Fatalf("publishCRL: %v", err)
	}

	got, _, err := gh.GetFile(context.Background(), testRepo, crlPath)
	if err != nil {
		t.Fatalf("GetFile after publish: %v", err)
	}
	if string(got) != "der-v2" {
		t.Errorf("published content = %q, want der-v2", got)
	}
}

// TestPublishCRLRepublishesUnconditionally verifies the CRL is written even when
// the bytes are identical to what is already published. The production CRL is
// non-deterministic per run (fresh thisUpdate/nextUpdate/Number + ECDSA), so
// there is deliberately no "skip when unchanged" branch — daily regeneration
// keeps nextUpdate fresh (spec §3.1). A hypothetical byte-identical input must
// still result in a write (proven here by the SHA advancing).
func TestPublishCRLRepublishesUnconditionally(t *testing.T) {
	gh := fake.New()
	gh.SetFile(testRepo, crlPath, []byte("der-v1"))
	_, before, err := gh.GetFile(context.Background(), testRepo, crlPath)
	if err != nil {
		t.Fatalf("GetFile before publish: %v", err)
	}

	if err := publishCRL(context.Background(), gh, testRepo, []byte("der-v1")); err != nil {
		t.Fatalf("publishCRL: %v", err)
	}

	_, after, err := gh.GetFile(context.Background(), testRepo, crlPath)
	if err != nil {
		t.Fatalf("GetFile after publish: %v", err)
	}
	if after == before {
		t.Errorf("blob SHA unchanged (%q) — publish was skipped, want a fresh write", after)
	}
}

// TestPublishCRLPropagatesConflict verifies that a lost race (PutFile returns
// ErrConflict because another writer landed first) surfaces as an error rather
// than being swallowed — the run fails and self-heals on the next regeneration.
func TestPublishCRLPropagatesConflict(t *testing.T) {
	gh := fake.New()
	gh.SetFile(testRepo, crlPath, []byte("der-v1"))
	gh.FailNextPutWithConflict = true

	if err := publishCRL(context.Background(), gh, testRepo, []byte("der-v2")); err == nil {
		t.Fatal("publishCRL: got nil error on PutFile conflict, want it propagated")
	}
}

// TestRunDiskFallbackWithoutToken verifies the dry-run branch of run(): with no
// GITHUB_TOKEN/GITHUB_REPOSITORY the signed CRL is written to crlPath on disk and
// nothing is published. Runs in an isolated temp dir (t.Chdir) so it never touches
// the committed crl/developers.crl. Uses the local in-memory signer (dry-run only).
func TestRunDiskFallbackWithoutToken(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	// A minimal ledger dir so store.LoadAll succeeds (empty active set → empty CRL).
	if err := os.MkdirAll(ledgerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ledgerJSON := `{"appId":"core","owner":{"origin":"owncloud","repo":"owncloud/core"},"claimedAt":"2026-07-06T00:00:00Z","reserved":true,"certificates":[]}`
	if err := os.WriteFile(filepath.Join(ledgerDir, "core.json"), []byte(ledgerJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	// No GITHUB_TOKEN/GITHUB_REPOSITORY → disk fallback; CRLGEN_ALLOW_LOCAL enables
	// the throwaway in-memory signer. t.Setenv restores the environment afterwards.
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GITHUB_REPOSITORY", "")
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("INTERMEDIATE_KEY_PEM", "")
	t.Setenv("CRLGEN_ALLOW_LOCAL", "1")

	if err := run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	got, err := os.ReadFile(crlPath)
	if err != nil {
		t.Fatalf("expected %s written locally: %v", crlPath, err)
	}
	if len(got) == 0 {
		t.Errorf("%s is empty; want signed CRL DER bytes", crlPath)
	}
}
