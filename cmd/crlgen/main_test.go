package main

import (
	"context"
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

// TestPublishCRLUpdatesWhenChanged verifies a changed CRL is written with the
// current blob SHA (optimistic-concurrency update path).
func TestPublishCRLUpdatesWhenChanged(t *testing.T) {
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

// TestPublishCRLSkipsWhenUnchanged verifies an identical CRL is not written, so
// no spurious commit lands on main.
func TestPublishCRLSkipsWhenUnchanged(t *testing.T) {
	gh := fake.New()
	gh.SetFile(testRepo, crlPath, []byte("der-v1"))
	// A write would mint a new SHA; a conflicting write would error. Force the
	// next Put to fail so any unexpected write is caught.
	gh.FailNextPutWithConflict = true

	if err := publishCRL(context.Background(), gh, testRepo, []byte("der-v1")); err != nil {
		t.Fatalf("publishCRL (unchanged) = %v, want nil (no write)", err)
	}
}
