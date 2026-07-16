package main

import (
	"context"
	"testing"

	"github.com/owncloud/developer-certificates/internal/ghclient"
	"github.com/owncloud/developer-certificates/internal/ghclient/fake"
)

func TestPublishCRLProposesChange(t *testing.T) {
	gh := fake.New()
	gh.Repo = "o/r"
	der := []byte("der-bytes")
	if err := publishCRL(context.Background(), gh, "o/r", der); err != nil {
		t.Fatalf("publishCRL = %v", err)
	}
	if len(gh.ProposedChanges) != 1 {
		t.Fatalf("ProposedChanges = %d, want 1", len(gh.ProposedChanges))
	}
	got := gh.ProposedChanges[0]
	if len(got.Files) != 1 || got.Files[0].Path != "crl/developers.crl" {
		t.Errorf("proposed files = %+v, want crl/developers.crl", got.Files)
	}
	if string(got.Files[0].Content) != "der-bytes" {
		t.Errorf("proposed content = %q", got.Files[0].Content)
	}
}

var _ ghclient.GitHub = fake.New()
