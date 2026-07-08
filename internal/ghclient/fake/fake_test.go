package fake

import (
	"context"
	"errors"
	"testing"

	"github.com/DeepDiver1975/developer-certificates/internal/ghclient"
)

func TestGetFileNotFound(t *testing.T) {
	c := New()
	if _, _, err := c.GetFile(context.Background(), "example-org/example-app", "/nope"); !errors.Is(err, ghclient.ErrNotFound) {
		t.Errorf("GetFile absent = %v, want ErrNotFound", err)
	}
	c.SetFile("example-org/example-app", "/f.txt", []byte("hi"))
	got, sha, err := c.GetFile(context.Background(), "example-org/example-app", "/f.txt")
	if err != nil || string(got) != "hi" || sha == "" {
		t.Errorf("GetFile present = %q, %q, %v", got, sha, err)
	}
}

// TestPutLedgerConcurrency exercises the optimistic-concurrency guard that the
// real client uses for conflict-retry (spec §2).
func TestPutLedgerConcurrency(t *testing.T) {
	ctx := context.Background()
	c := New()

	// Create-new requires empty prevSHA.
	if err := c.PutLedger(ctx, "example-app", []byte("v1"), "nonexistent", "msg"); !errors.Is(err, ghclient.ErrConflict) {
		t.Errorf("PutLedger create with stale prevSHA = %v, want ErrConflict", err)
	}
	if err := c.PutLedger(ctx, "example-app", []byte("v1"), "", "create"); err != nil {
		t.Fatalf("PutLedger create = %v", err)
	}

	_, sha, err := c.GetLedger(ctx, "example-app")
	if err != nil {
		t.Fatalf("GetLedger = %v", err)
	}

	// A write with a stale SHA conflicts; with the current SHA it succeeds.
	if err := c.PutLedger(ctx, "example-app", []byte("v2"), "stale", "msg"); !errors.Is(err, ghclient.ErrConflict) {
		t.Errorf("PutLedger stale = %v, want ErrConflict", err)
	}
	if err := c.PutLedger(ctx, "example-app", []byte("v2"), sha, "update"); err != nil {
		t.Errorf("PutLedger current SHA = %v, want nil", err)
	}
}

func TestSideEffectsRecorded(t *testing.T) {
	ctx := context.Background()
	c := New()
	_ = c.PostComment(ctx, 7, "hello")
	_ = c.SetLabels(ctx, 7, []string{"issued"}, []string{"awaiting-challenge"})
	_ = c.CloseIssue(ctx, 7)

	if got := c.PostedComments[7]; len(got) != 1 || got[0] != "hello" {
		t.Errorf("PostedComments = %v", got)
	}
	if got := c.LabelsAdded[7]; len(got) != 1 || got[0] != "issued" {
		t.Errorf("LabelsAdded = %v", got)
	}
	if got := c.LabelsRemoved[7]; len(got) != 1 || got[0] != "awaiting-challenge" {
		t.Errorf("LabelsRemoved = %v", got)
	}
	if !c.Closed[7] {
		t.Error("Closed[7] = false, want true")
	}
}
