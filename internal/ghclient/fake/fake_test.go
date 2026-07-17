package fake

import (
	"context"
	"errors"
	"testing"

	"github.com/owncloud/developer-certificates/internal/ghclient"
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

func TestProposeChangeGreenApplies(t *testing.T) {
	ctx := context.Background()
	c := New()
	sha := c.SetLedger("app.example", []byte("v1"))

	merged, err := c.ProposeChange(ctx, ghclient.ChangeSet{
		Branch:  "bot/ledger-app.example-1",
		Message: "ledger: update app.example",
		Files: []ghclient.FileChange{
			{Path: "ledger/app.example.json", Content: []byte("v2"), PrevSHA: sha},
		},
	})
	if err != nil || !merged {
		t.Fatalf("ProposeChange green = merged %v, err %v; want merged true, nil", merged, err)
	}
	got, _, _ := c.GetLedger(ctx, "app.example")
	if string(got) != "v2" {
		t.Errorf("ledger content = %q, want v2", got)
	}
	if len(c.ProposedChanges) != 1 || c.ProposedChanges[0].Branch != "bot/ledger-app.example-1" {
		t.Errorf("ProposedChanges = %+v", c.ProposedChanges)
	}
}

func TestProposeChangeStalePrevSHAConflicts(t *testing.T) {
	ctx := context.Background()
	c := New()
	c.SetLedger("app.example", []byte("v1"))
	_, err := c.ProposeChange(ctx, ghclient.ChangeSet{
		Branch: "b", Message: "m",
		Files: []ghclient.FileChange{{Path: "ledger/app.example.json", Content: []byte("v2"), PrevSHA: "stale"}},
	})
	if !errors.Is(err, ghclient.ErrConflict) {
		t.Errorf("ProposeChange stale = %v, want ErrConflict", err)
	}
}

// TestProposeChangeCRLPrevSHAConflicts proves the fake enforces PrevSHA on
// non-ledger (CRL) paths too, matching the real client — so a CRL-conflict
// regression is catchable here and not silently waved through.
func TestProposeChangeCRLPrevSHAConflicts(t *testing.T) {
	ctx := context.Background()
	c := New()
	c.Repo = "o/r"
	c.SetFile("o/r", "crl/developers.crl", []byte("crl-v1"))

	// Stale PrevSHA on the CRL path must conflict.
	_, err := c.ProposeChange(ctx, ghclient.ChangeSet{
		Branch: "bot/crl", Message: "crl",
		Files: []ghclient.FileChange{{Path: "crl/developers.crl", Content: []byte("crl-v2"), PrevSHA: "stale"}},
	})
	if !errors.Is(err, ghclient.ErrConflict) {
		t.Errorf("ProposeChange CRL stale = %v, want ErrConflict", err)
	}

	// Current SHA succeeds.
	_, sha, _ := c.GetFile(ctx, "o/r", "crl/developers.crl")
	if _, err := c.ProposeChange(ctx, ghclient.ChangeSet{
		Branch: "bot/crl", Message: "crl",
		Files: []ghclient.FileChange{{Path: "crl/developers.crl", Content: []byte("crl-v2"), PrevSHA: sha}},
	}); err != nil {
		t.Errorf("ProposeChange CRL current SHA = %v, want nil", err)
	}
}

func TestProposeChangePendingTimesOut(t *testing.T) {
	c := New()
	c.ChecksState = "pending"
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // deadline already passed
	merged, err := c.ProposeChange(ctx, ghclient.ChangeSet{
		Branch: "b", Message: "m",
		Files: []ghclient.FileChange{{Path: "ledger/app.example.json", Content: []byte("v2")}},
	})
	if merged || err == nil {
		t.Errorf("ProposeChange pending+cancelled = merged %v, err %v; want false, non-nil", merged, err)
	}
}
