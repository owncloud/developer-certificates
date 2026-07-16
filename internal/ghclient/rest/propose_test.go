package rest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/owncloud/developer-certificates/internal/ghclient"
)

// TestProposeChangeHappyPath drives the full branch→commit→PR→merge path against
// an in-process GitHub Git-Data/PR server. The merge gate reads the check-runs
// endpoint (not the legacy combined status), so the fake serves a completed,
// successful check-run.
func TestProposeChangeHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/repos/o/r/contents/"):
			// no PrevSHA on the file → expect create → base file absent
			http.Error(w, "not found", http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, "/git/ref/heads/main"):
			json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "basecommit"}})
		case strings.HasSuffix(r.URL.Path, "/git/commits/basecommit"):
			json.NewEncoder(w).Encode(map[string]any{"tree": map[string]string{"sha": "basetree"}})
		case strings.HasSuffix(r.URL.Path, "/git/blobs"):
			json.NewEncoder(w).Encode(map[string]string{"sha": "blob1"})
		case strings.HasSuffix(r.URL.Path, "/git/trees"):
			json.NewEncoder(w).Encode(map[string]string{"sha": "tree1"})
		case strings.HasSuffix(r.URL.Path, "/git/commits"):
			json.NewEncoder(w).Encode(map[string]string{"sha": "commit1"})
		case strings.HasSuffix(r.URL.Path, "/git/refs"): // create branch
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{})
		case strings.Contains(r.URL.Path, "/git/refs/heads/"): // patch branch
			json.NewEncoder(w).Encode(map[string]any{})
		case strings.HasSuffix(r.URL.Path, "/pulls") && r.Method == http.MethodPost:
			json.NewEncoder(w).Encode(map[string]any{"number": 42})
		case strings.Contains(r.URL.Path, "/commits/commit1/check-runs"):
			json.NewEncoder(w).Encode(map[string]any{
				"total_count": 1,
				"check_runs":  []map[string]string{{"status": "completed", "conclusion": "success"}},
			})
		case strings.HasSuffix(r.URL.Path, "/pulls/42/merge") && r.Method == http.MethodPut:
			json.NewEncoder(w).Encode(map[string]any{"merged": true})
		default:
			t.Logf("unhandled %s %s", r.Method, r.URL.Path)
			json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
	defer srv.Close()

	c, _ := New(Config{
		Token: "t", BotLogin: "bot", Repo: "o/r", APIBase: srv.URL,
		MergePollInterval: time.Millisecond, MergeTimeout: time.Second,
	})
	merged, err := c.ProposeChange(context.Background(), ghclient.ChangeSet{
		Branch: "bot/x", Message: "m",
		Files: []ghclient.FileChange{{Path: "crl/developers.crl", Content: []byte("der")}},
	})
	if err != nil || !merged {
		t.Fatalf("ProposeChange = merged %v, err %v; want true, nil", merged, err)
	}
}

// TestProposeChangeChecksFailed asserts a failed check-run conclusion aborts the
// merge: ProposeChange returns an error and the PUT /merge endpoint is never hit.
func TestProposeChangeChecksFailed(t *testing.T) {
	var mergeCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/repos/o/r/contents/"):
			http.Error(w, "not found", http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, "/git/ref/heads/main"):
			json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "basecommit"}})
		case strings.HasSuffix(r.URL.Path, "/git/commits/basecommit"):
			json.NewEncoder(w).Encode(map[string]any{"tree": map[string]string{"sha": "basetree"}})
		case strings.HasSuffix(r.URL.Path, "/git/blobs"):
			json.NewEncoder(w).Encode(map[string]string{"sha": "blob1"})
		case strings.HasSuffix(r.URL.Path, "/git/trees"):
			json.NewEncoder(w).Encode(map[string]string{"sha": "tree1"})
		case strings.HasSuffix(r.URL.Path, "/git/commits"):
			json.NewEncoder(w).Encode(map[string]string{"sha": "commit1"})
		case strings.HasSuffix(r.URL.Path, "/git/refs"):
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{})
		case strings.Contains(r.URL.Path, "/git/refs/heads/"):
			json.NewEncoder(w).Encode(map[string]any{})
		case strings.HasSuffix(r.URL.Path, "/pulls") && r.Method == http.MethodPost:
			json.NewEncoder(w).Encode(map[string]any{"number": 42})
		case strings.Contains(r.URL.Path, "/commits/commit1/check-runs"):
			json.NewEncoder(w).Encode(map[string]any{
				"total_count": 1,
				"check_runs":  []map[string]string{{"status": "completed", "conclusion": "failure"}},
			})
		case strings.HasSuffix(r.URL.Path, "/pulls/42/merge") && r.Method == http.MethodPut:
			mergeCalled = true
			json.NewEncoder(w).Encode(map[string]any{"merged": true})
		default:
			t.Logf("unhandled %s %s", r.Method, r.URL.Path)
			json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
	defer srv.Close()

	c, _ := New(Config{
		Token: "t", BotLogin: "bot", Repo: "o/r", APIBase: srv.URL,
		MergePollInterval: time.Millisecond, MergeTimeout: time.Second,
	})
	merged, err := c.ProposeChange(context.Background(), ghclient.ChangeSet{
		Branch: "bot/x", Message: "m",
		Files: []ghclient.FileChange{{Path: "crl/developers.crl", Content: []byte("der")}},
	})
	if err == nil || merged {
		t.Fatalf("ProposeChange = merged %v, err %v; want false, error", merged, err)
	}
	if mergeCalled {
		t.Fatalf("merge endpoint was called despite failing checks")
	}
}

// TestProposeChangeChecksPendingTimeout asserts that when check-runs stay
// in_progress the call times out with an error and never merges.
func TestProposeChangeChecksPendingTimeout(t *testing.T) {
	var mergeCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/repos/o/r/contents/"):
			http.Error(w, "not found", http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, "/git/ref/heads/main"):
			json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "basecommit"}})
		case strings.HasSuffix(r.URL.Path, "/git/commits/basecommit"):
			json.NewEncoder(w).Encode(map[string]any{"tree": map[string]string{"sha": "basetree"}})
		case strings.HasSuffix(r.URL.Path, "/git/blobs"):
			json.NewEncoder(w).Encode(map[string]string{"sha": "blob1"})
		case strings.HasSuffix(r.URL.Path, "/git/trees"):
			json.NewEncoder(w).Encode(map[string]string{"sha": "tree1"})
		case strings.HasSuffix(r.URL.Path, "/git/commits"):
			json.NewEncoder(w).Encode(map[string]string{"sha": "commit1"})
		case strings.HasSuffix(r.URL.Path, "/git/refs"):
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{})
		case strings.Contains(r.URL.Path, "/git/refs/heads/"):
			json.NewEncoder(w).Encode(map[string]any{})
		case strings.HasSuffix(r.URL.Path, "/pulls") && r.Method == http.MethodPost:
			json.NewEncoder(w).Encode(map[string]any{"number": 42})
		case strings.Contains(r.URL.Path, "/commits/commit1/check-runs"):
			json.NewEncoder(w).Encode(map[string]any{
				"total_count": 1,
				"check_runs":  []map[string]string{{"status": "in_progress", "conclusion": ""}},
			})
		case strings.HasSuffix(r.URL.Path, "/pulls/42/merge") && r.Method == http.MethodPut:
			mergeCalled = true
			json.NewEncoder(w).Encode(map[string]any{"merged": true})
		default:
			t.Logf("unhandled %s %s", r.Method, r.URL.Path)
			json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
	defer srv.Close()

	c, _ := New(Config{
		Token: "t", BotLogin: "bot", Repo: "o/r", APIBase: srv.URL,
		MergePollInterval: time.Millisecond, MergeTimeout: 20 * time.Millisecond,
	})
	merged, err := c.ProposeChange(context.Background(), ghclient.ChangeSet{
		Branch: "bot/x", Message: "m",
		Files: []ghclient.FileChange{{Path: "crl/developers.crl", Content: []byte("der")}},
	})
	if err == nil || merged {
		t.Fatalf("ProposeChange = merged %v, err %v; want false, timeout error", merged, err)
	}
	// The deadline may fire between polls (wrapped "not merged before timeout")
	// or during an in-flight check-runs GET; both wrap context.DeadlineExceeded.
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v; want a context-deadline timeout error", err)
	}
	if mergeCalled {
		t.Fatalf("merge endpoint was called despite pending checks")
	}
}

// TestProposeChangeStalePrevSHA asserts the pre-write concurrency guard: when the
// base-branch blob SHA differs from FileChange.PrevSHA, ProposeChange returns
// ErrConflict and creates no branch/blob/commit.
func TestProposeChangeStalePrevSHA(t *testing.T) {
	var wrote bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/repos/o/r/contents/"):
			json.NewEncoder(w).Encode(map[string]string{"content": "", "sha": "currentsha"})
		case strings.HasSuffix(r.URL.Path, "/git/blobs"),
			strings.HasSuffix(r.URL.Path, "/git/trees"),
			strings.HasSuffix(r.URL.Path, "/git/commits"),
			strings.HasSuffix(r.URL.Path, "/git/refs"):
			wrote = true
			json.NewEncoder(w).Encode(map[string]any{})
		default:
			t.Logf("unhandled %s %s", r.Method, r.URL.Path)
			json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
	defer srv.Close()

	c, _ := New(Config{
		Token: "t", BotLogin: "bot", Repo: "o/r", APIBase: srv.URL,
		MergePollInterval: time.Millisecond, MergeTimeout: time.Second,
	})
	merged, err := c.ProposeChange(context.Background(), ghclient.ChangeSet{
		Branch: "bot/x", Message: "m",
		Files: []ghclient.FileChange{{Path: "ledger/app.example.json", Content: []byte("v2"), PrevSHA: "stalesha"}},
	})
	if !errors.Is(err, ghclient.ErrConflict) {
		t.Fatalf("ProposeChange = merged %v, err %v; want ErrConflict", merged, err)
	}
	if wrote {
		t.Fatalf("a write endpoint was called despite the PrevSHA conflict")
	}
}

// TestProposeChangeBranchExistsReuse asserts a 422 on POST /git/refs (branch
// already exists, crash-recovery reuse) is tolerated and the flow proceeds to
// merge.
func TestProposeChangeBranchExistsReuse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/repos/o/r/contents/"):
			http.Error(w, "not found", http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, "/git/ref/heads/main"):
			json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "basecommit"}})
		case strings.HasSuffix(r.URL.Path, "/git/commits/basecommit"):
			json.NewEncoder(w).Encode(map[string]any{"tree": map[string]string{"sha": "basetree"}})
		case strings.HasSuffix(r.URL.Path, "/git/blobs"):
			json.NewEncoder(w).Encode(map[string]string{"sha": "blob1"})
		case strings.HasSuffix(r.URL.Path, "/git/trees"):
			json.NewEncoder(w).Encode(map[string]string{"sha": "tree1"})
		case strings.HasSuffix(r.URL.Path, "/git/commits"):
			json.NewEncoder(w).Encode(map[string]string{"sha": "commit1"})
		case strings.HasSuffix(r.URL.Path, "/git/refs"): // create branch → already exists
			w.WriteHeader(http.StatusUnprocessableEntity)
			json.NewEncoder(w).Encode(map[string]any{"message": "Reference already exists"})
		case strings.Contains(r.URL.Path, "/git/refs/heads/"):
			json.NewEncoder(w).Encode(map[string]any{})
		case strings.HasSuffix(r.URL.Path, "/pulls") && r.Method == http.MethodPost:
			json.NewEncoder(w).Encode(map[string]any{"number": 42})
		case strings.Contains(r.URL.Path, "/commits/commit1/check-runs"):
			json.NewEncoder(w).Encode(map[string]any{
				"total_count": 1,
				"check_runs":  []map[string]string{{"status": "completed", "conclusion": "success"}},
			})
		case strings.HasSuffix(r.URL.Path, "/pulls/42/merge") && r.Method == http.MethodPut:
			json.NewEncoder(w).Encode(map[string]any{"merged": true})
		default:
			t.Logf("unhandled %s %s", r.Method, r.URL.Path)
			json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
	defer srv.Close()

	c, _ := New(Config{
		Token: "t", BotLogin: "bot", Repo: "o/r", APIBase: srv.URL,
		MergePollInterval: time.Millisecond, MergeTimeout: time.Second,
	})
	merged, err := c.ProposeChange(context.Background(), ghclient.ChangeSet{
		Branch: "bot/x", Message: "m",
		Files: []ghclient.FileChange{{Path: "crl/developers.crl", Content: []byte("der")}},
	})
	if err != nil || !merged {
		t.Fatalf("ProposeChange = merged %v, err %v; want true, nil", merged, err)
	}
}
