package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/owncloud/developer-certificates/internal/ghclient"
)

// fakeGitHub is a minimal in-process GitHub Git-Data/PR server: it records the
// commit path and reports the PR merged on the second poll.
func TestProposeChangeHappyPath(t *testing.T) {
	var polls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
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
		case strings.Contains(r.URL.Path, "/commits/commit1/status"):
			json.NewEncoder(w).Encode(map[string]string{"state": "success"})
		case strings.HasSuffix(r.URL.Path, "/pulls/42/merge") && r.Method == http.MethodPut:
			json.NewEncoder(w).Encode(map[string]any{"merged": true})
		case strings.HasSuffix(r.URL.Path, "/pulls/42"):
			polls++
			json.NewEncoder(w).Encode(map[string]any{"number": 42, "mergeable": true, "merged": polls >= 1})
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
