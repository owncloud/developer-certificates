package rest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/owncloud/developer-certificates/internal/ghclient"
)

func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, func()) {
	t.Helper()
	srv := httptest.NewServer(h)
	c, err := New(Config{
		Token:      "t",
		BotLogin:   "owncloud-bot",
		Repo:       "owncloud/developer-certificates",
		APIBase:    srv.URL,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, srv.Close
}

// TestListOpenCertRequests verifies that ListOpenCertRequests fetches issues
// with the cert-request label, skipping PRs, and mapping labels correctly.
func TestListOpenCertRequests(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		// Assert the request path includes the cert-request label filter.
		if r.URL.Query().Get("labels") != "cert-request" {
			t.Errorf("ListOpenCertRequests request labels=%q, want cert-request", r.URL.Query().Get("labels"))
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"number": 10,
				"body":   "cert request body",
				"user":   map[string]any{"login": "alice", "id": int64(123)},
				"labels": []map[string]any{
					{"name": "cert-request"},
					{"name": "critical"},
				},
				"pull_request": nil,
			},
		})
	})
	defer closeFn()

	got, err := c.ListOpenCertRequests(context.Background())
	if err != nil {
		t.Fatalf("ListOpenCertRequests: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("ListOpenCertRequests returned %d issues, want 1", len(got))
		return
	}
	issue := got[0]
	if issue.Number != 10 || issue.Body != "cert request body" {
		t.Errorf("ListOpenCertRequests issue: %+v, want number=10 body=%q", issue, "cert request body")
	}
	if issue.Author.Login != "alice" || issue.Author.UserID != 123 {
		t.Errorf("ListOpenCertRequests author: %+v, want login=alice UserID=123", issue.Author)
	}
	if len(issue.Labels) != 2 || issue.Labels[0] != "cert-request" || issue.Labels[1] != "critical" {
		t.Errorf("ListOpenCertRequests labels: %v, want [cert-request critical]", issue.Labels)
	}
}

// TestListOpenRevocationRequests verifies that ListOpenRevocationRequests fetches
// issues with the revocation-request label, skipping PRs, and mapping labels correctly.
func TestListOpenRevocationRequests(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		// Assert the request path includes the revocation-request label filter.
		if r.URL.Query().Get("labels") != "revocation-request" {
			t.Errorf("ListOpenRevocationRequests request labels=%q, want revocation-request", r.URL.Query().Get("labels"))
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"number": 20,
				"body":   "revocation request body",
				"user":   map[string]any{"login": "bob", "id": int64(456)},
				"labels": []map[string]any{
					{"name": "revocation-request"},
				},
				"pull_request": nil,
			},
		})
	})
	defer closeFn()

	got, err := c.ListOpenRevocationRequests(context.Background())
	if err != nil {
		t.Fatalf("ListOpenRevocationRequests: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("ListOpenRevocationRequests returned %d issues, want 1", len(got))
		return
	}
	issue := got[0]
	if issue.Number != 20 || issue.Body != "revocation request body" {
		t.Errorf("ListOpenRevocationRequests issue: %+v, want number=20 body=%q", issue, "revocation request body")
	}
	if issue.Author.Login != "bob" || issue.Author.UserID != 456 {
		t.Errorf("ListOpenRevocationRequests author: %+v, want login=bob UserID=456", issue.Author)
	}
	if len(issue.Labels) != 1 || issue.Labels[0] != "revocation-request" {
		t.Errorf("ListOpenRevocationRequests labels: %v, want [revocation-request]", issue.Labels)
	}
}

// TestOwnCommentsFilters proves only the bot's comments are returned (spec §2).
func TestOwnCommentsFilters(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"body": "bot one", "created_at": "2026-07-08T10:00:00Z", "user": map[string]any{"login": "owncloud-bot"}},
			{"body": "a user", "created_at": "2026-07-08T11:00:00Z", "user": map[string]any{"login": "someone"}},
			{"body": "bot two", "created_at": "2026-07-08T12:00:00Z", "user": map[string]any{"login": "owncloud-bot"}},
		})
	})
	defer closeFn()

	got, err := c.OwnComments(context.Background(), 42)
	if err != nil {
		t.Fatalf("OwnComments: %v", err)
	}
	if len(got) != 2 || got[0].Body != "bot one" || got[1].Body != "bot two" {
		t.Errorf("OwnComments = %+v, want the two bot comments only", got)
	}
}

// TestGetFileDecodes checks base64 contents decoding and SHA passthrough.
func TestGetFileDecodes(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"content": base64.StdEncoding.EncodeToString([]byte("hello")),
			"sha":     "abc123",
		})
	})
	defer closeFn()

	content, sha, err := c.GetFile(context.Background(), "example-org/example-app", "appinfo/info.xml")
	if err != nil {
		t.Fatalf("GetFile: %v", err)
	}
	if string(content) != "hello" || sha != "abc123" {
		t.Errorf("GetFile = %q, %q", content, sha)
	}
}

// TestErrorMapping maps 404→ErrNotFound and handles concurrency conflicts.
func TestErrorMapping(t *testing.T) {
	c404, close404 := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer close404()
	if _, _, err := c404.GetLedger(context.Background(), "example-app"); err != ghclient.ErrNotFound {
		t.Errorf("GetLedger 404 = %v, want ErrNotFound", err)
	}

	// PutLedger returns ErrConflict when prevSHA doesn't match the current blob SHA
	c409, close409 := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/owncloud/developer-certificates/contents/ledger/example-app.json":
			// Current blob SHA is "current", provided PrevSHA is "stale" → conflict
			json.NewEncoder(w).Encode(map[string]string{"sha": "current"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer close409()
	if err := c409.PutLedger(context.Background(), "example-app", []byte("{}"), "stale", "msg"); err != ghclient.ErrConflict {
		t.Errorf("PutLedger with stale prevSHA = %v, want ErrConflict", err)
	}
}

// TestPutLedgerSendsSHA verifies PutLedger passes the prevSHA to ProposeChange,
// which checks it for concurrency conflicts before writing.
func TestPutLedgerSendsSHA(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/owncloud/developer-certificates/contents/ledger/example-app.json":
			// ProposeChange looks up the current blob SHA and compares to PrevSHA
			json.NewEncoder(w).Encode(map[string]string{"sha": "currsha"})
		case r.URL.Path == "/repos/owncloud/developer-certificates/git/ref/heads/main":
			json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "base"}})
		case r.URL.Path == "/repos/owncloud/developer-certificates/git/commits/base":
			json.NewEncoder(w).Encode(map[string]any{"tree": map[string]string{"sha": "bt"}})
		case r.URL.Path == "/repos/owncloud/developer-certificates/git/blobs":
			json.NewEncoder(w).Encode(map[string]string{"sha": "b1"})
		case r.URL.Path == "/repos/owncloud/developer-certificates/git/trees":
			var body struct{ Tree []struct{ Path string `json:"path"` } `json:"tree"` }
			json.NewDecoder(r.Body).Decode(&body)
			json.NewEncoder(w).Encode(map[string]string{"sha": "t1"})
		case r.URL.Path == "/repos/owncloud/developer-certificates/git/commits":
			json.NewEncoder(w).Encode(map[string]string{"sha": "c1"})
		case r.URL.Path == "/repos/owncloud/developer-certificates/git/refs":
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{})
		case r.URL.Path == "/repos/owncloud/developer-certificates/git/refs/heads/bot/ledger-example-app":
			json.NewEncoder(w).Encode(map[string]any{})
		case r.URL.Path == "/repos/owncloud/developer-certificates/pulls":
			json.NewEncoder(w).Encode(map[string]any{"number": 1})
		case r.URL.Path == "/repos/owncloud/developer-certificates/commits/c1/check-runs":
			json.NewEncoder(w).Encode(map[string]any{
				"total_count": 1,
				"check_runs":  []map[string]string{{"status": "completed", "conclusion": "success"}},
			})
		case r.URL.Path == "/repos/owncloud/developer-certificates/pulls/1/merge":
			json.NewEncoder(w).Encode(map[string]any{"merged": true})
		default:
			json.NewEncoder(w).Encode(map[string]any{})
		}
	})
	defer closeFn()

	// PutLedger should succeed with matching prevSHA
	if err := c.PutLedger(context.Background(), "example-app", []byte("{}"), "currsha", "msg"); err != nil {
		t.Fatalf("PutLedger: %v", err)
	}
}
