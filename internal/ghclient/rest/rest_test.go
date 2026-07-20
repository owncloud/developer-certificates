package rest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestErrorMapping maps 404→ErrNotFound and 409→ErrConflict.
func TestErrorMapping(t *testing.T) {
	c404, close404 := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer close404()
	if _, _, err := c404.GetLedger(context.Background(), "example-app"); err != ghclient.ErrNotFound {
		t.Errorf("GetLedger 404 = %v, want ErrNotFound", err)
	}

	c409, close409 := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	})
	defer close409()
	if err := c409.PutLedger(context.Background(), "example-app", []byte("{}"), "stale", "msg"); !errors.Is(err, ghclient.ErrConflict) {
		t.Errorf("PutLedger 409 = %v, want ErrConflict", err)
	}

	// A 409 with a body (e.g. a ruleset rejection, not an SHA conflict) must
	// still satisfy errors.Is(ErrConflict) so the retry loop keeps working,
	// while surfacing GitHub's reason instead of swallowing it.
	const reason = "required status check \"validate\" is expected"
	c409body, close409body := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(reason))
	})
	defer close409body()
	err := c409body.PutLedger(context.Background(), "example-app", []byte("{}"), "", "msg")
	if !errors.Is(err, ghclient.ErrConflict) {
		t.Errorf("PutLedger 409-with-body = %v, want errors.Is ErrConflict", err)
	}
	if err == nil || !strings.Contains(err.Error(), reason) {
		t.Errorf("PutLedger 409-with-body = %v, want it to surface %q", err, reason)
	}
}

// TestRepoAccessible maps GET /repos/{repo} 2xx→true and 404→false (GitHub
// hides private repos the token cannot see as 404).
func TestRepoAccessible(t *testing.T) {
	cOK, closeOK := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/owncloud/files_classifier" {
			t.Errorf("RepoAccessible path = %q, want /repos/owncloud/files_classifier", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"full_name":"owncloud/files_classifier"}`))
	})
	defer closeOK()
	if ok, err := cOK.RepoAccessible(context.Background(), "owncloud/files_classifier"); err != nil || !ok {
		t.Errorf("RepoAccessible(accessible) = %v, %v; want true, nil", ok, err)
	}

	c404, close404 := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer close404()
	if ok, err := c404.RepoAccessible(context.Background(), "owncloud/private-app"); err != nil || ok {
		t.Errorf("RepoAccessible(404) = %v, %v; want false, nil", ok, err)
	}
}

// TestPutLedgerSendsSHA verifies the update path includes the prevSHA (required
// by the Contents API to update rather than create).
func TestPutLedgerSendsSHA(t *testing.T) {
	var sawSHA string
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		sawSHA = body["sha"]
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	})
	defer closeFn()

	if err := c.PutLedger(context.Background(), "example-app", []byte("{}"), "blob99", "msg"); err != nil {
		t.Fatalf("PutLedger: %v", err)
	}
	if sawSHA != "blob99" {
		t.Errorf("PutLedger sent sha=%q, want blob99", sawSHA)
	}
}
