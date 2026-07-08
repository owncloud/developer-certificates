package rest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DeepDiver1975/developer-certificates/internal/ghclient"
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
	if err := c409.PutLedger(context.Background(), "example-app", []byte("{}"), "stale", "msg"); err != ghclient.ErrConflict {
		t.Errorf("PutLedger 409 = %v, want ErrConflict", err)
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
