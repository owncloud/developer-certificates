// Package rest implements ghclient.GitHub against the GitHub REST API using
// only the standard library (the surface is small — issues, comments, labels,
// and repository contents — so a full client library is not warranted).
//
// It enforces the two spec invariants structurally: OwnComments filters to the
// bot's own identity (spec §2), and the ledger read/write pair uses the
// Contents API's blob SHA for optimistic concurrency, surfacing
// ghclient.ErrConflict on a 409 so the pipeline can conflict-retry (spec §2,
// §4 step 10). This adapter is exercised against the live API; the pipeline
// logic itself is tested via the in-memory fake.
package rest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/owncloud/developer-certificates/internal/ghclient"
)

const (
	defaultAPIBase   = "https://api.github.com"
	acceptHeader     = "application/vnd.github+json"
	apiVersion       = "2022-11-28"
	certRequestLabel = "cert-request"
	revocationLabel  = "revocation-request"
)

// Config wires the REST client.
type Config struct {
	Token             string        // GitHub App/bot token
	BotLogin          string        // the bot identity whose comments are trusted (spec §2)
	Repo              string        // codesigning repo, "owner/name", hosting issues + ledger
	APIBase           string        // optional; defaults to https://api.github.com
	HTTPClient        *http.Client  // optional
	DefaultBranch     string        // base branch for PRs; default "main"
	MergePollInterval time.Duration // default 5s
	MergeTimeout      time.Duration // default 5m
}

// Client is a stdlib-based ghclient.GitHub implementation.
type Client struct {
	cfg    Config
	client *http.Client
	base   string
}

var _ ghclient.GitHub = (*Client)(nil)

// New validates the config and returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.Token == "" || cfg.BotLogin == "" || cfg.Repo == "" {
		return nil, fmt.Errorf("rest: Token, BotLogin and Repo are required")
	}
	base := cfg.APIBase
	if base == "" {
		base = defaultAPIBase
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.DefaultBranch == "" {
		cfg.DefaultBranch = "main"
	}
	if cfg.MergePollInterval == 0 {
		cfg.MergePollInterval = 5 * time.Second
	}
	if cfg.MergeTimeout == 0 {
		cfg.MergeTimeout = 5 * time.Minute
	}
	return &Client{cfg: cfg, client: hc, base: strings.TrimRight(base, "/")}, nil
}

// do performs an API request, JSON-encoding body (if non-nil) and decoding a
// 2xx JSON response into out (if non-nil). It returns wantStatus mismatches as
// errors and maps 404→ErrNotFound, 409→ErrConflict for the caller.
func (c *Client) do(ctx context.Context, method, path string, body, out any) (int, error) {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("rest: marshal body: %w", err)
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return 0, fmt.Errorf("rest: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Accept", acceptHeader)
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("rest: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case http.StatusNotFound:
		return resp.StatusCode, ghclient.ErrNotFound
	case http.StatusConflict:
		return resp.StatusCode, ghclient.ErrConflict
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("rest: %s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("rest: decode response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

func (c *Client) ListOpenCertRequests(ctx context.Context) ([]ghclient.Issue, error) {
	return c.listOpenIssues(ctx, certRequestLabel)
}

func (c *Client) ListOpenRevocationRequests(ctx context.Context) ([]ghclient.Issue, error) {
	return c.listOpenIssues(ctx, revocationLabel)
}

// listOpenIssues fetches open issues carrying the given label, skipping PRs
// (the issues endpoint also returns them).
func (c *Client) listOpenIssues(ctx context.Context, label string) ([]ghclient.Issue, error) {
	path := fmt.Sprintf("/repos/%s/issues?state=open&labels=%s&per_page=100", c.cfg.Repo, label)
	var raw []struct {
		Number int    `json:"number"`
		Body   string `json:"body"`
		User   struct {
			Login string `json:"login"`
			ID    int64  `json:"id"`
		} `json:"user"`
		Labels []struct {
			Name string `json:"name"`
		} `json:"labels"`
		PullRequest *struct{} `json:"pull_request"`
	}
	if _, err := c.do(ctx, http.MethodGet, path, nil, &raw); err != nil {
		return nil, err
	}
	var out []ghclient.Issue
	for _, r := range raw {
		if r.PullRequest != nil {
			continue // the issues endpoint also returns PRs; skip them
		}
		labels := make([]string, len(r.Labels))
		for i, l := range r.Labels {
			labels[i] = l.Name
		}
		out = append(out, ghclient.Issue{
			Number: r.Number,
			Body:   r.Body,
			Author: ghclient.Author{Login: r.User.Login, UserID: r.User.ID},
			Labels: labels,
		})
	}
	return out, nil
}

func (c *Client) OwnComments(ctx context.Context, issue int) ([]ghclient.Comment, error) {
	path := fmt.Sprintf("/repos/%s/issues/%d/comments?per_page=100", c.cfg.Repo, issue)
	var raw []struct {
		Body      string    `json:"body"`
		CreatedAt time.Time `json:"created_at"`
		User      struct {
			Login string `json:"login"`
		} `json:"user"`
	}
	if _, err := c.do(ctx, http.MethodGet, path, nil, &raw); err != nil {
		return nil, err
	}
	var out []ghclient.Comment
	for _, r := range raw {
		if r.User.Login != c.cfg.BotLogin {
			continue // spec §2: read only the bot's own comments
		}
		out = append(out, ghclient.Comment{Body: r.Body, CreatedAt: r.CreatedAt})
	}
	return out, nil
}

func (c *Client) PostComment(ctx context.Context, issue int, body string) error {
	path := fmt.Sprintf("/repos/%s/issues/%d/comments", c.cfg.Repo, issue)
	_, err := c.do(ctx, http.MethodPost, path, map[string]string{"body": body}, nil)
	return err
}

func (c *Client) SetLabels(ctx context.Context, issue int, add, remove []string) error {
	for _, name := range remove {
		path := fmt.Sprintf("/repos/%s/issues/%d/labels/%s", c.cfg.Repo, issue, url.PathEscape(name))
		if _, err := c.do(ctx, http.MethodDelete, path, nil, nil); err != nil && err != ghclient.ErrNotFound {
			return err // a label that isn't present is not an error
		}
	}
	if len(add) > 0 {
		path := fmt.Sprintf("/repos/%s/issues/%d/labels", c.cfg.Repo, issue)
		if _, err := c.do(ctx, http.MethodPost, path, map[string][]string{"labels": add}, nil); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) CloseIssue(ctx context.Context, issue int) error {
	path := fmt.Sprintf("/repos/%s/issues/%d", c.cfg.Repo, issue)
	_, err := c.do(ctx, http.MethodPatch, path, map[string]string{"state": "closed"}, nil)
	return err
}

// contentsResponse is the GitHub Contents API payload.
type contentsResponse struct {
	Content string `json:"content"` // base64
	SHA     string `json:"sha"`
}

// getContents fetches a file from repo at its default branch, returning the
// decoded content and its blob SHA.
func (c *Client) getContents(ctx context.Context, repo, path string) ([]byte, string, error) {
	apiPath := fmt.Sprintf("/repos/%s/contents/%s", repo, strings.TrimPrefix(path, "/"))
	var resp contentsResponse
	if _, err := c.do(ctx, http.MethodGet, apiPath, nil, &resp); err != nil {
		return nil, "", err
	}
	// The Contents API base64-encodes with embedded newlines.
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(resp.Content, "\n", ""))
	if err != nil {
		return nil, "", fmt.Errorf("rest: decode contents: %w", err)
	}
	return decoded, resp.SHA, nil
}

func (c *Client) GetFile(ctx context.Context, repo, path string) ([]byte, string, error) {
	return c.getContents(ctx, repo, path)
}

func (c *Client) GetLedger(ctx context.Context, appID string) ([]byte, string, error) {
	return c.getContents(ctx, c.cfg.Repo, "ledger/"+appID+".json")
}

func (c *Client) PutLedger(ctx context.Context, appID string, content []byte, prevSHA, message string) error {
	// runID keeps the branch unique per attempt while remaining deterministic
	// within a run; a crashed run's branch is reused (ensureBranch tolerates 422).
	branch := fmt.Sprintf("bot/ledger-%s", appID)
	_, err := c.ProposeChange(ctx, ghclient.ChangeSet{
		Branch:  branch,
		Message: message,
		Body:    fmt.Sprintf("Automated ledger update for `%s`.", appID),
		Files: []ghclient.FileChange{{
			Path:    "ledger/" + appID + ".json",
			Content: content,
			PrevSHA: prevSHA,
		}},
	})
	return err
}
