// Package fake is an in-memory ghclient.GitHub implementation for tests. It
// keeps the issuer pipeline hermetic — no network, no secrets — while still
// exercising the read-only-own-comments and ledger-conflict semantics of the
// real client.
package fake

import (
	"context"
	"fmt"
	"strings"

	"github.com/owncloud/developer-certificates/internal/ghclient"
)

// blob is a stored file with its concurrency SHA.
type blob struct {
	content []byte
	sha     string
}

// Client is an in-memory GitHub double. Construct with New and populate its
// exported fields before use; it is not safe for concurrent use.
type Client struct {
	// Issues are the open certificate requests ListOpenCertRequests returns.
	Issues []ghclient.Issue
	// RevocationIssues are the open revocation requests
	// ListOpenRevocationRequests returns.
	RevocationIssues []ghclient.Issue
	// OwnCommentsByIssue holds the bot's own comments per issue number.
	OwnCommentsByIssue map[int][]ghclient.Comment
	// Files maps "repo\x00path" to file content for GetFile.
	Files map[string]blob
	// Ledgers maps appId to its stored ledger blob.
	Ledgers map[string]blob

	// Recorded side effects, for assertions.
	PostedComments map[int][]string
	LabelsAdded    map[int][]string
	LabelsRemoved  map[int][]string
	Closed         map[int]bool

	// FailNextPutWithConflict, when true, makes the next PutLedger call return
	// ghclient.ErrConflict and resets itself. Lets tests exercise the
	// read-modify-write conflict-retry loop deterministically.
	FailNextPutWithConflict bool

	// ChecksState controls ProposeChange: "" or "green" merges immediately;
	// "pending"/"red" never merge (ProposeChange blocks until ctx fires).
	ChecksState string
	// ProposedChanges records every ProposeChange call for assertions.
	ProposedChanges []ghclient.ChangeSet

	// Repo is the repository name for non-ledger file storage.
	Repo string

	// nextSHA feeds deterministic blob SHAs.
	nextSHA int
}

var _ ghclient.GitHub = (*Client)(nil)

// New returns an empty Client with maps initialized.
func New() *Client {
	return &Client{
		OwnCommentsByIssue: map[int][]ghclient.Comment{},
		Files:              map[string]blob{},
		Ledgers:            map[string]blob{},
		PostedComments:     map[int][]string{},
		LabelsAdded:        map[int][]string{},
		LabelsRemoved:      map[int][]string{},
		Closed:             map[int]bool{},
	}
}

func fileKey(repo, path string) string { return repo + "\x00" + path }

func (c *Client) mintSHA() string {
	c.nextSHA++
	return fmt.Sprintf("sha%d", c.nextSHA)
}

// SetFile stores a file for GetFile to return.
func (c *Client) SetFile(repo, path string, content []byte) {
	c.Files[fileKey(repo, path)] = blob{content: content, sha: c.mintSHA()}
}

// SetLedger seeds a ledger file and returns its SHA (for conflict tests).
func (c *Client) SetLedger(appID string, content []byte) string {
	b := blob{content: content, sha: c.mintSHA()}
	c.Ledgers[appID] = b
	return b.sha
}

func (c *Client) ListOpenCertRequests(context.Context) ([]ghclient.Issue, error) {
	return c.Issues, nil
}

func (c *Client) ListOpenRevocationRequests(context.Context) ([]ghclient.Issue, error) {
	return c.RevocationIssues, nil
}

func (c *Client) OwnComments(_ context.Context, issue int) ([]ghclient.Comment, error) {
	return c.OwnCommentsByIssue[issue], nil
}

func (c *Client) PostComment(_ context.Context, issue int, body string) error {
	c.PostedComments[issue] = append(c.PostedComments[issue], body)
	return nil
}

func (c *Client) SetLabels(_ context.Context, issue int, add, remove []string) error {
	c.LabelsAdded[issue] = append(c.LabelsAdded[issue], add...)
	c.LabelsRemoved[issue] = append(c.LabelsRemoved[issue], remove...)
	return nil
}

func (c *Client) CloseIssue(_ context.Context, issue int) error {
	c.Closed[issue] = true
	return nil
}

func (c *Client) GetFile(_ context.Context, repo, path string) ([]byte, string, error) {
	b, ok := c.Files[fileKey(repo, path)]
	if !ok {
		return nil, "", ghclient.ErrNotFound
	}
	return b.content, b.sha, nil
}

func (c *Client) GetLedger(_ context.Context, appID string) ([]byte, string, error) {
	b, ok := c.Ledgers[appID]
	if !ok {
		return nil, "", ghclient.ErrNotFound
	}
	return b.content, b.sha, nil
}

func (c *Client) PutLedger(_ context.Context, appID string, content []byte, prevSHA, _ string) error {
	if c.FailNextPutWithConflict {
		c.FailNextPutWithConflict = false
		return ghclient.ErrConflict
	}
	existing, ok := c.Ledgers[appID]
	switch {
	case !ok && prevSHA != "":
		return ghclient.ErrConflict // expected an existing file, none present
	case ok && existing.sha != prevSHA:
		return ghclient.ErrConflict // stale write
	}
	c.Ledgers[appID] = blob{content: content, sha: c.mintSHA()}
	return nil
}

// ProposeChange models branch→PR→merge as an atomic apply when checks are
// green. With "pending"/"red" checks it applies nothing and blocks until ctx
// is done, mirroring an unmerged PR.
func (c *Client) ProposeChange(ctx context.Context, change ghclient.ChangeSet) (bool, error) {
	c.ProposedChanges = append(c.ProposedChanges, change)
	// Validate every file's prevSHA against current state first (no partial apply).
	for _, f := range change.Files {
		if err := c.checkPrevSHA(f); err != nil {
			return false, err
		}
	}
	if c.ChecksState != "" && c.ChecksState != "green" {
		<-ctx.Done()
		return false, fmt.Errorf("fake: PR %q not merged: %w", change.Branch, ctx.Err())
	}
	for _, f := range change.Files {
		c.applyFile(f)
	}
	return true, nil
}

// checkPrevSHA reports ErrConflict if f.PrevSHA disagrees with stored state.
// It enforces the guard on EVERY path — ledger files and non-ledger files (e.g.
// the CRL) alike — mirroring the real client's checkPrevSHAs so a CRL-conflict
// regression is catchable in tests.
func (c *Client) checkPrevSHA(f ghclient.FileChange) error {
	sha, present := c.currentSHA(f.Path)
	switch {
	case !present && f.PrevSHA != "":
		return ghclient.ErrConflict
	case present && sha != f.PrevSHA:
		return ghclient.ErrConflict
	}
	return nil
}

// currentSHA returns the stored blob SHA for path (ledger or repo file) and
// whether it exists.
func (c *Client) currentSHA(path string) (sha string, present bool) {
	if appID, ok := ledgerAppID(path); ok {
		b, ok := c.Ledgers[appID]
		return b.sha, ok
	}
	b, ok := c.Files[fileKey(c.Repo, path)]
	return b.sha, ok
}

// applyFile writes f into the appropriate store, minting a fresh SHA.
func (c *Client) applyFile(f ghclient.FileChange) {
	if appID, ok := ledgerAppID(f.Path); ok {
		c.Ledgers[appID] = blob{content: f.Content, sha: c.mintSHA()}
		return
	}
	c.Files[fileKey(c.Repo, f.Path)] = blob{content: f.Content, sha: c.mintSHA()}
}

// ledgerAppID extracts "<appId>" from "ledger/<appId>.json", else ok=false.
func ledgerAppID(path string) (string, bool) {
	const pfx, sfx = "ledger/", ".json"
	if strings.HasPrefix(path, pfx) && strings.HasSuffix(path, sfx) {
		return path[len(pfx) : len(path)-len(sfx)], true
	}
	return "", false
}
