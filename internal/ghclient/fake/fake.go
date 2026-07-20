// Package fake is an in-memory ghclient.GitHub implementation for tests. It
// keeps the issuer pipeline hermetic — no network, no secrets — while still
// exercising the read-only-own-comments and ledger-conflict semantics of the
// real client.
package fake

import (
	"context"
	"fmt"

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

	// inaccessibleRepos are repos the bot's token cannot see (set via
	// MarkRepoInaccessible): RepoAccessible is false and GetFile 404s for them.
	inaccessibleRepos map[string]bool

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

// MarkRepoInaccessible models a repo the bot's token cannot see: RepoAccessible
// returns false and GetFile returns ErrNotFound for any path under it, mirroring
// GitHub's 404-for-private-repos behaviour.
func (c *Client) MarkRepoInaccessible(repo string) {
	if c.inaccessibleRepos == nil {
		c.inaccessibleRepos = map[string]bool{}
	}
	c.inaccessibleRepos[repo] = true
}

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
	if c.inaccessibleRepos[repo] {
		return nil, "", ghclient.ErrNotFound // GitHub 404s a repo the token can't see
	}
	b, ok := c.Files[fileKey(repo, path)]
	if !ok {
		return nil, "", ghclient.ErrNotFound
	}
	return b.content, b.sha, nil
}

func (c *Client) RepoAccessible(_ context.Context, repo string) (bool, error) {
	return !c.inaccessibleRepos[repo], nil
}

func (c *Client) GetLedger(_ context.Context, appID string) ([]byte, string, error) {
	b, ok := c.Ledgers[appID]
	if !ok {
		return nil, "", ghclient.ErrNotFound
	}
	return b.content, b.sha, nil
}

// checkPrevSHA models the Contents API's optimistic-concurrency rule: creating
// requires no prevSHA, updating requires prevSHA to match the current blob. It
// also consumes the one-shot FailNextPutWithConflict knob so tests can force a
// conflict. Shared by PutLedger and PutFile.
func (c *Client) checkPrevSHA(existing blob, ok bool, prevSHA string) error {
	if c.FailNextPutWithConflict {
		c.FailNextPutWithConflict = false
		return ghclient.ErrConflict
	}
	switch {
	case !ok && prevSHA != "":
		return ghclient.ErrConflict // expected an existing file, none present
	case ok && existing.sha != prevSHA:
		return ghclient.ErrConflict // stale write
	}
	return nil
}

func (c *Client) PutLedger(_ context.Context, appID string, content []byte, prevSHA, _ string) error {
	existing, ok := c.Ledgers[appID]
	if err := c.checkPrevSHA(existing, ok, prevSHA); err != nil {
		return err
	}
	c.Ledgers[appID] = blob{content: content, sha: c.mintSHA()}
	return nil
}

func (c *Client) PutFile(_ context.Context, repo, path string, content []byte, prevSHA, _ string) error {
	existing, ok := c.Files[fileKey(repo, path)]
	if err := c.checkPrevSHA(existing, ok, prevSHA); err != nil {
		return err
	}
	c.Files[fileKey(repo, path)] = blob{content: content, sha: c.mintSHA()}
	return nil
}
