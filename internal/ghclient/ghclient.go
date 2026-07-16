// Package ghclient is the GitHub API seam for the issuer bot. The pipeline
// depends only on the GitHub interface here; the real REST implementation and
// an in-memory fake (for tests) both satisfy it, so the orchestrator never
// touches the network directly.
//
// Two invariants from the enrollment spec are encoded in the shape of this
// interface: the bot reads only its own comments (§2 — OwnComments returns only
// bot-authored comments), and all ledger writes are read-modify-write with an
// expected-SHA guard so concurrent writes are detected (§2, §4 step 10).
package ghclient

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by GetFile / GetLedger when the requested path does
// not exist on the default branch.
var ErrNotFound = errors.New("ghclient: not found")

// ErrConflict is returned by PutLedger when the expected SHA no longer matches
// (another write landed first). The caller re-reads and retries (spec §2).
var ErrConflict = errors.New("ghclient: ledger write conflict")

// Issue is a certificate-request issue as the bot sees it.
type Issue struct {
	Number int
	Body   string // raw issue-form body
	Author Author // the authenticated requester
	Labels []string
}

// Author is the account that filed the issue (accountability data, spec §5.4).
type Author struct {
	Login  string
	UserID int64
}

// Comment is a single issue comment. The pipeline only ever consumes
// bot-authored comments (see OwnComments).
type Comment struct {
	Body      string
	CreatedAt time.Time
}

// FileChange is a single file modification in a change set.
type FileChange struct {
	Path    string // repo-relative, e.g. "ledger/app.example.json"
	Content []byte
	PrevSHA string // blob SHA the change is based on ("" = create); mismatch → ErrConflict
}

// ChangeSet is a set of files to commit on a branch and propose as a PR.
type ChangeSet struct {
	Branch  string       // e.g. "bot/ledger-<appId>-<runID>"
	Message string       // commit message + PR title
	Body    string       // PR body
	Files   []FileChange // ≥1 file committed together
}

// GitHub is the subset of the GitHub API the issuer bot needs.
type GitHub interface {
	// ListOpenCertRequests returns the open certificate-request issues to
	// process this poll.
	ListOpenCertRequests(ctx context.Context) ([]Issue, error)

	// ListOpenRevocationRequests returns the open revocation-request issues to
	// process this poll (enrollment spec §5.1).
	ListOpenRevocationRequests(ctx context.Context) ([]Issue, error)

	// OwnComments returns only the comments authored by the bot/App identity on
	// the given issue, oldest first (spec §2).
	OwnComments(ctx context.Context, issue int) ([]Comment, error)

	// PostComment adds a bot comment to the issue.
	PostComment(ctx context.Context, issue int, body string) error

	// SetLabels adds and removes labels on the issue in one step.
	SetLabels(ctx context.Context, issue int, add, remove []string) error

	// CloseIssue closes the issue (terminal states, spec §4 step 11).
	CloseIssue(ctx context.Context, issue int) error

	// GetFile fetches a file from the default branch of repo ("owner/name").
	// Returns ErrNotFound if absent. commitSHA identifies the default-branch
	// commit the content was read at (spec §4 step 4).
	GetFile(ctx context.Context, repo, path string) (content []byte, commitSHA string, err error)

	// GetLedger reads ledger/<appId>.json from the codesigning repo. Returns
	// ErrNotFound if no ledger file exists yet. sha is the blob SHA for the
	// optimistic-concurrency guard on PutLedger.
	GetLedger(ctx context.Context, appID string) (content []byte, sha string, err error)

	// PutLedger writes ledger/<appId>.json. prevSHA is the blob SHA from
	// GetLedger, or "" to create a new file; a mismatch yields ErrConflict
	// (spec §2, §4 step 10).
	PutLedger(ctx context.Context, appID string, content []byte, prevSHA, message string) error

	// ProposeChange commits change.Files on change.Branch, opens a PR, enables
	// auto-merge, and blocks until the PR merges or ctx fires. A stale PrevSHA on
	// any file yields ErrConflict so the caller can re-read and retry (spec §2).
	ProposeChange(ctx context.Context, change ChangeSet) (merged bool, err error)
}
