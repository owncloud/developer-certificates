// Package rest — ProposeChange implements the branch→commit→PR→merge write path
// (bot-writes-via-PR design). The branch commit is created through the Git Data
// API so GitHub signs it under the App identity. We squash-merge, so the commit
// that finally lands on main is a NEW commit signed by GitHub's web-flow key,
// not the App-signed branch commit — main's required_signatures rule accepts the
// web-flow signature just the same (it is a verified GitHub signature), so the
// gate is satisfied either way. Auto-merge is GraphQL-only; to stay stdlib/REST
// we instead poll the commit's check-runs and merge via the REST merge endpoint
// once they are all green — preserving the "merge only on green checks"
// guarantee. (The legacy combined-status endpoint is not used: GitHub Actions
// checks such as validate.yml are check-runs and never appear there.)
package rest

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/owncloud/developer-certificates/internal/ghclient"
)

func (c *Client) ProposeChange(ctx context.Context, change ghclient.ChangeSet) (bool, error) {
	// Concurrency guard BEFORE any write: a stale PrevSHA on any file must yield
	// ErrConflict without creating a branch, blob, or commit (ghclient contract).
	if err := c.checkPrevSHAs(ctx, change.Files); err != nil {
		return false, err
	}
	baseSHA, baseTree, err := c.baseCommit(ctx)
	if err != nil {
		return false, err
	}
	if err := c.ensureBranch(ctx, change.Branch, baseSHA); err != nil {
		return false, err
	}
	treeSHA, err := c.buildTree(ctx, baseTree, change.Files)
	if err != nil {
		return false, err
	}
	commitSHA, err := c.commit(ctx, change.Message, treeSHA, baseSHA)
	if err != nil {
		return false, err
	}
	if err := c.moveBranch(ctx, change.Branch, commitSHA); err != nil {
		return false, err
	}
	prNum, err := c.openOrGetPR(ctx, change)
	if err != nil {
		return false, err
	}
	return c.waitForMerge(ctx, prNum, commitSHA)
}

// checkPrevSHAs enforces the optimistic-concurrency contract of FileChange:
// every file's expected blob SHA (PrevSHA) must match the current state on the
// base branch, else ErrConflict. It reads the base-branch blob SHA via the
// Contents API (getContents maps 404→ErrNotFound). Mirrors the fake's
// checkPrevSHA so both implementations enforce the same rule.
func (c *Client) checkPrevSHAs(ctx context.Context, files []ghclient.FileChange) error {
	for _, f := range files {
		_, curSHA, err := c.getContents(ctx, c.cfg.Repo, f.Path)
		switch {
		case errors.Is(err, ghclient.ErrNotFound):
			if f.PrevSHA != "" {
				return ghclient.ErrConflict // expected an existing file, none present
			}
		case err != nil:
			return err
		case curSHA != f.PrevSHA:
			// present but PrevSHA disagrees (incl. PrevSHA=="" while file exists)
			return ghclient.ErrConflict
		}
	}
	return nil
}

func (c *Client) baseCommit(ctx context.Context) (sha, tree string, err error) {
	var ref struct{ Object struct{ SHA string } `json:"object"` }
	if _, err = c.do(ctx, http.MethodGet,
		fmt.Sprintf("/repos/%s/git/ref/heads/%s", c.cfg.Repo, c.cfg.DefaultBranch), nil, &ref); err != nil {
		return "", "", err
	}
	var commit struct{ Tree struct{ SHA string } `json:"tree"` }
	if _, err = c.do(ctx, http.MethodGet,
		fmt.Sprintf("/repos/%s/git/commits/%s", c.cfg.Repo, ref.Object.SHA), nil, &commit); err != nil {
		return "", "", err
	}
	return ref.Object.SHA, commit.Tree.SHA, nil
}

// ensureBranch creates refs/heads/<branch> at baseSHA, tolerating "already exists".
func (c *Client) ensureBranch(ctx context.Context, branch, baseSHA string) error {
	body := map[string]string{"ref": "refs/heads/" + branch, "sha": baseSHA}
	status, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/git/refs", c.cfg.Repo), body, nil)
	if err != nil && status != http.StatusUnprocessableEntity {
		return err
	}
	return nil // 422 = branch already exists (crash-recovery reuse)
}

func (c *Client) buildTree(ctx context.Context, baseTree string, files []ghclient.FileChange) (string, error) {
	type entry struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
	}
	var entries []entry
	for _, f := range files {
		var blob struct{ SHA string `json:"sha"` }
		b := map[string]string{"content": base64.StdEncoding.EncodeToString(f.Content), "encoding": "base64"}
		if _, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/git/blobs", c.cfg.Repo), b, &blob); err != nil {
			return "", err
		}
		entries = append(entries, entry{Path: f.Path, Mode: "100644", Type: "blob", SHA: blob.SHA})
	}
	var tree struct{ SHA string `json:"sha"` }
	body := map[string]any{"base_tree": baseTree, "tree": entries}
	if _, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/git/trees", c.cfg.Repo), body, &tree); err != nil {
		return "", err
	}
	return tree.SHA, nil
}

func (c *Client) commit(ctx context.Context, message, tree, parent string) (string, error) {
	var out struct{ SHA string `json:"sha"` }
	body := map[string]any{"message": message, "tree": tree, "parents": []string{parent}}
	if _, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/git/commits", c.cfg.Repo), body, &out); err != nil {
		return "", err
	}
	return out.SHA, nil
}

func (c *Client) moveBranch(ctx context.Context, branch, commitSHA string) error {
	body := map[string]any{"sha": commitSHA, "force": true}
	_, err := c.do(ctx, http.MethodPatch,
		fmt.Sprintf("/repos/%s/git/refs/heads/%s", c.cfg.Repo, branch), body, nil)
	return err
}

// openOrGetPR opens a PR for the branch, reusing an existing open one on 422.
func (c *Client) openOrGetPR(ctx context.Context, change ghclient.ChangeSet) (int, error) {
	var pr struct{ Number int `json:"number"` }
	body := map[string]string{"title": change.Message, "body": change.Body, "head": change.Branch, "base": c.cfg.DefaultBranch}
	status, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/pulls", c.cfg.Repo), body, &pr)
	if err == nil {
		return pr.Number, nil
	}
	if status != http.StatusUnprocessableEntity {
		return 0, err
	}
	// A PR already exists for this head; find it.
	var list []struct{ Number int `json:"number"` }
	q := fmt.Sprintf("/repos/%s/pulls?state=open&head=%s:%s", c.cfg.Repo, strings.SplitN(c.cfg.Repo, "/", 2)[0], change.Branch)
	if _, e := c.do(ctx, http.MethodGet, q, nil, &list); e != nil {
		return 0, e
	}
	if len(list) == 0 {
		return 0, fmt.Errorf("rest: PR create returned 422 but no open PR found for %s", change.Branch)
	}
	return list[0].Number, nil
}

// waitForMerge polls commitSHA's check-runs; once every run has completed
// successfully it squash-merges the PR. A required GitHub Actions check like
// validate.yml is a check-run, so the legacy combined-status endpoint (which
// only reports classic statuses) must not be used here. Blocks until merge,
// ctx, or MergeTimeout.
func (c *Client) waitForMerge(ctx context.Context, prNum int, commitSHA string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.MergeTimeout)
	defer cancel()
	tick := time.NewTicker(c.cfg.MergePollInterval)
	defer tick.Stop()
	for {
		var cr struct {
			TotalCount int `json:"total_count"`
			CheckRuns  []struct {
				Status     string `json:"status"`
				Conclusion string `json:"conclusion"`
			} `json:"check_runs"`
		}
		if _, err := c.do(ctx, http.MethodGet,
			fmt.Sprintf("/repos/%s/commits/%s/check-runs?per_page=100", c.cfg.Repo, commitSHA), nil, &cr); err != nil {
			return false, err
		}
		if done, allGreen, failed := evalCheckRuns(cr.TotalCount, cr.CheckRuns); done {
			if failed != "" {
				return false, fmt.Errorf("rest: PR #%d checks failed (conclusion=%s); left open for inspection", prNum, failed)
			}
			if allGreen {
				var merged struct{ Merged bool `json:"merged"` }
				if _, err := c.do(ctx, http.MethodPut,
					fmt.Sprintf("/repos/%s/pulls/%d/merge", c.cfg.Repo, prNum), map[string]string{"merge_method": "squash"}, &merged); err != nil {
					return false, err
				}
				if !merged.Merged {
					return false, fmt.Errorf("rest: PR #%d merge endpoint returned merged=false", prNum)
				}
				return true, nil
			}
		}
		// checks not done yet (or none reported): keep polling
		select {
		case <-ctx.Done():
			return false, fmt.Errorf("rest: PR #%d not merged before timeout: %w", prNum, ctx.Err())
		case <-tick.C:
		}
	}
}

// evalCheckRuns classifies a check-runs response. done is false while any run is
// still queued/in_progress, none were reported yet (total==0), or the page is
// incomplete (len(runs) < total, i.e. a later page we did not fetch could hold a
// failure). When done, failed holds the first blocking conclusion (else ""), and
// allGreen is true only if every run concluded success/neutral/skipped.
//
// The incomplete-page guard makes the merge gate fail closed: this is the sole
// gate on a 0-approval auto-merge into a protected branch, so a green first page
// must never be read as "all green" while an unseen page could be red. Callers
// request per_page=100; anything beyond that keeps polling until timeout.
func evalCheckRuns(total int, runs []struct {
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
}) (done, allGreen bool, failed string) {
	if total == 0 || len(runs) < total {
		return false, false, ""
	}
	allGreen = true
	for _, run := range runs {
		if run.Status != "completed" {
			return false, false, "" // queued/in_progress: not done yet
		}
		switch run.Conclusion {
		case "success", "neutral", "skipped":
			// non-blocking success
		default: // failure, timed_out, cancelled, action_required, ...
			return true, false, run.Conclusion
		}
	}
	return true, allGreen, ""
}
