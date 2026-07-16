// Package rest — ProposeChange implements the branch→commit→PR→merge write path
// (bot-writes-via-PR design). Commits are created through the Git Data API so
// GitHub signs them under the App identity, satisfying main's required_signatures
// rule. Auto-merge is GraphQL-only; to stay stdlib/REST we instead poll the
// combined commit status and merge via the REST merge endpoint once it is
// "success" — preserving the "merge only on green checks" guarantee.
package rest

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/owncloud/developer-certificates/internal/ghclient"
)

func (c *Client) ProposeChange(ctx context.Context, change ghclient.ChangeSet) (bool, error) {
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

// waitForMerge polls the combined status of commitSHA; once "success" it merges
// the PR, then confirms merged. Blocks until merge, ctx, or MergeTimeout.
func (c *Client) waitForMerge(ctx context.Context, prNum int, commitSHA string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.MergeTimeout)
	defer cancel()
	tick := time.NewTicker(c.cfg.MergePollInterval)
	defer tick.Stop()
	for {
		var st struct{ State string `json:"state"` }
		if _, err := c.do(ctx, http.MethodGet,
			fmt.Sprintf("/repos/%s/commits/%s/status", c.cfg.Repo, commitSHA), nil, &st); err != nil {
			return false, err
		}
		switch st.State {
		case "success":
			var merged struct{ Merged bool `json:"merged"` }
			if _, err := c.do(ctx, http.MethodPut,
				fmt.Sprintf("/repos/%s/pulls/%d/merge", c.cfg.Repo, prNum), map[string]string{"merge_method": "squash"}, &merged); err != nil {
				return false, err
			}
			return true, nil
		case "failure", "error":
			return false, fmt.Errorf("rest: PR #%d checks failed (state=%s); left open for inspection", prNum, st.State)
		}
		select {
		case <-ctx.Done():
			return false, fmt.Errorf("rest: PR #%d not merged before timeout: %w", prNum, ctx.Err())
		case <-tick.C:
		}
	}
}
