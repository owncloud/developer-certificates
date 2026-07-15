package revoke

import (
	"context"
	"fmt"

	"github.com/owncloud/developer-certificates/internal/ghclient"
)

// terminal posts an explanatory comment and sets a terminal label (spec §9:
// every terminal state has a bot comment). The `invalid` state leaves the issue
// open so the developer can correct and re-file; the caller closes the issue
// only for the successful `revoked` state.
func terminal(ctx context.Context, d Deps, issue ghclient.Issue, label, comment string) error {
	if err := d.GH.PostComment(ctx, issue.Number, comment); err != nil {
		return fmt.Errorf("revoke: post %s comment: %w", label, err)
	}
	return d.GH.SetLabels(ctx, issue.Number, []string{label}, nil)
}

// hasLabel reports whether labels contains want.
func hasLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}
