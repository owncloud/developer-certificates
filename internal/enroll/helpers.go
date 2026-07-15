package enroll

import (
	"context"
	"fmt"

	"github.com/owncloud/developer-certificates/internal/ghclient"
)

// terminal posts an explanatory comment and sets a terminal label (spec §9:
// every terminal state has a bot comment). Non-`issued` terminal states leave
// the issue open so a developer can fix the problem and the bot re-enters on
// the next poll or issue edit.
func terminal(ctx context.Context, d Deps, issue ghclient.Issue, label, comment string) error {
	if err := d.GH.PostComment(ctx, issue.Number, comment); err != nil {
		return fmt.Errorf("enroll: post %s comment: %w", label, err)
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
