// Package fake is an in-memory cms.Verifier for hermetic pipeline tests: it
// returns a preset result or a preset error, with no openssl and no crypto.
package fake

import (
	"context"

	"github.com/DeepDiver1975/developer-certificates/internal/cms"
)

// Verifier is a cms.Verifier double. Set Result for a success or Err for a
// failure (e.g. cms.ErrInvalidCMS); if both are set, Err wins.
type Verifier struct {
	Result *cms.Result
	Err    error
}

var _ cms.Verifier = (*Verifier)(nil)

// New returns an empty Verifier.
func New() *Verifier { return &Verifier{} }

// Verify returns the preset error if set, otherwise the preset result.
func (v *Verifier) Verify(context.Context, []byte) (*cms.Result, error) {
	if v.Err != nil {
		return nil, v.Err
	}
	return v.Result, nil
}
