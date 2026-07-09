// Package store reads the ledger files the CRL generator consumes. The CRL bot
// runs with the repository checked out, so it reads ledger/<appId>.json directly
// from the working tree (rather than the GitHub Contents API the issuer/revocation
// bots use for single-appId access) — it needs the whole directory at once.
package store

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/DeepDiver1975/developer-certificates/internal/ledger"
)

// LoadAll reads and parses every <dir>/*.json ledger file, sorted by path for
// deterministic output. A malformed or schema-invalid file is a hard error: the
// CRL must never silently omit a ledger's revocations (spec §3.2). An empty or
// absent set of files yields an empty slice and no error.
func LoadAll(dir string) ([]*ledger.Ledger, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("store: glob %s: %w", dir, err)
	}
	sort.Strings(paths)
	ledgers := make([]*ledger.Ledger, 0, len(paths))
	for _, p := range paths {
		l, err := ledger.Load(p)
		if err != nil {
			return nil, fmt.Errorf("store: load %s: %w", p, err)
		}
		ledgers = append(ledgers, l)
	}
	return ledgers, nil
}
