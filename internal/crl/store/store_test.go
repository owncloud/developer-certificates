package store

import (
	"os"
	"path/filepath"
	"testing"
)

// validLedger is a minimal schema-valid ledger JSON (matches internal/ledger).
const validLedger = `{
  "appId": "app-a",
  "owner": {"origin": "github", "repo": "org/app-a"},
  "claimedAt": "2026-07-01T00:00:00Z",
  "certificates": []
}
`

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestLoadAllReadsLedgers(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app-a.json", validLedger)
	writeFile(t, dir, "app-b.json", `{"appId":"app-b","owner":{"origin":"github","repo":"org/app-b"},"claimedAt":"2026-07-01T00:00:00Z","certificates":[]}`)

	ls, err := LoadAll(dir)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(ls) != 2 {
		t.Fatalf("loaded %d ledgers, want 2", len(ls))
	}
	// Sorted by path → app-a before app-b.
	if ls[0].AppID != "app-a" || ls[1].AppID != "app-b" {
		t.Errorf("appIds = %q, %q, want app-a, app-b (sorted)", ls[0].AppID, ls[1].AppID)
	}
}

func TestLoadAllMalformedIsError(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app-a.json", validLedger)
	writeFile(t, dir, "broken.json", `{not valid json`)
	if _, err := LoadAll(dir); err == nil {
		t.Error("expected error for malformed ledger, got nil (must fail loud)")
	}
}

func TestLoadAllEmptyDir(t *testing.T) {
	ls, err := LoadAll(t.TempDir())
	if err != nil {
		t.Fatalf("LoadAll on empty dir: %v", err)
	}
	if len(ls) != 0 {
		t.Errorf("loaded %d ledgers from empty dir, want 0", len(ls))
	}
}
