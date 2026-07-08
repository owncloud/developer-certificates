package appinfo

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/DeepDiver1975/developer-certificates/internal/appid"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// TestExtractID reads the <id> from a representative info.xml and confirms the
// extracted value canonicalizes cleanly — the shape the issuer bot relies on
// when reconciling against the CSR CommonName (spec §4 step 5).
func TestExtractID(t *testing.T) {
	id, err := ExtractID(readFixture(t, "info.xml"))
	if err != nil {
		t.Fatalf("ExtractID unexpected err: %v", err)
	}
	if id != "example-app" {
		t.Fatalf("ExtractID = %q, want %q", id, "example-app")
	}
	if canon, err := appid.Canonicalize(id); err != nil || canon != "example-app" {
		t.Errorf("appid.Canonicalize(%q) = %q, %v; want %q, nil", id, canon, err, "example-app")
	}
}

// TestExtractIDTrimsAndFolds confirms surrounding whitespace is trimmed and
// that a mixed-case id survives extraction unchanged (folding is the caller's
// job, done here to prove the values line up).
func TestExtractIDTrimsAndFolds(t *testing.T) {
	const doc = "<info><id>\n  Example-App  \n</id></info>"
	id, err := ExtractID([]byte(doc))
	if err != nil {
		t.Fatalf("ExtractID unexpected err: %v", err)
	}
	if id != "Example-App" {
		t.Fatalf("ExtractID = %q, want trimmed %q", id, "Example-App")
	}
	if canon, err := appid.Canonicalize(id); err != nil || canon != "example-app" {
		t.Errorf("appid.Canonicalize(%q) = %q, %v; want %q, nil", id, canon, err, "example-app")
	}
}

func TestExtractIDNoID(t *testing.T) {
	if _, err := ExtractID(readFixture(t, "no-id.xml")); !errors.Is(err, ErrNoID) {
		t.Errorf("ExtractID(no-id) err = %v, want ErrNoID", err)
	}
	// A whitespace-only id is treated as absent.
	if _, err := ExtractID([]byte("<info><id>   </id></info>")); !errors.Is(err, ErrNoID) {
		t.Errorf("ExtractID(blank id) err = %v, want ErrNoID", err)
	}
}

func TestExtractIDMalformed(t *testing.T) {
	_, err := ExtractID(readFixture(t, "malformed.xml"))
	if err == nil || errors.Is(err, ErrNoID) {
		t.Errorf("ExtractID(malformed) err = %v, want a parse error", err)
	}
}
