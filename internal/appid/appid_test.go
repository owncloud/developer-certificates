package appid

import (
	"errors"
	"strings"
	"testing"
)

// TestPattern pins the exact grammar string. If this ever changes, the issue
// forms, developer guide, ledger and server verifier must all be updated in
// lockstep — the failure is the reminder.
func TestPattern(t *testing.T) {
	const want = `^[a-z][a-z0-9_.-]{2,63}$`
	if Pattern != want {
		t.Fatalf("appid.Pattern drifted: got %q, want %q", Pattern, want)
	}
}

// TestFoldASCIIOnly verifies Fold maps only 'A'..'Z' and leaves every other
// byte — including non-ASCII — untouched.
func TestFoldASCIIOnly(t *testing.T) {
	cases := []struct{ in, want string }{
		{"ABC", "abc"},
		{"MixedCase123", "mixedcase123"},
		{"already-lower_9", "already-lower_9"},
		{"", ""},
		// Non-ASCII bytes must pass through unchanged; ASCII in the same
		// string is still folded.
		{"café", "café"},
		{"ΩMEGA", "Ωmega"}, // Ω untouched, ASCII "MEGA" folded to "mega"
	}
	for _, c := range cases {
		if got := Fold(c.in); got != c.want {
			t.Errorf("Fold(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestFoldNotUnicodeLower guards against someone swapping the hand-rolled ASCII
// fold for strings.ToLower / unicode-aware folding. The Turkish dotted capital
// İ (U+0130) folds to a multi-byte sequence under Unicode rules but must be
// left untouched by our ASCII-only Fold.
func TestFoldNotUnicodeLower(t *testing.T) {
	const in = "İ" // U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE
	if Fold(in) != in {
		t.Errorf("Fold(%q) altered a non-ASCII byte; must be ASCII-only", in)
	}
	if Fold(in) == strings.ToLower(in) {
		t.Errorf("Fold must not behave like strings.ToLower for %q", in)
	}
}

func TestValidateStrict(t *testing.T) {
	// Strict path applies no folding: uppercase is rejected outright.
	if _, err := ValidateStrict("Example"); !errors.Is(err, ErrInvalid) {
		t.Errorf("ValidateStrict(%q) should reject uppercase, got err=%v", "Example", err)
	}
	got, err := ValidateStrict("example-app")
	if err != nil {
		t.Errorf("ValidateStrict(%q) unexpected err: %v", "example-app", err)
	}
	if got != "example-app" {
		t.Errorf("ValidateStrict returned %q, want unchanged input", got)
	}
}

func TestCanonicalize(t *testing.T) {
	accept := []struct{ in, want string }{
		{"Example", "example"}, // uppercase folded then valid
		{"ExampleApp", "exampleapp"},
		{"abc", "abc"},                                                  // min length 3
		{"a" + strings.Repeat("b", 63), "a" + strings.Repeat("b", 63)}, // 64 chars
		{"my_app-2", "my_app-2"},
		{"com.example.app", "com.example.app"}, // dot is legal (design §4.1)
	}
	for _, c := range accept {
		got, err := Canonicalize(c.in)
		if err != nil {
			t.Errorf("Canonicalize(%q) unexpected err: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Canonicalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	reject := []struct{ name, in string }{
		{"cyrillic homoglyph", "аpp"},              // Cyrillic 'а'
		{"en-dash", "my–app"},                       // U+2013
		{"em-dash", "my—app"},                       // U+2014
		{"minus sign", "my−app"},                    // U+2212
		{"leading digit", "9app"},
		{"leading hyphen", "-app"},
		{"leading underscore", "_app"},
		{"leading dot", ".app"},
		{"length 2 below min", "ab"},
		{"length 65", "a" + strings.Repeat("b", 64)},
		{"empty", ""},
		{"embedded space", "my app"},
		{"slash not allowed", "my/app"},
	}
	for _, c := range reject {
		if _, err := Canonicalize(c.in); !errors.Is(err, ErrInvalid) {
			t.Errorf("Canonicalize(%q) [%s] should be ErrInvalid, got err=%v", c.in, c.name, err)
		}
	}
}
