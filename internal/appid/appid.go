// Package appid implements the security-critical appId grammar and comparison
// rules from the PKI design (§4.1). Authorization rests entirely on the
// server's CN==appId check, so the ledger's FCFS uniqueness check and the
// server's identity check must treat two strings as "the same appId"
// identically — this package is the single Go implementation of that rule and
// must agree byte-for-byte with the future PHP verifier.
package appid

import (
	"errors"
	"regexp"
)

// Pattern is the canonical legal-appId grammar (design §4.1): lowercase ASCII
// letters, digits, underscore, hyphen and dot; must start with a letter; 3–64
// characters total. This exact string is load-bearing — the issue forms, the
// developer guide, the ledger FCFS check and the server CN==appId check must
// all agree on it, so it must never drift. The conformance harness pins it.
const Pattern = `^[a-z][a-z0-9_.-]{2,63}$`

// ErrInvalid is returned by ValidateStrict and Canonicalize when a string is
// not a legal appId.
var ErrInvalid = errors.New("appid: invalid app id")

// pattern is compiled once; Pattern is anchored, so Valid is an exact match.
var pattern = regexp.MustCompile(Pattern)

// Fold applies ASCII-ONLY case folding: the 26 bytes 'A'..'Z' map to 'a'..'z'
// and every other byte is left untouched. It deliberately does NOT use
// strings.ToLower / unicode.ToLower, which are Unicode/locale-aware and diverge
// across languages (e.g. the Turkish dotted/dotless I) — such divergence
// between the Go and PHP sides would break the anti-impersonation guarantee.
// Non-ASCII bytes pass through unchanged so that a subsequent Valid check still
// rejects them.
func Fold(s string) string {
	b := []byte(s)
	changed := false
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
			changed = true
		}
	}
	if !changed {
		return s
	}
	return string(b)
}

// Valid reports whether s matches Pattern exactly, with no folding applied.
func Valid(s string) bool {
	return pattern.MatchString(s)
}

// ValidateStrict validates a cert-CN-origin appId: exact bytes, no
// normalization. Issuance guarantees the CN is already canonical lowercase, so
// any deviation (e.g. uppercase) is rejected rather than folded. Returns the
// input unchanged on success, or ErrInvalid.
func ValidateStrict(cn string) (string, error) {
	if !Valid(cn) {
		return "", ErrInvalid
	}
	return cn, nil
}

// Canonicalize handles an info.xml- or filesystem-derived appId: it Folds
// first, then validates the folded form, returning the canonical lowercase
// appId suitable for an exact-byte comparison against a cert CN. Folding before
// validation ensures homoglyphs and other illegal characters are still rejected
// (Fold leaves them untouched and Valid then fails).
func Canonicalize(raw string) (string, error) {
	folded := Fold(raw)
	if !Valid(folded) {
		return "", ErrInvalid
	}
	return folded, nil
}
