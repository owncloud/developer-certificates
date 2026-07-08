// Package challenge implements the repo-control proof of the issuer bot
// (enrollment spec §4 steps 6–7, design §5.3). The bot generates a random
// nonce, posts it in a bot comment with instructions to commit it to a
// well-known path on the target repo's default branch, and later re-reads the
// nonce from its own comment to verify the committed file matches.
//
// The nonce is carried inside the bot comment in a stable, machine-parseable
// marker so a later poll can recover it without parsing arbitrary user text
// (spec §2: read only the bot's own comments). All functions here are pure;
// randomness and the clock are injected so the pipeline stays deterministic in
// tests.
package challenge

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// FilePath is the fixed well-known location the developer commits the nonce to,
// on the target repo's default branch (design §5.3). This exact string is
// load-bearing: it appears in the developer guide and is pinned by the
// conformance harness, so it must never drift.
const FilePath = "/.well-known/owncloud-codesigning-challenge.txt"

// Validity is how long a posted challenge remains acceptable, measured from the
// bot comment's creation timestamp (spec §4 step 6: 72h).
const Validity = 72 * time.Hour

// nonceBytes is the nonce size (256 bits, spec §4 step 6).
const nonceBytes = 32

// marker fences the nonce inside the bot comment so it round-trips exactly. It
// is an HTML comment so it renders invisibly in the GitHub UI.
const (
	markerPrefix = "<!-- owncloud-codesigning-challenge: "
	markerSuffix = " -->"
)

// markerRE recovers the hex nonce from a bot comment body.
var markerRE = regexp.MustCompile(`<!-- owncloud-codesigning-challenge: ([0-9a-f]{64}) -->`)

// Generate returns a fresh random 256-bit nonce as a 64-character lowercase hex
// string. Pass crypto/rand.Reader in production; a deterministic reader in
// tests.
func Generate(r io.Reader) (string, error) {
	if r == nil {
		r = rand.Reader
	}
	b := make([]byte, nonceBytes)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", fmt.Errorf("challenge: read random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// CommentBody renders the bot comment that carries the nonce and the developer
// instructions. The nonce is embedded in a hidden marker (recoverable via
// ParseNonce) and also shown in the fenced block the developer copies.
func CommentBody(nonce string) string {
	var b strings.Builder
	b.WriteString(markerPrefix)
	b.WriteString(nonce)
	b.WriteString(markerSuffix)
	b.WriteString("\n\n")
	b.WriteString("To prove you control this repository, commit a file containing ")
	b.WriteString("exactly the value below to your repository's **default branch** at:\n\n")
	b.WriteString("```text\n")
	b.WriteString(FilePath)
	b.WriteString("\n```\n\n")
	b.WriteString("File contents:\n\n```text\n")
	b.WriteString(nonce)
	b.WriteString("\n```\n\n")
	b.WriteString("You have 72 hours. The bot re-checks periodically; you may delete the file afterwards.\n")
	return b.String()
}

// ParseNonce recovers the nonce from a bot comment body produced by
// CommentBody. ok is false if no marker is present.
func ParseNonce(body string) (nonce string, ok bool) {
	m := markerRE.FindStringSubmatch(body)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// Expired reports whether a challenge posted at commentCreatedAt is past its
// 72h window at now.
func Expired(commentCreatedAt, now time.Time) bool {
	return now.Sub(commentCreatedAt) > Validity
}

// Match reports whether the fetched file contents satisfy the stored nonce,
// using a constant-time comparison. The fetched contents are trimmed of
// surrounding whitespace (a trailing newline is expected and tolerated).
func Match(stored, fetched string) bool {
	got := strings.TrimSpace(fetched)
	return subtle.ConstantTimeCompare([]byte(stored), []byte(got)) == 1
}
