package challenge

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// TestGenerateNonce checks the nonce is 256 bits of lowercase hex and that a
// deterministic reader produces the expected value.
func TestGenerateNonce(t *testing.T) {
	n, err := Generate(bytes.NewReader(bytes.Repeat([]byte{0xab}, nonceBytes)))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if want := strings.Repeat("ab", nonceBytes); n != want {
		t.Fatalf("Generate = %q, want %q", n, want)
	}
}

func TestGenerateShortReader(t *testing.T) {
	if _, err := Generate(bytes.NewReader([]byte{0x01})); err == nil {
		t.Error("Generate with short reader: err = nil, want error")
	}
}

// TestCommentRoundTrip proves the nonce embedded in a bot comment is recovered
// exactly by ParseNonce (spec §2: the bot reads state from its own comment).
func TestCommentRoundTrip(t *testing.T) {
	nonce, err := Generate(bytes.NewReader(bytes.Repeat([]byte{0x3c}, nonceBytes)))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	body := CommentBody(nonce)
	if !strings.Contains(body, FilePath) {
		t.Errorf("CommentBody missing the challenge file path")
	}
	got, ok := ParseNonce(body)
	if !ok {
		t.Fatalf("ParseNonce found no marker in the bot comment")
	}
	if got != nonce {
		t.Errorf("ParseNonce = %q, want %q", got, nonce)
	}
}

func TestParseNonceAbsent(t *testing.T) {
	if _, ok := ParseNonce("a user comment with no marker"); ok {
		t.Error("ParseNonce reported a nonce in unrelated text")
	}
}

// TestExpired checks the 72h boundary from the comment timestamp.
func TestExpired(t *testing.T) {
	posted := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"just posted", posted, false},
		{"within window", posted.Add(71 * time.Hour), false},
		{"exactly 72h", posted.Add(Validity), false},
		{"one second past", posted.Add(Validity + time.Second), true},
	}
	for _, c := range cases {
		if got := Expired(posted, c.now); got != c.want {
			t.Errorf("Expired(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestMatch covers whitespace tolerance and rejection of a wrong value.
func TestMatch(t *testing.T) {
	const nonce = "deadbeef"
	if !Match(nonce, nonce+"\n") {
		t.Error("Match should tolerate a trailing newline")
	}
	if !Match(nonce, "  "+nonce+"  \n") {
		t.Error("Match should trim surrounding whitespace")
	}
	if Match(nonce, "cafebabe") {
		t.Error("Match accepted a wrong nonce")
	}
	if Match(nonce, "") {
		t.Error("Match accepted empty contents")
	}
}
