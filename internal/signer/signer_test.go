package signer

import (
	"math/big"
	"testing"
)

func TestFormatSerial(t *testing.T) {
	cases := []struct {
		in   *big.Int
		want string
	}{
		{big.NewInt(0), "0x0"},
		{big.NewInt(26), "0x1a"},
		{big.NewInt(255), "0xff"},
		{new(big.Int).SetBytes([]byte{0x1a, 0x2b, 0x3c}), "0x1a2b3c"},
	}
	for _, c := range cases {
		if got := FormatSerial(c.in); got != c.want {
			t.Errorf("FormatSerial(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFingerprint(t *testing.T) {
	// SHA-256 of the empty input, as a stable known-answer check.
	got := Fingerprint(nil)
	const want = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("Fingerprint(nil) = %q, want %q", got, want)
	}
}
