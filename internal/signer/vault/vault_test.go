package vault

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// TestDecodeTransitSignature covers the non-network plumbing: stripping the
// "vault:vN:" prefix and base64-decoding the ASN.1 signature.
func TestDecodeTransitSignature(t *testing.T) {
	want := []byte{0x30, 0x44, 0x02, 0x20, 0xde, 0xad}
	enc := base64.StdEncoding.EncodeToString(want)
	body := []byte(`{"data":{"signature":"vault:v1:` + enc + `"}}`)

	got, err := decodeTransitSignature(body)
	if err != nil {
		t.Fatalf("decodeTransitSignature: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("decoded = %x, want %x", got, want)
	}
}

func TestDecodeTransitSignatureErrors(t *testing.T) {
	cases := []struct{ name, body string }{
		{"not json", "not json"},
		{"no signature", `{"data":{}}`},
		{"bad base64", `{"data":{"signature":"vault:v1:!!!notbase64!!!"}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := decodeTransitSignature([]byte(c.body)); err == nil {
				t.Errorf("decodeTransitSignature(%s) err = nil, want error", c.name)
			}
		})
	}
}

// TestNewValidation checks required-field validation without touching Vault.
func TestNewValidation(t *testing.T) {
	if _, err := New(Config{}, nil); err == nil {
		t.Error("New with empty config err = nil, want error")
	}
}
