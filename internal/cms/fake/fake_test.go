package fake

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/DeepDiver1975/developer-certificates/internal/cms"
)

func TestFakeReturnsResult(t *testing.T) {
	want := &cms.Result{SignerCert: &x509.Certificate{}, Content: []byte("revoke")}
	v := New()
	v.Result = want
	got, err := v.Verify(context.Background(), []byte("ignored"))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != want {
		t.Errorf("Verify result = %p, want %p", got, want)
	}
}

func TestFakeReturnsError(t *testing.T) {
	v := New()
	v.Err = cms.ErrInvalidCMS
	if _, err := v.Verify(context.Background(), nil); !errors.Is(err, cms.ErrInvalidCMS) {
		t.Errorf("Verify err = %v, want ErrInvalidCMS", err)
	}
}
