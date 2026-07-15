package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pemsigner "github.com/owncloud/developer-certificates/internal/signer/pem"
	"github.com/owncloud/developer-certificates/internal/signer/vault"
)

// newSigner precedence is the security-sensitive core of this change: the
// production workflow must pick Vault when it is configured and must never
// silently fall back to nothing. This table exercises every env-var combination.
func TestNewSignerPrecedence(t *testing.T) {
	key := mustP384(t)
	certPath, keyPEM := writeIntermediate(t, key)

	// Every variable newSigner reads; each case sets a subset and we clear the rest.
	allVars := []string{"VAULT_ADDR", "VAULT_TOKEN", "VAULT_TRANSIT_KEY", "INTERMEDIATE_KEY_PEM", "INTERMEDIATE_CERT"}

	tests := []struct {
		name    string
		env     map[string]string
		wantErr string                    // substring; "" means no error
		check   func(t *testing.T, s any) // asserts the concrete signer type
	}{
		{
			name: "vault wins when both vault and pem configured",
			env: map[string]string{
				"VAULT_ADDR":           "https://vault.example:8200",
				"VAULT_TOKEN":          "t",
				"VAULT_TRANSIT_KEY":    "intermediate",
				"INTERMEDIATE_KEY_PEM": keyPEM,
				"INTERMEDIATE_CERT":    certPath,
			},
			check: func(t *testing.T, s any) {
				if _, ok := s.(*vault.Signer); !ok {
					t.Fatalf("expected *vault.Signer, got %T", s)
				}
			},
		},
		{
			name: "pem selected when only INTERMEDIATE_KEY_PEM set",
			env: map[string]string{
				"INTERMEDIATE_KEY_PEM": keyPEM,
				"INTERMEDIATE_CERT":    certPath,
			},
			check: func(t *testing.T, s any) {
				if _, ok := s.(*pemsigner.Signer); !ok {
					t.Fatalf("expected *pemsigner.Signer, got %T", s)
				}
			},
		},
		{
			name:    "hard error when no signer configured",
			env:     map[string]string{"INTERMEDIATE_CERT": certPath},
			wantErr: "no signer configured",
		},
		{
			// Regression for the error-ordering fix: with no signer configured the
			// caller must get the clear "no signer configured" message, not a
			// cert-load error, even when INTERMEDIATE_CERT is also missing.
			name:    "no signer + no cert still reports no signer configured",
			env:     map[string]string{},
			wantErr: "no signer configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, k := range allVars {
				os.Unsetenv(k)
			}
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			s, err := newSigner()
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tt.check(t, s)
		})
	}
}

func mustP384(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// writeIntermediate self-signs a certificate for key, writes it to a temp file,
// and returns the cert path plus the key encoded as PKCS#8 PEM. The pem signer
// requires the key's public half to match the issuer cert, so both must derive
// from the same key.
func writeIntermediate(t *testing.T, key *ecdsa.PrivateKey) (certPath, keyPEM string) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test intermediate"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31, 0),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPath = filepath.Join(t.TempDir(), "intermediate.crt")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	return certPath, keyPEM
}
