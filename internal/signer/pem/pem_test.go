package pem

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// makeIntermediate builds a self-signed P-384 intermediate CA and returns its
// cert plus its private key encoded as PKCS#8 PEM.
func makeIntermediate(t *testing.T) (*x509.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	return cert, keyPEM
}

func TestNewAndSignCRL(t *testing.T) {
	cert, keyPEM := makeIntermediate(t)
	s, err := New(Config{KeyPEM: keyPEM, Issuer: cert})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.IssuerCertificate() != cert {
		t.Error("IssuerCertificate did not return the configured issuer")
	}
	tmpl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour)}
	der, err := s.SignCRL(context.Background(), tmpl)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	if err := rl.CheckSignatureFrom(cert); err != nil {
		t.Errorf("CRL signature does not verify against issuer: %v", err)
	}
}

func TestNewRejectsMismatch(t *testing.T) {
	cert, _ := makeIntermediate(t)  // cert from one key...
	_, otherPEM := makeIntermediate(t) // ...key from another
	if _, err := New(Config{KeyPEM: otherPEM, Issuer: cert}); err == nil {
		t.Error("New with mismatched key/cert err = nil, want error")
	}
}

func TestNewRejectsBadInput(t *testing.T) {
	cert, keyPEM := makeIntermediate(t)
	cases := []struct {
		name string
		cfg  Config
	}{
		{"empty key", Config{KeyPEM: "", Issuer: cert}},
		{"nil issuer", Config{KeyPEM: keyPEM, Issuer: nil}},
		{"garbage pem", Config{KeyPEM: "not a pem", Issuer: cert}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := New(c.cfg); err == nil {
				t.Errorf("New(%s) err = nil, want error", c.name)
			}
		})
	}
}

func TestNewRejectsNonP384(t *testing.T) {
	cert, _ := makeIntermediate(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	if _, err := New(Config{KeyPEM: keyPEM, Issuer: cert}); err == nil {
		t.Error("New with P-256 key err = nil, want error (design §3 requires P-384)")
	}
}
