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
	"testing"
	"time"
)

func writePEM(t *testing.T, dir, name, typ string, der []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func TestRunProducesVerifiableEmptyCRL(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3},
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)

	keyPath := writePEM(t, dir, "ca.key", "PRIVATE KEY", pkcs8)
	certPath := writePEM(t, dir, "ca.crt", "CERTIFICATE", certDER)
	outPath := filepath.Join(dir, "seed.crl")

	if err := run(keyPath, certPath, outPath, time.Now()); err != nil {
		t.Fatalf("run: %v", err)
	}
	der, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	if len(rl.RevokedCertificateEntries) != 0 {
		t.Errorf("seed CRL has %d entries, want 0", len(rl.RevokedCertificateEntries))
	}
	if err := rl.CheckSignatureFrom(cert); err != nil {
		t.Errorf("seed CRL does not verify against CA: %v", err)
	}
}
