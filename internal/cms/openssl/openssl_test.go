package openssl

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/DeepDiver1975/developer-certificates/internal/cms"
)

// requireOpenSSL skips the test when the openssl CLI is unavailable, so the
// suite stays green on machines without it while still running for real in CI
// (openssl is present on ubuntu-latest).
func requireOpenSSL(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not on PATH; skipping CMS round-trip")
	}
}

// makeLeaf writes an EC P-384 key + a self-signed leaf (CN=appID) to dir and
// returns their file paths. The revocation flow only needs the embedded cert to
// match the ledger, so a self-signed leaf is sufficient for the round-trip.
func makeLeaf(t *testing.T, dir, appID string) (keyPath, certPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big1(),
		Subject:      pkix.Name{CommonName: appID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPath = filepath.Join(dir, "app.key")
	certPath = filepath.Join(dir, "app.crt")
	writePEM(t, keyPath, "EC PRIVATE KEY", keyDER)
	writePEM(t, certPath, "CERTIFICATE", der)
	return keyPath, certPath
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func big1() *big.Int { return big.NewInt(1) }

// signRequest runs the documented developer command (spec §5.1) to produce a
// PEM CMS revocation request over the literal "revoke".
func signRequest(t *testing.T, keyPath, certPath string) []byte {
	t.Helper()
	cmd := exec.Command("openssl", "cms", "-sign",
		"-signer", certPath, "-inkey", keyPath,
		"-outform", "PEM", "-nodetach")
	cmd.Stdin = bytes.NewReader([]byte("revoke"))
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("openssl cms -sign: %v: %s", err, errb.String())
	}
	return out.Bytes()
}

func TestVerifyRoundTrip(t *testing.T) {
	requireOpenSSL(t)
	dir := t.TempDir()
	keyPath, certPath := makeLeaf(t, dir, "example-app")
	req := signRequest(t, keyPath, certPath)

	res, err := New().Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := res.SignerCert.Subject.CommonName; got != "example-app" {
		t.Errorf("signer CN = %q, want example-app", got)
	}
	if !bytes.Equal(res.Content, []byte("revoke")) {
		t.Errorf("content = %q, want revoke", res.Content)
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	requireOpenSSL(t)
	_, err := New().Verify(context.Background(), []byte("-----BEGIN CMS-----\nnot base64\n-----END CMS-----\n"))
	if !errors.Is(err, cms.ErrInvalidCMS) {
		t.Errorf("Verify err = %v, want ErrInvalidCMS", err)
	}
}

func TestVerifyRejectsTampered(t *testing.T) {
	requireOpenSSL(t)
	dir := t.TempDir()
	keyPath, certPath := makeLeaf(t, dir, "example-app")
	req := signRequest(t, keyPath, certPath)
	// Corrupt a byte inside the base64 body (line 2 onward) to break the signature.
	tampered := bytes.Replace(req, []byte("MII"), []byte("MIA"), 1)
	if bytes.Equal(tampered, req) {
		t.Skip("could not locate a byte to tamper; skipping")
	}
	if _, err := New().Verify(context.Background(), tampered); !errors.Is(err, cms.ErrInvalidCMS) {
		t.Errorf("Verify err = %v, want ErrInvalidCMS on tampered input", err)
	}
}
