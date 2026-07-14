// Command seedcrl mints a single empty, signed CRL from a key+cert PEM pair.
// The CA bootstrap ceremony (design §19 Phase 4) uses it to produce the seed
// root and intermediate CRLs. Unlike cmd/crlgen (which builds the leaf CRL from
// the ledger via a signer.Signer), this reads a raw key file directly, because
// during the offline ceremony the root/intermediate keys are plain PEM files on
// disk, not yet a configured signer backend.
package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {
	keyPath := flag.String("key", "", "PEM EC private key of the CRL issuer")
	certPath := flag.String("cert", "", "PEM certificate of the CRL issuer")
	outPath := flag.String("out", "", "output path for the DER CRL")
	flag.Parse()
	if *keyPath == "" || *certPath == "" || *outPath == "" {
		log.Fatal("seedcrl: -key, -cert and -out are all required")
	}
	if err := run(*keyPath, *certPath, *outPath, time.Now().UTC()); err != nil {
		log.Fatalf("seedcrl: %v", err)
	}
}

// crlValidity is the seed CRL nextUpdate window. The bots republish long before
// this; the seed just needs a valid, non-expired window at ship time.
const crlValidity = 7 * 24 * time.Hour

func run(keyPath, certPath, outPath string, now time.Time) error {
	key, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	cert, err := loadCert(certPath)
	if err != nil {
		return err
	}
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(crlValidity),
	}
	der, err := x509.CreateRevocationList(nil, tmpl, cert, key.(crypto.Signer))
	if err != nil {
		return fmt.Errorf("create crl: %w", err)
	}
	if err := os.WriteFile(outPath, der, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	return nil
}

func loadKey(path string) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("key %q is not PEM", path)
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("key %q: unexpected PEM block %q", path, block.Type)
	}
}

func loadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("cert %q is not a PEM CERTIFICATE", path)
	}
	return x509.ParseCertificate(block.Bytes)
}
