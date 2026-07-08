// Package vault implements signer.Signer by signing leaf certificates through
// HashiCorp Vault's Transit secrets engine (design §19). The intermediate CA
// private key lives in Vault and never enters the runner: x509.CreateCertificate
// hands the certificate's SHA-384 digest to a crypto.Signer adapter, which POSTs
// it to Transit's sign endpoint and returns the ASN.1 ECDSA signature Vault
// produces.
//
// This is the production path. It cannot be exercised end to end until the CA
// bootstrap ceremony (design §19) has created the intermediate and loaded its
// key into Vault, so the live round-trip test is environment-gated; the
// digest/DER-assembly plumbing that does not need Vault is covered directly.
package vault

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Config wires the Vault Transit signer.
type Config struct {
	Address    string        // Vault base URL, e.g. https://vault.example:8200
	Token      string        // Vault token (from the runner's OIDC/secret)
	KeyName    string        // Transit key name for the intermediate
	HTTPClient *http.Client  // optional; defaults to a client with Timeout
	Timeout    time.Duration // optional; default 30s when HTTPClient is nil
}

// Signer issues leaves under a Vault-held intermediate key.
type Signer struct {
	cfg    Config
	client *http.Client
	issuer *x509.Certificate
}

// New returns a Vault Transit signer. issuer is the intermediate CA certificate
// (public, distributed with the repo); its public key must correspond to the
// Transit key named in cfg.
func New(cfg Config, issuer *x509.Certificate) (*Signer, error) {
	if cfg.Address == "" || cfg.Token == "" || cfg.KeyName == "" {
		return nil, fmt.Errorf("vault: Address, Token and KeyName are required")
	}
	if issuer == nil {
		return nil, fmt.Errorf("vault: nil issuer certificate")
	}
	client := cfg.HTTPClient
	if client == nil {
		timeout := cfg.Timeout
		if timeout == 0 {
			timeout = 30 * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}
	return &Signer{cfg: cfg, client: client, issuer: issuer}, nil
}

// IssuerCertificate returns the intermediate CA certificate.
func (s *Signer) IssuerCertificate() *x509.Certificate { return s.issuer }

// Sign builds and signs the leaf via x509.CreateCertificate, delegating the
// actual signature to Vault through the crypto.Signer adapter.
func (s *Signer) Sign(ctx context.Context, template *x509.Certificate, subjectPub any) ([]byte, error) {
	cs := &cryptoSigner{ctx: ctx, s: s, pub: s.issuer.PublicKey}
	// x509.CreateCertificate reads no randomness for ECDSA when the signer is a
	// crypto.Signer, but a non-nil reader is still required.
	der, err := x509.CreateCertificate(zeroReader{}, template, s.issuer, subjectPub, cs)
	if err != nil {
		return nil, fmt.Errorf("vault: create certificate: %w", err)
	}
	return der, nil
}

// cryptoSigner adapts Vault Transit to crypto.Signer so x509 can drive it.
type cryptoSigner struct {
	ctx context.Context
	s   *Signer
	pub crypto.PublicKey
}

func (c *cryptoSigner) Public() crypto.PublicKey { return c.pub }

// Sign sends the prehashed digest to Vault Transit and returns the ASN.1 ECDSA
// signature. x509 passes the SHA-384 digest of the TBS certificate as digest;
// opts.HashFunc() is crypto.SHA384.
func (c *cryptoSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA384 {
		return nil, fmt.Errorf("vault: unexpected hash %v, want SHA-384", opts.HashFunc())
	}
	return c.s.signDigest(c.ctx, digest)
}

// signDigest performs the Transit sign call and decodes the signature bytes.
func (s *Signer) signDigest(ctx context.Context, digest []byte) ([]byte, error) {
	reqBody, err := json.Marshal(map[string]any{
		"input":          base64.StdEncoding.EncodeToString(digest),
		"prehashed":      true,
		"hash_algorithm": "sha2-384",
		// asn1 marshaling yields the ECDSA-Sig-Value DER x509 expects.
		"marshaling_algorithm": "asn1",
	})
	if err != nil {
		return nil, fmt.Errorf("vault: marshal request: %w", err)
	}

	url := strings.TrimRight(s.cfg.Address, "/") + "/v1/transit/sign/" + s.cfg.KeyName
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("vault: build request: %w", err)
	}
	httpReq.Header.Set("X-Vault-Token", s.cfg.Token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("vault: sign request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault: sign returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	return decodeTransitSignature(body)
}

// decodeTransitSignature extracts the raw ASN.1 signature from a Transit sign
// response. The signature field has the form "vault:v1:<base64>".
func decodeTransitSignature(body []byte) ([]byte, error) {
	var parsed struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("vault: decode response: %w", err)
	}
	sig := parsed.Data.Signature
	if sig == "" {
		return nil, fmt.Errorf("vault: response had no signature")
	}
	// Strip the "vault:vN:" version prefix.
	if i := strings.LastIndex(sig, ":"); i >= 0 {
		sig = sig[i+1:]
	}
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil, fmt.Errorf("vault: decode signature base64: %w", err)
	}
	return raw, nil
}

// zeroReader is a non-nil io.Reader for x509.CreateCertificate; ECDSA signing
// via a crypto.Signer does not consume it.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
