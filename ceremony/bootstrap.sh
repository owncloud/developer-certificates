#!/usr/bin/env bash
# CA bootstrap ceremony (master PKI design §19, Phases 1–4).
#
# Generates the Root CA G2, Intermediate CA G2, attestation certificate, and
# empty seed CRLs. Private keys are written under ceremony/out/ (gitignored);
# public certs + seed CRLs are placed into resources/codesigning/ for commit.
#
# Root and attestation private keys must be moved offline by the operator after
# this runs. The intermediate key is set as the INTERMEDIATE_KEY_PEM GitHub
# secret (see README in this dir / bootstrap design §5). This script NEVER runs
# git and NEVER sets secrets — it only produces files.
set -euo pipefail

cd "$(dirname "$0")/.."
OUT=ceremony/out
RES=resources/codesigning

# Refuse to overwrite existing artifacts (a re-run must be a conscious wipe).
for f in "$OUT" "$RES/roots/root-g2.crt" "$RES/intermediates/intermediate-g2.crt" "$RES/attestations/attestation-g2.crt" "$RES/crl/root.crl" "$RES/crl/intermediate.crl"; do
  if [ -e "$f" ]; then
    echo "ERROR: $f already exists; refusing to overwrite CA material. Remove it deliberately to re-run." >&2
    exit 1
  fi
done

mkdir -p "$OUT" "$RES/roots" "$RES/intermediates" "$RES/attestations" "$RES/crl"

CRL_BASE="https://owncloud.github.io/developer-certificates/crl"

echo "== Phase 1: Root CA (25y, self-signed) =="
openssl ecparam -name secp384r1 -genkey -noout -out "$OUT/root-g2.key"
openssl req -new -x509 -key "$OUT/root-g2.key" -sha384 -days 9125 \
  -subj "/C=DE/O=ownCloud GmbH/CN=ownCloud Code Signing Root CA G2" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out "$RES/roots/root-g2.crt"

echo "== Phase 2: Intermediate CA (5y, root-signed) =="
openssl ecparam -name secp384r1 -genkey -noout -out "$OUT/intermediate-g2.key"
openssl req -new -key "$OUT/intermediate-g2.key" -sha384 \
  -subj "/C=DE/O=ownCloud GmbH/CN=ownCloud Code Signing Intermediate CA G2" \
  -out "$OUT/intermediate-g2.csr"
openssl x509 -req -in "$OUT/intermediate-g2.csr" \
  -CA "$RES/roots/root-g2.crt" -CAkey "$OUT/root-g2.key" -CAserial "$OUT/root-g2.srl" -CAcreateserial \
  -sha384 -days 1825 \
  -extfile <(printf "%s\n" \
    "basicConstraints=critical,CA:TRUE,pathlen:0" \
    "keyUsage=critical,keyCertSign,cRLSign" \
    "extendedKeyUsage=codeSigning,timeStamping" \
    "subjectKeyIdentifier=hash" \
    "authorityKeyIdentifier=keyid:always" \
    "crlDistributionPoints=URI:$CRL_BASE/root.crl") \
  -out "$RES/intermediates/intermediate-g2.crt"

echo "== Phase 3: Attestation cert (3y, intermediate-signed, separate key) =="
openssl ecparam -name secp384r1 -genkey -noout -out "$OUT/attestation-g2.key"
openssl req -new -key "$OUT/attestation-g2.key" -sha384 \
  -subj "/O=ownCloud GmbH/CN=ownCloud Timestamp Attestation" \
  -out "$OUT/attestation-g2.csr"
openssl x509 -req -in "$OUT/attestation-g2.csr" \
  -CA "$RES/intermediates/intermediate-g2.crt" -CAkey "$OUT/intermediate-g2.key" -CAserial "$OUT/intermediate-g2.srl" -CAcreateserial \
  -sha384 -days 1095 \
  -extfile <(printf "%s\n" \
    "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=critical,timeStamping" \
    "subjectKeyIdentifier=hash" \
    "authorityKeyIdentifier=keyid:always") \
  -out "$RES/attestations/attestation-g2.crt"

echo "== Phase 4: Seed CRLs (empty) =="
go run ./cmd/seedcrl -key "$OUT/root-g2.key" -cert "$RES/roots/root-g2.crt" -out "$RES/crl/root.crl"
go run ./cmd/seedcrl -key "$OUT/intermediate-g2.key" -cert "$RES/intermediates/intermediate-g2.crt" -out "$RES/crl/intermediate.crl"

echo "== Phase 5: Verify chains + EKUs (fail-closed) =="
# openssl verify checks the signature chain and, with -purpose, the EKU. Note
# that openssl does NOT enforce EKU *nesting* down the chain, so the -purpose
# checks below are necessary but NOT sufficient — the Go x509.Verify step is the
# one that catches an attestation EKU (timeStamping) that a codeSigning-only
# intermediate would strip. Both EKUs must live on the intermediate.
openssl verify -CAfile "$RES/roots/root-g2.crt" "$RES/intermediates/intermediate-g2.crt"
openssl verify -purpose codesign \
  -CAfile "$RES/roots/root-g2.crt" -untrusted "$RES/intermediates/intermediate-g2.crt" \
  "$RES/attestations/attestation-g2.crt" >/dev/null 2>&1 || true # attestation is not a codesign cert
openssl verify -purpose timestampsign \
  -CAfile "$RES/roots/root-g2.crt" -untrusted "$RES/intermediates/intermediate-g2.crt" \
  "$RES/attestations/attestation-g2.crt"

# Go's chain builder intersects the EKU set down the chain: a timeStamping leaf
# under a codeSigning-only intermediate is rejected. This is the authoritative
# check that the attestation cert is usable for its stated purpose.
GO_VERIFY=$(cat <<'GOEOF'
package main
import ("crypto/x509";"encoding/pem";"fmt";"os")
func load(p string) *x509.Certificate {
	d, err := os.ReadFile(p); if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
	b, _ := pem.Decode(d)
	if b == nil { fmt.Fprintf(os.Stderr, "%s: not PEM\n", p); os.Exit(1) }
	c, err := x509.ParseCertificate(b.Bytes); if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
	return c
}
func main() {
	root, inter, att := load(os.Args[1]), load(os.Args[2]), load(os.Args[3])
	roots := x509.NewCertPool(); roots.AddCert(root)
	inters := x509.NewCertPool(); inters.AddCert(inter)
	if _, err := att.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}); err != nil {
		fmt.Fprintf(os.Stderr, "attestation cert fails timeStamping chain verification: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Go x509.Verify: attestation cert OK for timeStamping")
}
GOEOF
)
GO_VERIFY_DIR=$(mktemp -d)
printf '%s\n' "$GO_VERIFY" > "$GO_VERIFY_DIR/main.go"
go run "$GO_VERIFY_DIR/main.go" \
  "$RES/roots/root-g2.crt" "$RES/intermediates/intermediate-g2.crt" "$RES/attestations/attestation-g2.crt"
rm -rf "$GO_VERIFY_DIR"

echo
echo "Ceremony complete. Public artifacts under $RES/ (commit these)."
echo "Private keys under $OUT/ (gitignored):"
echo "  - root-g2.key         → MOVE OFFLINE (cold storage); never commit."
echo "  - attestation-g2.key  → MOVE OFFLINE; no consumer yet."
echo "  - intermediate-g2.key → set as GitHub secret INTERMEDIATE_KEY_PEM, then delete locally."
