// Package crl builds the leaf certificate revocation list from the public
// ledger (attestation-and-crl spec §3, design §9). It is pure logic: given the
// parsed ledgers and the current time, it produces the x509.RevocationList
// template the signer then signs. Every ledger certificate with status
// "revoked" becomes one CRL entry whose revocation date is the certificate's
// revokedFrom, which is what enables revoke-from-time verification.
package crl

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/DeepDiver1975/developer-certificates/internal/ledger"
)

// crlValidity is the leaf-CRL freshness window (spec §3.1): nextUpdate is set a
// week out, comfortably longer than the daily regeneration cadence so a missed
// run does not expire the CRL.
const crlValidity = 7 * 24 * time.Hour

// Build assembles the CRL template from all ledgers. Entries are the revoked
// certificates across every ledger, sorted by serial for byte-stable output.
// thisUpdate = now, nextUpdate = now + 7d, Number = now.Unix() (monotonic
// because the ledger-write concurrency lock serializes runs — spec §2).
func Build(ledgers []*ledger.Ledger, now time.Time) (*x509.RevocationList, error) {
	var entries []x509.RevocationListEntry
	for _, l := range ledgers {
		for i := range l.Certificates {
			c := &l.Certificates[i]
			if c.Status != ledger.StatusRevoked {
				continue
			}
			serial, err := parseSerial(c.Serial)
			if err != nil {
				return nil, fmt.Errorf("crl: ledger %s cert %q: %w", l.AppID, c.Serial, err)
			}
			if c.RevokedFrom == nil {
				// ledger.Parse guarantees revoked entries carry revokedFrom; guard anyway.
				return nil, fmt.Errorf("crl: ledger %s cert %q is revoked but has no revokedFrom", l.AppID, c.Serial)
			}
			entries = append(entries, x509.RevocationListEntry{
				SerialNumber:   serial,
				RevocationTime: time.Time(*c.RevokedFrom).UTC(),
			})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].SerialNumber.Cmp(entries[j].SerialNumber) < 0
	})
	return &x509.RevocationList{
		Number:                    big.NewInt(now.Unix()),
		ThisUpdate:                now.UTC(),
		NextUpdate:                now.Add(crlValidity).UTC(),
		RevokedCertificateEntries: entries,
	}, nil
}

// parseSerial converts the ledger's canonical "0x<hex>" serial back to a
// big.Int (signer.FormatSerial is the inverse).
func parseSerial(s string) (*big.Int, error) {
	if len(s) < 3 || s[:2] != "0x" {
		return nil, fmt.Errorf("serial %q is not 0x-prefixed hex", s)
	}
	n, ok := new(big.Int).SetString(s[2:], 16)
	if !ok {
		return nil, fmt.Errorf("serial %q is not valid hex", s)
	}
	return n, nil
}
