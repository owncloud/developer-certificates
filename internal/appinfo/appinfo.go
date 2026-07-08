// Package appinfo extracts the app id from an ownCloud app's
// appinfo/info.xml. The issuer bot fetches this file from the target repo's
// default branch (enrollment spec §4 step 4, design §5.2) and reconciles its id
// against the CSR CommonName before issuing a certificate.
//
// This package does no I/O and no canonicalization: it takes the file bytes and
// returns the raw <id> text. The caller runs the extracted value through
// internal/appid.Canonicalize (fold-then-validate), matching the design's
// treatment of filesystem/info.xml-derived ids.
package appinfo

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
)

// ErrNoID is returned when info.xml parses but carries no non-empty <id>.
var ErrNoID = errors.New("appinfo: info.xml has no <id>")

// info mirrors the single element we care about: <info><id>…</id></info>.
// All other elements are ignored by encoding/xml.
type info struct {
	XMLName xml.Name `xml:"info"`
	ID      string   `xml:"id"`
}

// ExtractID parses appinfo/info.xml bytes and returns the raw <id> text with
// surrounding whitespace trimmed. It does not canonicalize or validate the id;
// pass the result to appid.Canonicalize.
func ExtractID(data []byte) (string, error) {
	var doc info
	if err := xml.Unmarshal(data, &doc); err != nil {
		return "", fmt.Errorf("appinfo: parse info.xml: %w", err)
	}
	id := strings.TrimSpace(doc.ID)
	if id == "" {
		return "", ErrNoID
	}
	return id, nil
}
