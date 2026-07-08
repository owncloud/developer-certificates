// Package ledger models the public issuance ledger (design §6): one JSON file
// per appId under ledger/<appId>.json. The ledger is the source of truth for
// appId ownership (FCFS) and revocation state, and its git history is the
// immutable transparency/audit log. This package provides the schema types,
// deterministic (byte-stable) serialization, and the FCFS decision logic that
// the enrollment/revocation workflows build on.
package ledger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/DeepDiver1975/developer-certificates/internal/appid"
)

// Origin identifies the authority that proved control over the namespace.
type Origin string

const (
	OriginGitHub   Origin = "github"   // automated: identity + nonce-in-repo challenge
	OriginGitLab   Origin = "gitlab"   // documented future extension (design §4)
	OriginPartner  Origin = "partner"  // commercial closed-source (design §11)
	OriginOwnCloud Origin = "owncloud" // first-party reservations (design §15)
)

// Status is the lifecycle state of a certificate in the ledger.
type Status string

const (
	StatusActive  Status = "active"
	StatusRevoked Status = "revoked"
)

// Owner is the account/org that owns the target repository (not the requester).
type Owner struct {
	Origin Origin `json:"origin"`
	Repo   string `json:"repo"`
}

// Requester records the authenticated account that filed the request (design
// §5.4). It is accountability data only; ownership is Owner.
type Requester struct {
	Origin Origin `json:"origin"`
	Login  string `json:"login"`
	UserID int64  `json:"userId"`
}

// Certificate is one issued leaf recorded in the ledger. Multiple certs per app
// accumulate here (concurrent certs, renewals, key rollover), all bound to the
// single Owner. Revocation flips Status to revoked and records RevokedFrom,
// Reason and Actor (enrollment spec §5).
type Certificate struct {
	Serial      string    `json:"serial"`
	Fingerprint string    `json:"fingerprint"`
	NotBefore   Timestamp `json:"notBefore"`
	NotAfter    Timestamp `json:"notAfter"`
	Requester   Requester `json:"requester"`
	IssueRef    string    `json:"issueRef"`
	Status      Status    `json:"status"`

	// Revocation fields; omitted while the certificate is active.
	RevokedFrom *Timestamp `json:"revokedFrom,omitempty"`
	Reason      string     `json:"reason,omitempty"`
	Actor       string     `json:"actor,omitempty"`
}

// Ledger is the on-disk record for a single appId.
type Ledger struct {
	AppID     string    `json:"appId"`
	Owner     Owner     `json:"owner"`
	ClaimedAt Timestamp `json:"claimedAt"`
	// Reserved marks a first-party pre-claim (design §15, §19 Phase 5): the
	// FCFS check rejects any third-party attempt to claim it. Omitted (false)
	// for ordinary claims.
	Reserved     bool          `json:"reserved,omitempty"`
	Certificates []Certificate `json:"certificates"`
}

// timeLayout is the single canonical timestamp form: RFC3339 in UTC, seconds
// precision, "Z" zone. Committed ledger files are byte-stable and match a
// future PHP writer only if every timestamp uses exactly this layout.
const timeLayout = "2006-01-02T15:04:05Z"

// Timestamp is an RFC3339 UTC timestamp that marshals deterministically. Go's
// default time.Time JSON marshaling emits nanoseconds and the local offset,
// which would neither be byte-stable nor match the documented format.
type Timestamp time.Time

// MarshalJSON renders the timestamp as a canonical UTC "...Z" string.
func (t Timestamp) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(t).UTC().Format(timeLayout))
}

// UnmarshalJSON parses an RFC3339 timestamp and stores it in UTC.
func (t *Timestamp) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return fmt.Errorf("ledger: invalid timestamp %q: %w", s, err)
	}
	*t = Timestamp(parsed.UTC())
	return nil
}

// Parse unmarshals ledger JSON and validates structural invariants: the appId
// is legal (strict, no folding — the ledger stores the canonical lowercase
// form), the certificate status enum is known, and revoked entries carry a
// revokedFrom date.
func Parse(data []byte) (*Ledger, error) {
	var l Ledger
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("ledger: decode: %w", err)
	}
	if _, err := appid.ValidateStrict(l.AppID); err != nil {
		return nil, fmt.Errorf("ledger: appId %q: %w", l.AppID, err)
	}
	for i := range l.Certificates {
		c := &l.Certificates[i]
		switch c.Status {
		case StatusActive:
			// ok
		case StatusRevoked:
			if c.RevokedFrom == nil {
				return nil, fmt.Errorf("ledger: cert %q is revoked but has no revokedFrom", c.Serial)
			}
		default:
			return nil, fmt.Errorf("ledger: cert %q has unknown status %q", c.Serial, c.Status)
		}
	}
	return &l, nil
}

// Load reads and Parses a ledger file from disk.
func Load(path string) (*Ledger, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Marshal produces deterministic, canonical JSON: 2-space indent, HTML escaping
// disabled (so "/" and "&" in repo slugs are not mangled), and a trailing
// newline. This keeps round-trips and bot commits stable, minimal-diff.
func (l *Ledger) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(l); err != nil {
		return nil, err
	}
	// json.Encoder.Encode already appends a trailing newline.
	return buf.Bytes(), nil
}

// FileName returns the canonical ledger file name for an appId.
func FileName(appID string) string {
	return appID + ".json"
}
