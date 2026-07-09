package revoke

import (
	"strings"
	"testing"
)

// revocationBody renders a revocation-request issue body the way GitHub does
// for the single CMS field.
func revocationBody(cmsPEM string) string {
	return "### CMS revocation request (PEM)\n\n```\n" + cmsPEM + "\n```\n"
}

const sampleCMS = "-----BEGIN CMS-----\nMIIABC==\n-----END CMS-----"

func TestParseFormExtractsCMS(t *testing.T) {
	f, err := parseForm(revocationBody(sampleCMS))
	if err != nil {
		t.Fatalf("parseForm: %v", err)
	}
	if !strings.Contains(f.CMS, "BEGIN CMS") || !strings.Contains(f.CMS, "END CMS") {
		t.Errorf("CMS block not extracted: %q", f.CMS)
	}
}

func TestParseFormMissingCMS(t *testing.T) {
	if _, err := parseForm("no cms here"); err == nil {
		t.Error("expected error for body with no CMS block")
	}
}

func TestParseFormAcceptsPKCS7(t *testing.T) {
	body := "### CMS revocation request (PEM)\n\n```\n-----BEGIN PKCS7-----\nMIIABC==\n-----END PKCS7-----\n```\n"
	f, err := parseForm(body)
	if err != nil {
		t.Fatalf("parseForm: %v", err)
	}
	if !strings.Contains(f.CMS, "BEGIN PKCS7") {
		t.Errorf("PKCS7 block not extracted: %q", f.CMS)
	}
}
