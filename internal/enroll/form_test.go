package enroll

import "testing"

const sampleCSR = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----"

func TestParseFormOK(t *testing.T) {
	body := "### Certificate Signing Request (PEM)\n\n```\n" + sampleCSR + "\n```\n\n" +
		"### App repository (owner/name)\n\nexample-org/example-app\n"
	f, err := parseForm(body)
	if err != nil {
		t.Fatalf("parseForm: %v", err)
	}
	if f.Repo != "example-org/example-app" {
		t.Errorf("Repo = %q", f.Repo)
	}
	if f.CSR != sampleCSR {
		t.Errorf("CSR = %q, want the PEM block only", f.CSR)
	}
}

func TestParseFormErrors(t *testing.T) {
	cases := []struct{ name, body string }{
		{"no csr", "### App repository (owner/name)\n\nexample-org/example-app\n"},
		{"no repo", "### Certificate Signing Request (PEM)\n\n```\n" + sampleCSR + "\n```\n"},
		{"bad repo slug", "### Certificate Signing Request (PEM)\n\n```\n" + sampleCSR + "\n```\n\n### App repository (owner/name)\n\nnot a slug\n"},
		{"repo with spaces", "### Certificate Signing Request (PEM)\n\n```\n" + sampleCSR + "\n```\n\n### App repository (owner/name)\n\nexample org/app\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := parseForm(c.body); err == nil {
				t.Errorf("parseForm(%s) err = nil, want error", c.name)
			}
		})
	}
}

func TestOwnerOf(t *testing.T) {
	if got := ownerOf("example-org/example-app"); got != "example-org" {
		t.Errorf("ownerOf = %q, want example-org", got)
	}
}
