package enroll

import (
	"fmt"
	"regexp"
	"strings"
)

// csrBlockRE extracts the PEM CERTIFICATE REQUEST block from an issue body,
// tolerating any surrounding markdown/code fences GitHub adds when rendering a
// `render: text` textarea.
var csrBlockRE = regexp.MustCompile(`(?s)-----BEGIN CERTIFICATE REQUEST-----.*?-----END CERTIFICATE REQUEST-----`)

// repoHeading is the issue-form label for the target repository field. GitHub
// renders each field as a "### <label>" section.
const repoHeading = "App repository (owner/name)"

// repoRE validates a target repo slug: exactly "owner/name" with no spaces.
var repoRE = regexp.MustCompile(`^[^\s/]+/[^\s/]+$`)

// form is the parsed certificate-request issue body.
type form struct {
	CSR  string // the PEM CERTIFICATE REQUEST block
	Repo string // target repo, "owner/name"
}

// parseForm extracts the CSR block and the target repo from a rendered issue
// body. A missing or malformed field is a parse error (the caller labels the
// issue `invalid`).
func parseForm(body string) (form, error) {
	csr := csrBlockRE.FindString(body)
	if csr == "" {
		return form{}, fmt.Errorf("no PEM CERTIFICATE REQUEST block found")
	}

	repo := strings.TrimSpace(stripFences(sectionBody(body, repoHeading)))
	if repo == "" {
		return form{}, fmt.Errorf("missing %q field", repoHeading)
	}
	if !repoRE.MatchString(repo) {
		return form{}, fmt.Errorf("target repo %q is not a valid owner/name slug", repo)
	}

	return form{CSR: csr, Repo: repo}, nil
}

// sectionBody returns the text under a "### <heading>" section, up to the next
// "### " heading or end of body. Returns "" if the heading is absent.
func sectionBody(body, heading string) string {
	marker := "### " + heading
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	rest := body[i+len(marker):]
	if j := strings.Index(rest, "\n### "); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// stripFences removes surrounding triple-backtick code fences (with an optional
// language tag) from a section body, leaving the inner text.
func stripFences(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	lines := strings.Split(s, "\n")
	// Drop the opening fence line and a trailing fence line if present.
	lines = lines[1:]
	if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "```" {
		lines = lines[:len(lines)-1]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// ownerOf returns the owner org (first path segment) of an "owner/name" slug.
func ownerOf(repo string) string {
	return repo[:strings.IndexByte(repo, '/')]
}
