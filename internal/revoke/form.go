package revoke

import (
	"fmt"
	"regexp"
)

// cmsBlockRE extracts a PEM CMS (or the equivalent PKCS7) block from an issue
// body, tolerating the markdown/code fences GitHub adds around a `render: text`
// textarea. openssl accepts either BEGIN CMS or BEGIN PKCS7 headers, so both are
// matched (spec §5.1 / developer-doc §7.2).
var cmsBlockRE = regexp.MustCompile(`(?s)-----BEGIN (?:CMS|PKCS7)-----.*?-----END (?:CMS|PKCS7)-----`)

// form is the parsed revocation-request issue body (developer-doc spec §7.2:
// exactly one field, the self-contained CMS request).
type form struct {
	CMS string // the PEM CMS/PKCS7 block
}

// parseForm extracts the CMS block from a rendered issue body. A missing block
// is a parse error (the caller labels the issue `invalid`).
func parseForm(body string) (form, error) {
	block := cmsBlockRE.FindString(body)
	if block == "" {
		return form{}, fmt.Errorf("no PEM CMS revocation request block found")
	}
	return form{CMS: block}, nil
}
