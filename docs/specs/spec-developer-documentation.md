# Spec — Developer Documentation & Issue Forms

**Companion to:** `owncloud-code-signing-pki-design.md`
**Status:** Content spec for the external developer documentation and the GitHub
issue form definitions. The prose below is close to publishable; the YAML is
directly usable.
**Audience:** whoever writes the public developer docs and adds the issue forms to
the codesigning repo.

> **Examples** use placeholders (`example-app`, `example-org`, `example-user`).
> The codesigning repo is `owncloud/developer-certificates`; the leaf CRL is
> published at `https://owncloud.github.io/developer-certificates/crl/developers.crl`.

---

## 1. Audience & structure

External app developers. Sections:

1. Overview — why apps must be signed, what you get, the two modes.
2. Generate your key and CSR.
3. Request a certificate (issue form + nonce challenge).
4. Sign your app (the `ocsign` tool).
5. (Optional) Get a Mode-2 attestation for longevity.
6. Renew / re-sign.
7. Revoke a certificate.
8. What signing enforcement means for your users (mandatory signing, hard block,
   per-app admin disable).
9. Key protection guidance.
10. Notes: partners, the legacy transition/sunset, GitLab (future).

---

## 2. Generate your key and CSR

Primary path — **EC P-384**:

```sh
# 1. Generate your private key (KEEP THIS SECRET — never share, never commit)
openssl ecparam -name secp384r1 -genkey -noout -out example-app.key

# 2. Create the CSR. The CN must be your app id (lowercase; a-z 0-9 _ . - ; 3-64;
#    must start with a letter) and MUST match the id in your appinfo/info.xml.
openssl req -new -key example-app.key -out example-app.csr \
  -subj "/CN=example-app"
```

Fallback — **RSA-4096** (only if your HSM/CI cannot do EC):

```sh
openssl genrsa -out example-app.key 4096
openssl req -new -key example-app.key -out example-app.csr -subj "/CN=example-app"
```

Per-OS quoting note: on Windows PowerShell use `-subj "/CN=example-app"` as-is;
in `cmd.exe` the same. On POSIX shells the quoting above is correct.

**Warnings to state prominently:**

- Your **private key never leaves your control**. We only ever receive the CSR
  (public key). We will never ask for your private key.
- The CSR `CN` and your `appinfo/info.xml` `id` must be the **same** canonical
  appId, or issuance is rejected.
- Allowed appId charset: `^[a-z][a-z0-9_.-]{2,63}$` (lowercase ASCII letters,
  digits, underscore, hyphen, dot; letter-first; 3–64 chars).

---

## 3. Request a certificate

1. Open a **"Request a code-signing certificate"** issue in `owncloud/developer-certificates`
   using the form (§7.1). Paste your CSR; enter your app's repository
   (`owner/name`).
2. A bot replies with a **one-time challenge value** and instructions.
3. Commit a file containing exactly that value to your repo's **default branch**
   at:

   ```
   /.well-known/owncloud-codesigning-challenge.txt
   ```

   Anyone with write access to the repo can do this — it proves your team controls
   the repository. You have **72 hours**.
4. The bot verifies the file, checks your appId against `appinfo/info.xml`, and —
   if this appId is unclaimed or already owned by this repo — issues your
   certificate. It posts back your **leaf certificate** and the **intermediate
   certificate**. Save both.
5. You may delete the challenge file afterward; it has no further purpose.

**First-come-first-served:** an appId is bound to the first repo that
successfully claims it. If your appId is already owned by a different repo, the
request is rejected (contact us for genuine disputes).

---

## 4. Sign your app

Use the `ocsign` tool (single static binary; see its releases):

```sh
ocsign --path ./example-app \
       --key  example-app.key \
       --cert example-app-leaf.crt \
       --chain intermediate.crt
```

This writes `example-app/appinfo/signature.json`. That's a **Mode-1** signature:
valid while your certificate is valid (2 years). If your cert expires, re-sign
with a renewed cert.

Ship `signature.json` inside your app. On install/update, ownCloud servers verify
it.

---

## 5. Optional: Mode-2 attestation (longevity)

If you want your signed release to keep verifying **even after your certificate
expires**, obtain an attestation:

```sh
ocsign --path ./example-app --key example-app.key \
       --cert example-app-leaf.crt --chain intermediate.crt \
       --attest --attest-repo owncloud/developer-certificates
```

This asks our attestation service to timestamp your signed manifest and embeds the
token in `signature.json`. Requirements: your leaf must be active (not revoked),
and you must present the genuine signature (only you can, since only you hold the
key). Attestation is available **only via automation** (a workflow/API call) — if
you cannot consume it, you simply stay on Mode-1 (which is fine; you just re-sign
on expiry).

Mode-2 also means a future revocation is applied precisely by time: releases you
attested *before* a revocation date keep working; Mode-1 releases stop working on
any revocation.

---

## 6. Renew, re-sign, revoke

**Renew / additional cert:** open another certificate request for the same appId
from the same repo. The bot re-verifies control and issues a fresh cert (appended
to your ledger entry). You may hold multiple valid certs at once (e.g. a CI key
and a release key).

**Revoke — self-service (you still hold the key):** open a **"Request
revocation"** issue (form §7.2) and paste a **CMS revocation request** — a
standard signed blob proving you hold the certificate's private key. One command:

```sh
# Sign the word "revoke" with your cert's key; the certificate is embedded
# automatically. Paste revocation-request.pem into the issue.
printf 'revoke' | openssl cms -sign \
  -signer example-app-leaf.crt -inkey example-app.key \
  -outform PEM -nodetach -out revocation-request.pem
```

The bot verifies the CMS signature, reads the embedded certificate, matches it to
your ledger entry, and revokes automatically — no human step. (This mirrors how
ACME/Let's Encrypt lets you revoke a certificate using its own private key.)

If you no longer have the private key, you cannot produce this — report via our
Security Advisory (VDP) instead (below).

**Revoke — you lost your key, or you're reporting someone else's bad app:** you
cannot sign, so report it through our **GitHub Security Advisory (VDP)**; the
security team verifies and revokes.

---

## 7. GitHub issue forms (YAML)

### 7.1 Certificate request — `.github/ISSUE_TEMPLATE/certificate-request.yml`

```yaml
name: Request a code-signing certificate
description: Submit a CSR to obtain a certificate for your ownCloud app.
title: "[cert] <your-app-id>"
labels: ["cert-request"]
body:
  - type: markdown
    attributes:
      value: |
        Your private key must never be shared. Paste only your CSR (public key).
        Your CSR `CN` must equal your app's `appinfo/info.xml` `id`
        (lowercase; `^[a-z][a-z0-9_.-]{2,63}$`).
  - type: textarea
    id: csr
    attributes:
      label: Certificate Signing Request (PEM)
      description: The full -----BEGIN CERTIFICATE REQUEST----- block.
      render: text
    validations:
      required: true
  - type: input
    id: repo
    attributes:
      label: App repository (owner/name)
      description: The GitHub repository that owns this app. Its default branch
        must contain appinfo/info.xml, and you must be able to commit the
        challenge file to it.
      placeholder: example-org/example-app
    validations:
      required: true
```

### 7.2 Revocation request — `.github/ISSUE_TEMPLATE/revocation-request.yml`

```yaml
name: Request certificate revocation
description: Revoke one of your certificates (requires a CMS request signed with
  your private key).
title: "[revoke] <your-app-id>"
labels: ["revocation-request"]
body:
  - type: markdown
    attributes:
      value: |
        If you no longer have the private key, do NOT use this form — report via
        our Security Advisory (VDP) instead. Paste the CMS revocation request
        produced by the `openssl cms -sign` command in the docs; your certificate
        is embedded in it, so no separate identifier is needed.
  - type: textarea
    id: cms_request
    attributes:
      label: CMS revocation request (PEM)
      description: The `-----BEGIN CMS-----` block from `openssl cms -sign`
        (signed with your cert's private key; the cert is embedded).
      render: text
    validations:
      required: true
```

> The certificate-request form has exactly two fields (CSR + repo); the revocation
> form has one (the self-contained CMS request). The bot derives requester, owner,
> and origin (enrollment-bot spec §3), and reads the cert to revoke from inside the
> CMS structure.

---

## 8. What enforcement means for your users

- **Signing is mandatory.** Unsigned or invalidly-signed apps are **blocked** at
  install/update/enable on ownCloud 11+ (not merely warned).
- An admin *can* consciously **disable validation for a specific app** to run it
  anyway, but that is a logged, deliberate action and forfeits integrity/
  revocation protection for that app. Don't rely on it as a distribution strategy.
- **Development installs** (the `git` channel) are exempt so you can develop
  unsigned locally.

---

## 9. Key protection guidance (design §16)

- **Baseline:** never commit or bundle your private key; restrict file
  permissions; keep it passphrase-encrypted at rest.
- **CI signing (recommended for most):** store the key as an encrypted CI secret
  and sign in your release workflow (reference workflow provided — attestation/CRL
  spec §2). Protect the signing job (environment protection rules / required
  reviewers) — a CI secret is a "warm" key.
- **High assurance:** hardware-backed keys (HSM, cloud KMS, hardware token).
  EC P-384 is widely supported.
- Consider **separate keys** for CI vs. manual release (you can hold multiple
  concurrent certs), so a CI-key compromise doesn't sink everything.

---

## 10. Notes

- **Partners (closed-source):** commercial partners with proprietary apps have a
  separate, contract-backed enrollment — contact us. Private-app appIds are
  owner-prefixed (`<partnerid>_<app>`). Alternatively, a partner may ship unsigned
  and have the admin exclude the app from validation (forfeiting protections).
- **Legacy transition:** apps signed under the old (pre-2026) scheme are accepted
  with a warning **until 2026-12-31**, after which only the new PKI is trusted.
  Re-sign under the new PKI before then.
- **GitLab (future):** identity is always a GitHub account today. Support for a
  GitLab-hosted app *repository* (nonce checked on GitLab) is planned but not yet
  available.
```
