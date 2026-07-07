# Signing your ownCloud app — developer guide

This guide explains how to obtain a code-signing certificate, sign your ownCloud
app, and keep it verifying over time. It is the external developer documentation
for the ownCloud Code-Signing PKI (see [`specs/`](specs/) for the full design).

> **Placeholders.** Examples use `example-app`, `example-org`, `example-user`.
> The codesigning repo is **`DeepDiver1975/developer-certificates`**. The CRL URL
> (`<crl-url>`) is finalized when GitHub Pages hosting is configured; it is a
> core-side constant and not something developers interact with directly.
>
> **Status: dev / staging.** This repository is private during implementation.
> The production codesigning repo will be public (its ledger is a public
> transparency log).

---

## 1. Overview — why apps must be signed

ownCloud verifies every app's authenticity and integrity at install/update time.
Third-party app signing is **mandatory**: an unsigned or invalidly-signed app is
**blocked** (not merely warned) on ownCloud 11+. Signing gives your users a
cryptographic guarantee that the app is really yours and has not been tampered
with.

There are **two signing modes**:

- **Mode 1 (default):** your signature is valid while your certificate is valid
  (2 years). If the certificate expires, you re-sign with a renewed one.
- **Mode 2 (optional, for longevity):** you additionally obtain an ownCloud
  **attestation** (a trusted timestamp) so your release keeps verifying **even
  after your certificate expires**, and a future revocation is applied precisely
  by time.

You keep full control of your private key at all times — we only ever receive
your CSR (the public half).

---

## 2. Generate your key and CSR

Primary path — **EC P-384**:

```sh
# 1. Generate your private key (KEEP THIS SECRET — never share, never commit)
openssl ecparam -name secp384r1 -genkey -noout -out example-app.key

# 2. Create the CSR. The CN must be your app id (lowercase; a-z 0-9 _ - ; 2-64;
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

**Important:**

- Your **private key never leaves your control.** We only ever receive the CSR
  (public key). We will never ask for your private key.
- The CSR `CN` and your `appinfo/info.xml` `id` must be the **same** canonical
  appId, or issuance is rejected.
- Allowed appId charset: `^[a-z][a-z0-9_-]{1,63}$` (lowercase ASCII letters,
  digits, underscore, hyphen; letter-first; 2–64 chars).

---

## 3. Request a certificate

1. Open a **"Request a code-signing certificate"** issue in
   `DeepDiver1975/developer-certificates` using the form. Paste your CSR; enter
   your app's repository (`owner/name`).
2. A bot replies with a **one-time challenge value** and instructions.
3. Commit a file containing exactly that value to your repo's **default branch**
   at:

   ```
   /.well-known/owncloud-codesigning-challenge.txt
   ```

   Anyone with write access to the repo can do this — it proves your team
   controls the repository. You have **72 hours**.
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

Use the [`ocsign`](https://github.com/DeepDiver1975/ocsign) tool (a single static
binary; see its releases):

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
       --attest --attest-repo DeepDiver1975/developer-certificates
```

This asks our attestation service to timestamp your signed manifest and embeds
the token in `signature.json`. Requirements: your leaf must be active (not
revoked), and you must present the genuine signature (only you can, since only
you hold the key). Attestation is available **only via automation** (a
workflow/API call) — if you cannot consume it, you simply stay on Mode-1 (which
is fine; you just re-sign on expiry).

Mode-2 also means a future revocation is applied precisely by time: releases you
attested *before* a revocation date keep working; Mode-1 releases stop working on
any revocation.

> **Not yet available.** Mode-2 attestation is designed but not yet implemented:
> the exact byte layout that binds the manifest hash and timestamp inside the
> token is not finalized (specs — attestation/CRL workflows, ITEM #2). Until it
> is pinned, `--attest` is not usable and every app stays on Mode-1. This section
> documents the intended flow.

---

## 6. Renew, re-sign, revoke

**Renew / additional cert:** open another certificate request for the same appId
from the same repo. The bot re-verifies control and issues a fresh cert (appended
to your ledger entry). You may hold multiple valid certs at once (e.g. a CI key
and a release key).

**Revoke — self-service (you still hold the key):** open a **"Request
revocation"** issue with your cert's serial/fingerprint and a revocation request
**signed with your private key**:

```sh
# Produce the signed revocation request.
openssl dgst -sha384 -sign example-app.key \
  -out revoke.sig revocation-statement.txt
base64 revoke.sig > revoke.sig.b64
```

The bot verifies the signature against your cert's public key and revokes
automatically — no human step.

> **Statement format not yet finalized.** The exact bytes of
> `revocation-statement.txt` (what precisely you sign) are being pinned so the
> documented OpenSSL command and the bot's verifier agree byte-for-byte (specs —
> enrollment bot, Open items). This section will carry the exact command once the
> revocation bot lands.

**Revoke — you lost your key, or you're reporting someone else's bad app:** you
cannot sign, so report it through our **GitHub Security Advisory (VDP)**; the
security team verifies and revokes.

---

## 7. What signing enforcement means for your users

- **Signing is mandatory.** Unsigned or invalidly-signed apps are **blocked** at
  install/update/enable on ownCloud 11+ (not merely warned).
- An admin *can* consciously **disable validation for a specific app** to run it
  anyway, but that is a logged, deliberate action and forfeits integrity/
  revocation protection for that app. Don't rely on it as a distribution
  strategy.
- **Development installs** (the `git` channel) are exempt so you can develop
  unsigned locally.

---

## 8. Key protection guidance

- **Baseline:** never commit or bundle your private key; restrict file
  permissions; keep it passphrase-encrypted at rest.
- **CI signing (recommended for most):** store the key as an encrypted CI secret
  and sign in your release workflow. Protect the signing job (environment
  protection rules / required reviewers) — a CI secret is a "warm" key.
- **High assurance:** hardware-backed keys (HSM, cloud KMS, hardware token).
  EC P-384 is widely supported.
- Consider **separate keys** for CI vs. manual release (you can hold multiple
  concurrent certs), so a CI-key compromise doesn't sink everything.

---

## 9. Notes

- **Partners (closed-source):** commercial partners with proprietary apps have a
  separate, contract-backed enrollment — contact us. Private-app appIds are
  owner-prefixed (`<partnerid>_<app>`). Alternatively, a partner may ship
  unsigned and have the admin exclude the app from validation (forfeiting
  protections).
- **Legacy transition:** apps signed under the old (pre-2026) scheme are accepted
  with a warning **until 2026-12-31**, after which only the new PKI is trusted.
  Re-sign under the new PKI before then.
- **GitLab (future):** identity is always a GitHub account today. Support for a
  GitLab-hosted app *repository* (nonce checked on GitLab) is planned but not yet
  available.
