# Signing your ownCloud app — developer guide

This guide explains how to obtain a code-signing certificate, sign your ownCloud
app, and keep it verifying over time. It is the external developer documentation
for the ownCloud Code-Signing PKI (see [`specs/`](specs/) for the full design).

> **Placeholders.** Examples use `example-app`, `example-org`, `example-user`.
> The codesigning repo is **`owncloud/developer-certificates`**. The CRL is
> published at `https://owncloud.dev/developer-certificates/crl/developers.crl`;
> it is a core-side constant and not something developers interact with directly.
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

**Important:**

- Your **private key never leaves your control.** We only ever receive the CSR
  (public key). We will never ask for your private key.
- The CSR `CN` and your `appinfo/info.xml` `id` must be the **same** canonical
  appId, or issuance is rejected.
- Allowed appId charset: `^[a-z][a-z0-9_.-]{2,63}$` (lowercase ASCII letters,
  digits, underscore, hyphen, dot; letter-first; 3–64 chars).

---

## 3. Request a certificate

1. Open a **"Request a code-signing certificate"** issue in
   `owncloud/developer-certificates` using the form. Paste your CSR; enter
   your app's repository (`owner/name`).
2. A bot replies with a **one-time challenge value** and instructions.
3. Commit a file containing exactly that value to your repo's **default branch**
   at:

   ```text
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

Use the [`ocsign`](https://github.com/owncloud/ocsign) tool (a single static
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

> **`--path` is the packaged app payload, not your repository checkout.** The
> manifest hashes *everything* under `--path`, so signing a checkout makes
> `.git`, `tests/` and `.github/` part of the signed app — and it still verifies,
> because the manifest genuinely describes what was signed. Your users would
> install your git history. `ocsign` therefore refuses a `--path` that contains a
> `.git` entry at any depth and exits 1. `--allow-vcs` overrides that for one
> purpose only: signing a development checkout in place to try verification
> locally. Never use it in a release pipeline.

### 4.1 Signing in CI

Copy this into your app repo as `.github/workflows/release.yml`. It packages the
payload, signs the staging directory, and only then rolls the tarball — so the
tree you ship is exactly the tree you signed.

If your app uses the stock ownCloud Makefile, `make appstore` already does this in
the right order: it stages the payload into `build/artifacts/appstore/<app>`,
signs that directory, then tars it. To drive it from CI, either split the staging
part into its own target (`appstore-dir` below) and let the workflow sign and tar,
or keep the target whole and replace its legacy `occ integrity:sign-app` hook with
`ocsign`. Never tar before signing.

Staging inside your checkout is fine — `ocsign` only looks for `.git` **under**
`--path`, so `build/artifacts/appstore/<app>` passes the check.

```yaml
name: release

on:
  release:
    types: [published]

permissions:
  contents: write          # to attach the signed tarball to the release

jobs:
  sign:
    runs-on: ubuntu-latest
    environment: release   # a CI key is "warm": require reviewers on this job
    env:
      APP_ID: example-app
      OCSIGN_VERSION: v0.3.0
      PAYLOAD: build/artifacts/appstore/example-app
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Install ocsign (pinned, checksum-verified)
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          set -euo pipefail
          archive="ocsign_${OCSIGN_VERSION}_linux_amd64.tar.gz"
          gh release download "$OCSIGN_VERSION" --repo owncloud/ocsign \
            --dir "$RUNNER_TEMP" --pattern "$archive" --pattern SHA256SUMS
          cd "$RUNNER_TEMP"
          sha256sum --ignore-missing --check SHA256SUMS
          tar -xzf "$archive" ./ocsign
          install -m 0755 ocsign /usr/local/bin/ocsign

      - name: Build the app payload
        # Stages the release tree into $PAYLOAD and stops there: no tarball, no
        # signing. Everything the app ships and nothing else — no .git, no
        # tests/, no .github/, no build scratch.
        run: make appstore-dir

      - name: Write the key material
        env:
          OCSIGN_KEY: ${{ secrets.OCSIGN_KEY }}
          OCSIGN_LEAF: ${{ secrets.OCSIGN_LEAF }}
          OCSIGN_CHAIN: ${{ secrets.OCSIGN_CHAIN }}
        run: |
          set -euo pipefail
          umask 077
          printf '%s\n' "$OCSIGN_KEY"   > "$RUNNER_TEMP/signing.key"
          printf '%s\n' "$OCSIGN_LEAF"  > "$RUNNER_TEMP/leaf.crt"
          printf '%s\n' "$OCSIGN_CHAIN" > "$RUNNER_TEMP/intermediate.crt"

      - name: Sign the payload
        run: |
          ocsign --path "$PAYLOAD" \
                 --key   "$RUNNER_TEMP/signing.key" \
                 --cert  "$RUNNER_TEMP/leaf.crt" \
                 --chain "$RUNNER_TEMP/intermediate.crt"

      # Mode-2 attestation is not yet available (see §5). Once it is, add
      # --attest --attest-repo owncloud/developer-certificates to the command
      # above; nothing else in this workflow changes.

      - name: Roll the tarball from the signed payload
        run: tar --format=gnu -czf "$APP_ID.tar.gz" -C "$(dirname "$PAYLOAD")" "$APP_ID"

      - name: Attach it to the release
        env:
          GH_TOKEN: ${{ github.token }}
        run: gh release upload "${{ github.event.release.tag_name }}" "$APP_ID.tar.gz"
```

- `OCSIGN_VERSION` pins the `ocsign` release; integrity comes from that release's
  `SHA256SUMS`. For higher assurance, hardcode the archive's SHA-256 instead of
  fetching the sums file from the same release.
- `actions/checkout` is pinned to a full commit SHA, and the upload uses the
  pre-installed `gh` rather than a third-party action, so there is exactly one
  action SHA to keep current.
- Store your leaf and intermediate as secrets as well, so nothing about signing
  has to be committed to your repo.

---

## 5. Optional: Mode-2 attestation (longevity)

If you want your signed release to keep verifying **even after your certificate
expires**, obtain an attestation:

```sh
ocsign --path ./example-app --key example-app.key \
       --cert example-app-leaf.crt --chain intermediate.crt \
       --attest --attest-repo owncloud/developer-certificates
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
revocation"** issue and paste a **CMS revocation request** — a standard signed
blob proving you hold the certificate's private key. One command:

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
  and sign in your release workflow (reference workflow in §4.1). Protect the
  signing job (environment protection rules / required reviewers) — a CI secret is
  a "warm" key.
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
