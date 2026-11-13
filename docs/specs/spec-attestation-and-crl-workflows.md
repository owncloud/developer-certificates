# Spec — Attestation & CRL Workflows

**Companion to:** `owncloud-code-signing-pki-design.md`
**Status:** Implementation spec, buildable from this document alone.
**Audience:** whoever implements the attestation workflow, the reference developer
signing workflow, and CRL generation/publishing.

> **Examples** use placeholders. The single repo hosting these is **the
> codesigning repo**. Signing keys live in **HashiCorp Vault** (Transit engine;
> key never enters the runner — design §19).

---

## 1. Attestation workflow (Mode 2 tokens)

### 1.1 Trigger & inputs

Exposed **only** as a dispatchable workflow (`workflow_dispatch`, and/or
`repository_dispatch` so a developer's release CI can call it via the API). **No
manual issue path** (design §8).

Inputs:

- `leaf` — the developer's leaf certificate (PEM) or its SHA-256 fingerprint.
- `manifest_hash` — `H = SHA-384(M)` (the canonical manifest digest; see the Go
  signing tool spec §3.5, §6).
- `manifest_signature` — the developer's signature over `M` (base64 DER), i.e. the
  `signature` value from their Mode-1 `signature.json`.

### 1.2 Pre-issue checks (abuse resistance — design §8, S3)

Not authorization, but the token is only issued for a genuinely-signed manifest:

1. **Leaf is real & active:** the leaf (by fingerprint) exists in the ledger and
   its `status` is `active` (not revoked). Else → reject.
2. **Manifest genuinely signed:** verify `manifest_signature` over `H`'s
   preimage — i.e. verify the developer signature against the leaf's public key
   using the leaf's `alg`. Only the leaf private-key holder can produce it. Else →
   reject.
3. **Rate limiting:** per-requester/day cap + workflow `concurrency` limit
   (defense-in-depth against resource abuse).

### 1.3 Issue the token

- Compute `T = <workflow run time, UTC>`.
- Produce `token = sign_attestationKey( bind(H, T) )`. Sign **via Vault Transit**
  under the **attestation key** (separate from the intermediate — design §2.4,
  §8).

> **⚠️ ITEM #2 — TO BE DECIDED (blocks interoperable implementation).** The exact
> byte layout of `bind(H, T)` — what precise bytes are signed to bind the manifest
> hash `H` and timestamp `T` — is **not yet fixed**. It MUST be pinned before the
> attestation workflow, the core verifier's Mode-2 path, and `ocsign --attest`
> can interoperate. Options: a small ASN.1 SEQUENCE `{ hashAlg, H, genTime }`
> (RFC-3161-flavored), or a fixed documented concatenation. Whichever is chosen
> must be documented here as the single source of truth and covered by a golden
> vector (§4). Until decided, Mode-2 is not implementable.

- Return to the caller: `token` (base64) + the **attestation certificate** (PEM,
  EKU `timeStamping`). Delivery mechanism: workflow artifact and/or a committed
  transparency-log entry the caller reads back (see §1.4, and Go tool spec §6).

### 1.4 Transparency log

Append an entry to an **append-only** log in the repo (design §8): appId (from the
leaf CN), leaf fingerprint, `H`, `T`, requester. This is the auditable record;
because §1.2 gates on real signed manifests, the log never fills with junk.

### 1.5 Security notes (from design §8)

- The token asserts only "ownCloud saw this manifest hash at T"; it does **not**
  vouch for the signature or CN. The **server independently** verifies the
  developer signature and `CN==appId`.
- The attestation key is **separate** from the intermediate. A stolen intermediate
  cannot self-attest; attestation-key compromise alone cannot mint leaves.
- `signature.json` carries **no plaintext time** — `T` lives only inside `token`
  (design §17).

---

## 2. Reference developer signing workflow (GitHub Actions)

A **copy-paste reference** developers add to their app repo to sign releases in CI
(design §16, CI-signing tier). Not run by us — documentation output. It:

1. Installs the `ocsign` Go binary (pinned version/checksum).
2. **Builds the app payload** into a staging directory — the tree that becomes the
   release tarball and nothing else, e.g. `build/artifacts/appstore/<app>` (the
   `make appstore` convention). No `.git`, no `tests/`, no `.github/`, no build
   scratch.
3. Loads the developer's private key from a **repo/environment secret** (guidance:
   protect the signing job with environment protection rules / required
   reviewers — the key is "warm").
4. Runs `ocsign --path build/artifacts/appstore/<app> --key <secret> --cert
   leaf.crt --chain intermediate.crt` to produce Mode-1
   `build/artifacts/appstore/<app>/appinfo/signature.json`.
5. Optionally runs with `--attest --attest-repo <codesigning repo>` (or calls the
   attestation workflow via `repository_dispatch`) to obtain and embed a Mode-2
   token.
6. **Rolls the tarball from the signed staging directory** and publishes it
   (developer's own distribution — not through ownCloud).

**The signed tree and the shipped tree must be the same tree.** Package first,
point `--path` at the staging directory, tar afterwards:

- `--path .` in a CI job signs the `actions/checkout` tree. In app mode the
  manifest hashes everything under `--path` bar `appinfo/signature.json` and OS
  cruft (Go tool spec §3.2), so the app's signature would legitimize `.git`
  internals, tests and CI config — and it verifies, because the manifest
  genuinely describes the tree that was signed. `ocsign` therefore refuses a
  `--path` holding a `.git` entry at any depth (owncloud/ocsign#21), and
  `--allow-vcs` MUST NOT appear in a release pipeline — it exists only for
  signing a development checkout in place to exercise verification locally.
- A staging directory *inside* the checkout (`build/artifacts/…`) is fine: the
  guard only looks for `.git` **under** `--path`. There is no need to stage
  outside the workspace.
- Apps whose Makefile stages, signs and tars in one `appstore` target already
  have the right order — keep it, and swap the legacy `occ integrity:sign-app`
  hook for `ocsign`. Never tar before signing.

The full YAML lives in the developer-documentation spec (§4.1).

---

## 3. CRL generation & publishing (design §6, §9, §13)

### 3.1 Trigger

Runs whenever the ledger changes a revocation state (invoked by the revocation
paths — enrollment-bot spec §5) and on a **daily schedule** (`0 * * *` once/day),
so `nextUpdate` stays fresh even without revocations. Set the leaf-CRL
`nextUpdate` to **now + 7 days** (comfortably longer than the daily regeneration
cadence, so a missed run does not expire the CRL).

### 3.2 Generation

Under the single-concurrency ledger lock (enrollment-bot spec §2):

- **Leaf CRL** → published as **`crl/developers.crl`** (signed by the
  **intermediate** via Vault Transit): include every ledger `certificates[]` entry
  with `status = revoked`, each as a CRL entry with its serial and **`revokedFrom`**
  encoded as the CRL entry's revocation/invalidity date (this is what enables
  revoke-from-time — design §9). Set `thisUpdate` = now, `nextUpdate` = now + 7
  days.
- **Intermediate CRL** → **`crl/intermediate.crl`** (signed by the **root**):
  generated only during a root-side ceremony (rare); normally static. Include any
  revoked intermediates.
- **Root CRL** → **`crl/root.crl`** (self-issued at the root ceremony; normally
  empty/static).
- **Legacy (G1) CRL:** frozen — bundled once, **never regenerated/refreshed**
  (accepted risk — design §12). Not produced by this workflow.

### 3.3 Publishing (design §13)

- Commit the generated CRL(s) into the codesigning repo
  (`owncloud/developer-certificates`) and publish via **GitHub Pages** at
  `https://owncloud.dev/developer-certificates/crl/`, served over the Pages CDN.
  `main` is protected (design §6 write path), so the commit is made by the
  **codesign-bot App** — the ruleset bypass actor — via the GitHub Contents API (a
  GitHub-signed commit satisfying `required_signatures`), not a raw `git push`. The
  leaf CRL is regenerated and republished on **every** run (freshness comes from
  `thisUpdate`/`nextUpdate`; §3.1), so there is no "publish only on change" step.
- **Pages publishes only the CRL, not the repo.** A dedicated deploy workflow
  (`.github/workflows/pages.yml`) uses the **GitHub Actions** Pages build and stages
  only `crl/*.crl` into the artifact, so the published site contains nothing but the
  CRL(s) — no repository source, docs, or ledger is web-exposed.
- The core verifier fetches from a **constant URL** and does **not** follow
  redirects (verifier spec §5). The URL is the `owncloud.dev` host, because the org
  user-site custom domain 301-redirects the `owncloud.github.io/*` path org-wide
  (design §13). Future migration to a dedicated domain is a code change + independent
  hosting.
- Content-type is irrelevant (our verifier parses by content).

### 3.4 Seed CRLs

The initial empty CRLs are produced in the CA ceremony (design §19 Phase 4) and
bundled into core (`resources/codesigning/crl/`) as the fallback the verifier uses
when a fresh fetch fails (verifier spec §5).

---

## 4. OpenSSL / interoperability compatibility (REQUIRED)

- The attestation **certificate** is a standard OpenSSL-issued PEM cert; the core
  verifier parses it with standard tooling.
- The **token signature** must be verifiable with standard primitives (the same
  ECDSA-DER / RSA-PSS conventions as elsewhere). Whatever `bind(H, T)` layout is
  chosen (item #2), signing and verification must be reproducible with `openssl`
  where reasonable, and cross-tested against it in CI — not Go-only / PHP-only.

## 5. Open items

- **⚠️ ITEM #2 — `bind(H, T)` exact encoding (TO BE DECIDED):** the precise byte
  layout (ASN.1 structure vs. fixed concatenation) so the attestation workflow,
  `ocsign --attest`, and the core verifier agree byte-for-byte. **Blocks Mode-2
  implementation.** Add a golden vector covering token creation/verification.
- **Token result delivery** to the `ocsign --attest` caller: decide between a
  workflow artifact the tool downloads vs. a transparency-log commit the tool
  reads back; document in the Go tool spec §6 accordingly.
- **CRL cadence: DECIDED** — regeneration daily; `nextUpdate` = +7 days;
  issuer/revocation poll every 10 min.
