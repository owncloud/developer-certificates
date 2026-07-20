# ownCloud Code-Signing PKI — Design

**Status:** Complete design. All architectural decisions are made. The
vibe-codeable implementation notes and developer documentation are captured as
separate spec files (see "Companion specs" below).

**Date:** 2026-07-06

**Scope:** A green-field Public Key Infrastructure for signing ownCloud apps so a
server can verify authenticity and integrity at install/update time. Third-party
app signing is mandatory. This replaces the legacy ownCloud integrity-signing
trust mechanism (`OC\IntegrityCheck`) rather than building on it.

**Note on examples:** all app IDs, organizations, users, and repository names in
this document are placeholders (`example-app`, `example-org`, `example-user`,
etc.). They are illustrative only. Real product/entity names (ownCloud, Kiteworks)
and genuine technical identifiers (`core`, `signature.json`) are used as such.

**Operational identifiers (decided):**

- **Codesigning repo:** `owncloud/developer-certificates` — the single repo
  hosting CSR/revocation issue intake, the public issuance ledger, the CRL, and
  the issuance/attestation/revocation workflows. (Created private in the ownCloud
  org during implementation; made public before go-live, since the ledger is a
  public transparency log.)
- **CRL URLs (GitHub Pages, Option B):**
  - leaf/developer CRL: `https://owncloud.github.io/developer-certificates/crl/developers.crl`
  - intermediate CRL: `https://owncloud.github.io/developer-certificates/crl/intermediate.crl`
  - root CRL: `https://owncloud.github.io/developer-certificates/crl/root.crl`

  These are the constants the verifier is built with (§9, §13). Migration to a
  custom domain later is a code-constant change + independent hosting (§13).

**Companion specs (separate files, option #2 structure):**

- `spec-enrollment-bot.md` — GitHub App + Actions enrollment bot,
  privileged partner workflow, internal partner processing.
- `spec-attestation-and-crl-workflows.md` — dispatchable attestation
  workflow, reference developer signing workflow, CRL generation/publishing.
- `spec-core-verifier.md` — the new `Checker` verification, transition
  logic, sunset, CRL fetch.
- `spec-go-signing-tool.md` — standalone Go signing CLI, incl. the
  canonicalization spec and golden test vectors.
- `spec-developer-documentation.md` — external developer guide and the
  GitHub issue form YAML.

---

## 1. Background and goals

ownCloud already ships a code-signing mechanism (`lib/private/IntegrityCheck/`)
that signs core and apps with X.509 + RSA, embedding a leaf certificate in
`appinfo/signature.json` and verifying it against a bundled intermediate CA. Its
design intent already anticipated third-party developers — the class docblock
notes that an app author would receive a certificate valid only for their own
application. Its weaknesses:

- Certificates are **V1** (no extensions): no KeyUsage/EKU/BasicConstraints, no
  CRL Distribution Point (revocation location hardcoded in core).
- App identity is only the `CN` (= app ID); no developer identity/accountability.
- Manifest signature uses **RSA-PSS with SHA-1** as the message hash.
- Trust anchor + CRL shipped only inside the release tree; revocation latency =
  release cadence.
- Third-party signing is **optional and unenforced**.
- The bundled root/intermediate/leaf certificates **expired 2026-01-31**.
- Certificate issuance was **manual** (developer pastes a CSR into a GitHub
  issue; a human eyeballs and signs — no proof of repo/app ownership). Confirmed
  by a real historical issue in which a CSR was pasted and issued with no
  ownership proof at all.

The old marketplace is being retired; a new fetch mechanism replaces it; the
client-side "market" app remains one optional install path alongside manual
installation. Apps do **not** flow through an ownCloud build/publication step —
developers build and distribute independently.

**Goals:**

1. A clean 3-tier PKI under ownCloud/Kiteworks control.
2. Mandatory third-party app signing, verified on install/update.
3. Automated, self-service certificate issuance with real proof of ownership.
4. Accountability: tie certificates to a verifiable GitHub identity.
5. Modern cryptography with crypto-agility (a clear path to PQC).
6. Support the open-source community (GitHub; public GitLab as a future
   extension) plus a small number of commercial closed-source partners.

---

## 2. Trust hierarchy and certificate profiles

```text
Root CA G2 (offline; private key in cold storage/HSM; certificate baked into core)
   └── Intermediate CA G2 (private key in vault/KMS; used by automated issuer)
          ├── Leaf certificates      (EKU codeSigning; one per app; CN = appId)
          └── Attestation certificate (EKU timeStamping; SEPARATE key; signs time tokens)
```

All keys are **EC P-384** (primary); **RSA-4096** is a documented developer/HSM
fallback. All CA/CRL signatures are **ecdsa-with-SHA384**.

### 2.1 Root CA

| Attribute | Value |
| --- | --- |
| Subject / Issuer | `C=DE, O=ownCloud GmbH, CN=ownCloud Code Signing Root CA G2` (self-signed) |
| Key / Sig | EC P-384 / ecdsa-with-SHA384 |
| Serial | random 128-bit |
| Validity | ~25 years |
| Basic Constraints | critical, `CA:TRUE`, `pathlen:1` |
| Key Usage | critical, Certificate Sign, CRL Sign |
| SKI | present |
| EKU / AIA / CRL DP | none |

- `pathlen:1` caps the hierarchy at root → intermediate → leaf.
- "G2" generation marker enables successor coexistence (legacy = "G1"; future
  PQC/hybrid = "G3"). See §12.

### 2.2 Intermediate CA

| Attribute | Value |
| --- | --- |
| Subject | `C=DE, O=ownCloud GmbH, CN=ownCloud Code Signing Intermediate CA G2` |
| Issuer | Root CA G2 |
| Key / Sig | EC P-384 / ecdsa-with-SHA384 |
| Validity | 5 years (see §7 for rotation) |
| Basic Constraints | critical, `CA:TRUE`, `pathlen:0` |
| Key Usage | critical, Certificate Sign, CRL Sign |
| Extended Key Usage | Code Signing (constrains all leaves via EKU chaining) |
| SKI / AKI | present |
| CRL DP | URI to root CRL |
| AIA (OCSP) | optional, non-load-bearing |
| Name Constraints | **not used** (does not fit a flat-appId CN model; the ledger enforces namespacing) |

### 2.3 Leaf (developer/app) certificate

| Attribute | Value |
| --- | --- |
| Subject | `O=<owner>, OU=<origin>, CN=<appId>` — only `CN` is authoritative |
| `CN` | the app ID (e.g. `example-app`) — the single authoritative field |
| `O` / `OU` | owner org / origin (`github`/`gitlab`/`partner`) — cosmetic, **not trusted** |
| Key / Sig | EC P-384 (RSA-4096 fallback) / ecdsa-with-SHA384 |
| Validity | 2 years |
| Basic Constraints | critical, `CA:FALSE` |
| Key Usage | critical, Digital Signature |
| Extended Key Usage | Code Signing |
| SKI / AKI | present |
| CRL DP | present for external tooling; **the core verifier ignores it** (see §9) |
| Custom OID / scope extension | **none** |

**Key decision:** no custom OID. The server authorizes purely on `CN==appId`;
namespace ownership is enforced at issuance by the ledger (§6). Repo name (which
may differ from app ID), requester, and origin live in the ledger, not the cert.

### 2.4 Attestation certificate

| Attribute | Value |
| --- | --- |
| Subject | `CN=ownCloud Timestamp Attestation, O=ownCloud GmbH` |
| Issuer | Intermediate CA G2 |
| Key / Sig | EC P-384 / ecdsa-with-SHA384 — **separate key from the intermediate** |
| Basic Constraints | critical, `CA:FALSE` |
| Extended Key Usage | `id-kp-timeStamping` |

The timestamping EKU cryptographically prevents this cert from signing apps (and
prevents code-signing leaves from producing attestations). It **must** be a
distinct key from the intermediate — see §8 for why this separation is what makes
intermediate-revocation safe.

---

## 3. Cryptography and crypto-agility

- **Keys:** EC P-384 (`secp384r1`) primary everywhere; RSA-4096 documented
  fallback. Enrollment rejects weak/unknown key types (RSA < 3072, non-approved
  curves) via an allowlist.
- **X.509 / CRL signatures:** ecdsa-with-SHA384.
- **App manifest signature:** ECDSA-P384-SHA384 over the file-hash manifest
  (replacing legacy RSA-PSS-SHA1). RSA fallback = PSS with SHA-256/384, never
  SHA-1.
- **File manifest hashes:** SHA-512.
- **Crypto-agility:** `signature.json` carries an explicit **algorithm identifier
  and format version** (`"alg": "ecdsa-p384-sha384"`, `"v": 2`). The verifier
  dispatches on it against an allowlist and refuses unknown/weak algorithms. This
  prevents another hardcoded-SHA-1 situation and enables migration.
- **PQC:** deferred, not blocked. No mature standardized PQC code-signing X.509
  story in PHP tooling as of 2026. The future path is *hybrid* (classical + PQC);
  the agility hooks + generational root scheme (§12) make that migration
  feasible.

---

## 4. Namespace model

**Conceptual scope grammar:** `origin:owner/appId` (e.g.
`github:example-org/example-app`). This is a **ledger/conceptual** construct —
NOT encoded in the certificate and does NOT change the flat on-disk app ID.

- `origin` — which authority proved control: `github`, `gitlab`, `partner`.
- `owner` — the account/org that owns the **repository** (not the CSR submitter).
- `appId` — the flat ownCloud app ID (no change to app dirs, `info.xml`, DB).

**Ownership rule:** `owner` = the **repository owner**. The CSR submitter need not
be the repo owner (e.g. an individual with push access to
`github.com/example-org/example-app` may enroll; the namespace owner is
`example-org`, the individual is recorded only as *requester*). Repo
rename/transfer changes the namespace for *future* issuance; already-issued
certs/artifacts are unaffected.

**Origins:**

- `github` — default, automated (identity + nonce-in-repo challenge).
- `gitlab` — public community projects; same grammar. Nonce-checking against
  GitLab is a **documented future extension, not implemented now**. Note: intake
  identity is always a GitHub account (§10), even when the target repo is GitLab.
- `partner` — commercial closed-source customers (§11). Same cert format, CA, and
  server verification; only the control-proof step differs (manual).

Reserved namespaces (first-party appIds + core identity) are pre-claimed in the
ledger at bootstrap so no third party can ever obtain them (§5.4, §15).

### 4.1 AppId format and comparison (impersonation defense)

Because authorization rests entirely on `CN == appId`, the definition of a legal
appId and the comparison rule are security-critical: the ledger's FCFS uniqueness
check and the server's `CN==appId` check **must** treat two strings as "the same
appId" identically, or the anti-impersonation guarantee breaks.

**Legal appId:** `^[a-z][a-z0-9_.-]{2,63}$` — lowercase ASCII letters, digits,
underscore, hyphen, dot; must start with a letter; 3–64 characters. This forbids
uppercase, dots, whitespace, and all non-ASCII characters. Homoglyph attacks
(e.g. Cyrillic `а`) and lookalike dashes (en-/em-dash, U+2212) are impossible
because those characters are simply illegal and rejected.

**Handling by source:**

| Source | Handling |
| --- | --- |
| Cert `CN` (issued by us) | Validate **strictly** against the regex, exact bytes, **no normalization**. Issuance guarantees the CN is canonical lowercase. Reject on mismatch. |
| `info.xml` id / filesystem-derived appId (at install) | Apply **ASCII-only case-folding** (`A`→`a` … `Z`→`z`, the 26 ASCII bytes only — **never** Unicode/locale `toLowerCase`, which diverges across languages), **then** validate against the regex (reject if it still fails), **then** exact-byte compare to the cert `CN`. |
| Ledger | Stores the canonical lowercase CN; FCFS uniqueness = exact-byte comparison of canonical forms. |

**Why the asymmetry is safe:** the cert CN is always canonical lowercase (we
enforce it at issuance), and the filesystem side is folded into that same
lowercase space before comparison — so both sides always compare in one canonical
form, with the only folding being ASCII-only and thus trivially identical across
PHP and Go. Case-folding is applied **before** validation, so homoglyphs/illegal
characters are still rejected regardless of source. Enrollment guarantees the
issued CN is canonical lowercase (§5.2 / see P1): a CSR CN or `info.xml` id with
uppercase is ASCII-lowercased to derive the canonical appId, or rejected.

---

## 5. Enrollment (automated, GitHub)

### 5.1 Two separate proofs

1. **Identity (accountability):** the authenticated GitHub issue author. No
   explicit OAuth flow — GitHub already authenticates the issue author; the App
   reads it via the API (minimal permissions). The nonce challenge is a public
   committed file, needing no delegated access.
2. **Authorization (namespace):** proof of **write control of the target
   repository** via a nonce-in-repo challenge — this, not personal identity, is
   the gate.

Requester (filer) and whoever commits the nonce need **not** be the same person.
We record the filer; we independently check the nonce exists in the repo.

### 5.2 CSR collection — GitHub Issue form + bot

- Intake is a **GitHub Issue form** (YAML-defined) with exactly two fields: the
  pasted **CSR** and the **target repo** (`owner/name`).
- `appId` = the CSR's `CN`, taken as a *claim* and validated against the repo's
  actual `info.xml` app `id`. The CN is never trusted blindly.
- `requester` (issue author), `owner` (from the repo), `origin` (`github`) are
  **derived**, not asked.
- Processed by a **GitHub App + GitHub Actions** bot — no hosted web service.

**AppId reconciliation and the issued CN (P1).** Three appId sources must agree:
the CSR `CN` (claim), the repo `info.xml` `id` (enrollment), and the shipped
`info.xml` `id` (install). At enrollment the bot:

1. Reads `info.xml` from **`appinfo/info.xml` at the repo root**, on the **same
   commit of the default branch where the nonce was verified** (one consistent
   snapshot; reject if the file is absent — the conventional path is assumed and
   can be revisited later if unusual layouts need support).
2. ASCII-lowercases and validates both the CSR `CN` and the repo `info.xml` `id`
   against `^[a-z][a-z0-9_.-]{2,63}$` (§4.1). They **must match** after
   canonicalization; on disagreement the request is **rejected** (the developer
   aligns them and resubmits).
3. Mints the leaf with **`CN` = that canonical (validated, lowercased) appId**, so
   the issued CN is always canonical per §4.1 and equals the repo's declared id.
   The FCFS ledger claim uses this canonical appId.

**Binding is enforced at install, not enrollment.** Because apps are distributed
independently (not through ownCloud), nothing cryptographically ties the
enrollment-time `info.xml` to the shipped artifact. This is acceptable: the
verifier re-checks `CN == appId` at install against the *shipped* `info.xml`
(§9), so a shipped app only verifies if its `info.xml` id equals the cert CN.
Enrollment's role is only to mint a CN the developer can match.

### 5.3 Nonce challenge

- **Nonce:** plain random 256-bit, **single-use**, **issue-scoped**, **72-hour**
  expiry.
- **Storage:** posted as the **bot's own comment**. Verification reads it back
  **filtering strictly on bot authorship**; no other comments are processed. The
  bot **polls** on a schedule (not comment-triggered).
- **Challenge:** the developer commits the nonce to
  `/.well-known/owncloud-codesigning-challenge.txt` on the repo's **default
  branch** (fixed path, no extra directory levels). Only someone with write
  access can do this.
- **Verification:** the bot fetches that path via the GitHub API and compares to
  the nonce from the same issue. Always bound to that issue's CSR and repo; no
  cross-issue reuse. The file is inert after issuance.

### 5.4 Recorded accountability data

GitHub **login** + stable **numeric user ID** + **repo** + **issue reference** +
**timestamp**. No email. Origin-tagged so the schema handles github/gitlab
uniformly in future.

---

## 6. Issuance ledger (state + transparency)

A **public git repository** — the **same repository** used for CSR issue intake
(issues = intake; files = ledger). Written **only** by the issuance bot,
append-only by convention. Git history is the immutable transparency/audit log.

**Write path (App bypass actor).** `main` is protected by an org-level ruleset
(pull requests + `required_signatures`), so the bots do **not** push commits or
call the Contents API under the default workflow `GITHUB_TOKEN`. Instead, each bot
workflow mints a **GitHub App token** (`owncloud-codesign-bot`, the sole ruleset
**bypass actor**) and writes `ledger/<appId>.json` and `crl/developers.crl`
directly via the GitHub Contents API — a GitHub-signed commit that satisfies
`required_signatures`, admitted to `main` because the App bypasses the ruleset.
The single-concurrency serialization below is unchanged. This trades review of
bot commits for possession of the App key: whoever can trigger these workflows or
read `BOT_APP_ID`/`BOT_APP_PRIVATE_KEY` can write to `main` unreviewed, and the
protection of `main` rests on the bypass being scoped to exactly this App (managed
in `owncloud/admin`).

**Structure:** one JSON file per appId, e.g. `ledger/example-app.json`:

```json
{
  "appId": "example-app",
  "owner": { "origin": "github", "repo": "example-org/example-app" },
  "claimedAt": "2026-07-06T10:00:00Z",
  "certificates": [
    {
      "serial": "0x1a2b...",
      "fingerprint": "sha256:...",
      "notBefore": "2026-07-06T10:00:00Z",
      "notAfter": "2028-07-05T10:00:00Z",
      "requester": { "origin": "github", "login": "example-user", "userId": 12345 },
      "issueRef": "example-org/<intake-repo>#<issue-number>",
      "status": "active"
    }
  ]
}
```

**Guarantees:**

- **AppId uniqueness / ownership (FCFS):** absent file → new claim bound to the
  proven repo. Present → the request's repo must equal `owner.repo`, else reject.
  Because the CA never issues two `CN=<appId>` certs to different owners, the
  server can trust `CN==appId`.
- **Serialization (single-concurrency):** FCFS correctness requires that ledger
  reads/writes are serialized. The issuance workflow **must run at concurrency 1**
  (a single-concurrency GitHub Actions workflow / a global lock), so two
  near-simultaneous requests for the same new appId cannot both observe "no ledger
  file" and both claim it (TOCTOU). Commit-conflict-retry is an additional
  safeguard.
- **Multiple certs per app:** appended to `certificates[]` (concurrent certs,
  renewals, key rollover), all bound to the single owner.
- **Disputes/squatting:** FCFS by default; resolved **manually** (admin edits the
  ledger and revokes). No automated anti-squatting at this scale.
- **Revocation source of truth:** revoking flips `status` and records the
  revoke-from date; the **CRL is generated from the ledger**.
- **Visibility:** **public**, including partner entries (§11).

---

## 7. Expiration and rotation

| Tier | Validity | Rotation |
| --- | --- | --- |
| Root | ~25 years | generational (G2 → G3) with successor cross-signing |
| Intermediate | 5 years | new one issued when the current has ~2.5 years left; overlapping |
| Leaf | 2 years | self-service re-enrollment; **timestamp model** means expiry need not break old signatures (§8) |
| Attestation | 3 years | reissued under the intermediate; tokens it signed while valid remain verifiable after its expiry (timestamp model) |

**Timestamp (valid-at-signing-time) model:** the server verifies the signing cert
was valid **at signing time**, not install time (Mode 2 only; see §8). This
enables short leaves without forcing constant re-signing of stable apps.

**Intermediate rotation arithmetic:** a 5-year intermediate can only issue 2-year
leaves while ≥2 years of life remain (a leaf's `notAfter` must not exceed its
issuer's). Its issuing window is its first 3 years. The successor is issued at
~2.5 years remaining (a half-year operational buffer), giving continuous,
overlapping coverage. Over 25 years the root issues ~8 intermediates (fine under
`pathlen:1`).

**Issuer rule:** always sign leaves under the newest intermediate; hard-cap leaf
`notAfter` to `min(now + 2yr, intermediate.notAfter)`.

**Emergency / compromise:**

- **Leaf:** revoke (revoke-from-time) + developer re-enrolls. Routine.
- **Intermediate:** revoke via the **root-issued CRL** + stand up a new
  intermediate. Revocation follows the **same Mode-1/Mode-2 logic** as leaves
  (Mode-2 attested apps survive; Mode-1 hard-fail). Safe because the attestation
  key is separate (§8) — a stolen intermediate cannot self-attest.
- **Root:** catastrophic; push a new root (G3) via a core release and distrust
  G2. Primarily incident-response/comms.

### 7.1 Revocation intake (how a revocation is triggered)

All paths converge on the same execution: **edit the ledger** (`status` →
`revoked`, record `revokedFrom` date + reason + actor) → the CRL-generation
workflow republishes. Four cases:

1. **Developer self-service (fully automated, no human).** The developer submits
   a **"Request revocation" GitHub issue form** containing a **CMS/PKCS#7
   SignedData** revocation request (RFC 5652) produced with `openssl cms -sign`,
   signed with the cert's **private key** and with the **certificate embedded**.
   The bot verifies the CMS signature (`openssl cms -verify`), reads the embedded
   signer cert, matches it to the ledger, and revokes automatically. A valid CMS
   signature is proof-of-possession and sufficient authorization — no
   nonce/challenge is needed: revocation is fail-safe and **replay is harmless**
   (re-revoking is idempotent). This follows the ACME cert-key-authenticated
   revocation principle (RFC 8555 §7.6) without running an ACME endpoint. Because
   the cert is embedded, no separate serial/fingerprint field is required, and
   there is no bespoke byte-parity hazard. The OpenSSL command is documented for
   developers.
2. **Privileged internal workflow (authoritative).** A `workflow_dispatch`,
   org-gated workflow revokes **any** cert. Inputs: cert identifier + a **reason
   string**; the **triggering GitHub account** is recorded. This is the path all
   non-self-service revocations ultimately run through.
3. **Third-party / abuse reports.** No dedicated intake — reporters are directed
   to the **GitHub Security Advisory feature (our VDP)** to reach the security
   team, who triage and then act via case 2.
4. **Developer lost their private key.** Case 1 is impossible (cannot sign), so it
   **folds into case 3**: report via the security advisory; the team verifies
   identity out-of-band and revokes via case 2.

---

## 8. Signing-time attestation (Mode 1 / Mode 2 hybrid)

Because apps do not flow through an ownCloud build step, signing time cannot be
attested at publication. Instead:

**Mode 1 — no attested timestamp (default, fully offline/out-of-band):**

- Signature valid only while the leaf cert is within its validity window
  (verify `notBefore ≤ now ≤ notAfter` at install time). Expiry → re-sign.
- **Any revocation is a hard revocation** for Mode-1 signatures: because there is
  no trusted signing time, a revoked cert fails verification for all its Mode-1
  signatures regardless of claimed date (an attacker could otherwise backdate).

**Mode 2 — with an ownCloud-attested timestamp (opt-in, for longevity):**

- The developer submits their signature to the **attestation workflow**; it
  returns a signed token `sign(hash(manifest) + T)` bound to that specific
  manifest; the developer embeds it in `signature.json`.
- The server verifies the cert was valid **at T** → the app keeps installing even
  after the leaf expires; **revoke-from-time** is honored precisely.
- The token binds to `hash(manifest)`, so it cannot be reused to backdate a
  different signature.
- **Trusted time source:** the verifier uses **only** the time `T` bound *inside*
  the signed token. `signature.json` carries **no** plaintext timestamp field
  (§17) — there is nothing attacker-forgeable to misread. All time logic
  (leaf-valid-at-T, revoke-from-time) uses the token-internal `T` exclusively.

| Mode | Signing time known? | Expiry | Revocation |
| --- | --- | --- | --- |
| **Mode 1** | No | valid only within cert window | any revocation = hard |
| **Mode 2** | Yes (trusted T) | survives cert expiry | revoke-from-time honored |

**Security properties:**

- The attestation key is **separate from the intermediate** and has the
  timestamping EKU. A stolen intermediate can mint rogue leaves but cannot
  self-attest — rogue leaves are Mode-1 and hard-fail on revocation, while
  legitimate Mode-2 apps survive.
- The attestation token asserts only "ownCloud saw this manifest hash at T"; it
  does **not** vouch for the signature or CN. The server still independently
  verifies the developer signature and `CN==appId`. Therefore the attestation
  workflow needs no heavy auth: a token for an arbitrary hash is useless without
  a valid leaf cert for that appId.
- Attestation-key compromise (alone) is contained: an attacker can backdate
  tokens but cannot mint leaves, so cannot produce a verifiable malicious app;
  the attestation cert is revoked via the intermediate CRL.
- **Developer responsibility:** engaging with attestation buys longevity and
  precise revocation; staying Mode-1 is simpler but forfeits both on any
  revocation. The choice, and its risk, belong to the developer.

**Intake:** the attestation service is exposed **only as a dispatchable GitHub
Actions workflow** (no manual issue path). No verification-time storage — the
token is self-contained in `signature.json`. Each issuance is recorded in an
**append-only transparency log** in the repo.

**Abuse resistance (not authorization).** The workflow does **not** require
proof of app ownership (a token is security-inert without a matching leaf, so
authorization is unnecessary), but it is **not an open signing oracle** either.
Before issuing a token it checks:

1. **Leaf is real:** the referenced leaf cert exists in the ledger and is active
   (not revoked). (Not authorization — leaf certs are public — but it bounds the
   service to real apps and gives the transparency log meaningful keys.)
2. **The manifest is genuinely signed:** the requester submits the manifest and
   the developer's signature; the workflow **verifies that signature against the
   leaf's key before attesting**. Only the leaf's private-key holder can produce
   it, so one can only obtain a token for a manifest one actually signed.
3. **Rate limiting** (defense-in-depth): per-requester/day caps and workflow
   concurrency limits, handling resource abuse.

This turns the service into "a timestamp for genuinely-signed manifests only":
the transparency log never fills with junk, and there is no standalone value an
attacker could extract from an unbounded oracle — closing the latent risk if
token semantics were ever broadened. The verification is lightweight and
stateless (all inputs are supplied by the requester).

---

## 9. Server-side verification

Per app (given `appinfo/signature.json`; core uses `core/signature.json`):

1. **Parse & algorithm-gate.** Read `v`/`alg`; reject if `alg` is not on the
   allowlist (kills SHA-1 and future-deprecated algorithms).
2. **Chain.** Verify the embedded leaf chains to a bundled trust anchor
   (intermediate → root). Enforce `CA:FALSE`, EKU `codeSigning`.
3. **Manifest signature.** Verify the developer signature over the sorted SHA-512
   manifest using the `alg`-named scheme.
4. **Time + revocation (Mode-1/Mode-2 branch):**
   - Mode 2: verify the attestation token against the bundled attestation-cert
     chain (EKU `timeStamping`); confirm the token's bound `hash(manifest)` equals
     the actual manifest hash; extract **T from inside the verified token**
     (never any plaintext field) → require leaf valid at T → apply
     revoke-from-time against T.
   - Mode 1: require leaf valid at **now**; if the leaf is in the CRL **at all**,
     fail (hard revocation).
5. **Identity.** `CN == appId`. The authoritative `appId` is the `id` declared in
   the app's `info.xml`. If the on-disk directory name and `info.xml` `id`
   disagree, `info.xml` **wins**; on any mismatch that cannot be resolved to a
   single appId, **stop and do not install** (fail with a warning) rather than
   guess. The comparison follows §4.1: ASCII-only case-fold the `info.xml` id,
   validate against `^[a-z][a-z0-9_.-]{2,63}$`, then exact-byte compare to the cert
   `CN` (which is validated strictly, no normalization).
6. **Integrity diff.** Re-hash on-disk files, compare to the signed manifest
   (`FILE_MISSING` / `EXTRA_FILE` / `INVALID_HASH`).

**Scope of a signature (full tree, root-only).** Verification covers the **full
app tree** from the app root. Only the single `appinfo/signature.json` at the app
root (or `core/signature.json` for core) is consulted; its manifest covers every
file beneath the root. Nested directories that happen to resemble apps, or stray
`signature.json` files in subdirectories, are **not** separately verified — they
are just files under the root and are covered (or flagged as `EXTRA_FILE`) by the
root manifest. There is exactly one authoritative signature per app.

**Enforcement:**

- **Mandatory signing for all apps.** No production per-app "ignore missing
  signature" waiver. A **dev-only** exemption remains for the `git`/`''` channel.
- **Hard block only.** Any app failing verification is refused
  (install/update/enable). To keep a failing app running, an admin must
  **consciously disable validation for that specific app**, and that action is
  **logged**. (This also serves as the partner confidentiality escape hatch,
  §11.)
- **Timing.** Verify at install/update (the gate) **and** keep periodic
  full-instance re-verification (the safety net that makes revocation meaningful
  for already-installed apps).

**CRL fetch:** the verifier fetches the CRL from a **core-side constant URL**
(chosen per release), **not** from the cert's CRL DP field, and **does not follow
redirects** (SSRF safety). Certs still carry a CRL DP for external tooling, which
the core verifier ignores. See §12 for the transition rules and §13 for hosting.

**CRL availability (fallback chain).** Revocation checking uses, in order: (1) a
freshly fetched, signature-valid CRL from the constant URL; if that fetch fails or
the CRL fails signature validation, (2) the CRL **bundled in the release**
(`resources/codesigning/crl/`). If **neither** yields a valid CRL, the verifier
**stops** — install/update is refused (fail-closed). A stale-but-valid CRL is
accepted ("stale is stale, work with what we have"); the only fail-closed trigger
is having *no* valid CRL at all.

---

## 10. Enrollment identity

- **No explicit OAuth**; rely on native GitHub issue-author authentication +
  public API reads. Minimal bot permissions (read issues/comments, post comments,
  read public repo contents).
- **Identity is always a GitHub account** (intake is always a GitHub issue), even
  when the target repo is on GitLab.
- Record: login + stable numeric user ID + repo + issueRef + timestamp. No email.
- Requester and nonce-committer are **not** tied.
- Schema is origin-tagged and prefix-extensible for a future GitLab **repo**
  origin (which requires extending the nonce checker — documented, not built).

---

## 11. Closed-source / partner enrollment

Same cert profile, CA, and server verification as third-party; only the
control-proof step differs (manual, contract-backed identity of the authorized
contact). Low volume (1–2 digits). **Option A: single public repo, no split.**

- **Intake:** a **privileged internal workflow** (`workflow_dispatch`, gated to
  org members — not triggerable by external issue filing) plus an internal
  form/script ensuring correct team processing (contractual identity check, CSR
  validation, owner-prefix rule).
- **Issuance:** same intermediate, `origin=partner`, `owner=<partner ID>`. The
  cert is documented and **appended to the same public ledger**.
- **Two paths for partners:**
  - **Public app** → the regular GitHub flow like anyone else (no prefix).
  - **Private app** → the appId **must be prefixed with the owner**
    (`CN=<partnerid>_<app>`, ships on disk that way).
- **Known limitation (documented):** the owner-prefix is a **convention, not a
  reserved namespace** — a public developer could still claim a `<partnerid>_`
  flat appId. The real collision-resolver is FCFS + manual override; the prefix
  only reduces accidental collisions and aids attribution/squatting-detection.
  Academic risk at this scale.
- **Confidentiality escape hatches** for a partner wanting no public footprint:
  (a) fully out-of-band issuance (manual exception), or (b) don't sign + use the
  per-app admin validation disable (§9) — which **forfeits all protections** (no
  integrity check, no revocation; admin owns the risk). Stated plainly.

---

## 12. Trust anchor distribution and legacy migration

**What ships in core** (`resources/codesigning/`):

- `roots/` — the trust anchor(s): `root-g2.crt`. During transitions, multiple
  roots coexist (legacy G1 during migration; future G2+G3). The verifier trusts a
  chain validating to **any** root present — this is what makes both root
  rotation and legacy migration work without a flag day.
- `intermediates/` — current intermediate(s), bundled for chain-building
  robustness (not strictly required; artifacts embed their chain).
- `crl/` — the seed CRL, refreshed online (§9, §13).

**Principle:** core ships **trust anchors (roots), not the population of issued
certs.** Leaf + attestation + intermediate certs travel **embedded in
`signature.json`**.

**Deployment reality:** most ownCloud 11 installs are clean (11 ships as a Docker
image; 10.x was mostly non-Docker PHP), so the legacy-signature burden on upgrade
is small. Nonetheless a bounded transition is provided.

**Three-case transition:**

1. **Invalid signature / tampered manifest** → **hard block**, always. No
   leniency ever.
2. **Valid G1 (legacy) chain, cert expired** → **warn + allow**, with the expiry
   check **skipped** and the legacy SHA-1/RSA-PSS algorithm temporarily on the
   allowlist — but **only if not revoked in the bundled legacy CRL**, and **only
   until the sunset**. This is the single warn-not-block exception to the
   hard-block rule.
3. **Valid G2 chain** → full validation (§9).

**Sunset — 2026-12-31, enforced by a hardcoded date in the verifier**, NOT by an
upgrade. A customer who freezes their version to avoid a "G1 removal" release
still loses G1 acceptance on that date, because the code they already run enforces
it. After sunset, case 2 folds into case 1; G1, the legacy CRL, and the legacy
algorithm are gated off even though the files may remain present. A later release
may physically delete the inert G1 files (cosmetic).

**Accepted risks:**

- The **legacy CRL is bundled once and not refreshed online**. If a G1 cert is
  compromised during the window, we cannot push its revocation. Bounded and
  accepted.
- The sunset is a wall-clock cutoff; an admin who sets the clock back can extend
  it locally. Self-inflicted; out of scope.

---

## 13. CRL hosting

- **Start with GitHub Pages, default `github.io` URL (Option B):**
  `https://owncloud.github.io/developer-certificates/crl/` (leaf =
  `developers.crl`, plus `intermediate.crl`, `root.crl`). The CRL is generated by
  the ledger workflow, committed into the repo, and served over the Pages/Fastly
  CDN. Maximally co-located with the ledger.
- The verifier uses a **core-side constant URL** and does **not** follow
  redirects (§9).
- **Future migration to a custom domain (Option C):** done as a **code change to
  a new URL constant plus independent hosting for the new host** — NOT by adding a
  Pages custom domain to the same repo (which would 301-redirect the `github.io`
  URL and break old, non-redirect-following clients). The original `github.io`
  URL must keep returning 200 so already-deployed instances continue to work.
- Content-type is irrelevant: our own verifier fetches and parses by content, not
  MIME.

---

## 14. Signing layers (relationship)

**Two layers, clearly scoped — not three:**

| Layer | Protects | Verifier | When | Anchor |
| --- | --- | --- | --- | --- |
| **PKI app-integrity** (this design) | each app/core file tree | ownCloud **server** | install/update + periodic | baked-in root |
| **GPG tarball** (`ocrelease` `keys/`, unchanged) | the whole release archive bytes | **admin / download tooling** | at download | GPG key from keyserver |

- The concept of a separate **"full application signature" is dropped** — core is
  covered by layer 1 (its `core/signature.json`, via a first-party cert).
- **GPG tarball signing stays** for release archives. Unifying it into the PKI is
  explicitly deferred/optional.

---

## 15. First-party (ownCloud) signing

- **Model A — pipeline-issued reserved certs.** ownCloud's own apps and core get
  certs through a privileged internal path tied to the `ocrelease` pipeline
  (identity = control of the CA/pipeline). Keys live in the release pipeline's
  secret management.
- **Same cert profile and same server verification** as third-party — this is
  what satisfies "similar to other developers" where it matters (the trust
  model). Only enrollment differs.
- **Shipped apps** (the first-party apps bundled with core) get `CN=<appId>`
  leaves. The legacy `CN=core` "always trusted" magic is **removed**; a shipped
  app is verified by the same `CN==appId` rule as any app.
- **Core itself** gets a dedicated reserved first-party cert under the new PKI,
  verified via the core-signature path (chain + revocation the modern way).
- The **ledger pre-reserves all first-party appIds and the core identity** at
  bootstrap so no third party can obtain them.

---

## 16. Developer key protection

- **Self-custody:** we **never** generate or hold a developer's private key. The
  developer generates the keypair locally and sends only the CSR.
- **Tiered guidance:**
  - *Baseline (all):* never commit/bundle the key; restricted permissions;
    passphrase-encrypted at rest.
  - *CI signing (most):* key as an encrypted CI secret used by a release
    workflow (reference GitHub Actions workflow provided). This is a "warm" key —
    use environment protection rules / required reviewers on the signing job.
  - *High-assurance (partners, high-value apps):* hardware-backed keys — HSM,
    cloud KMS (AWS/GCP KMS), or hardware token. EC P-384 is well-supported.
- The design **rewards** good hygiene: multiple concurrent certs allow separate
  CI vs. release keys; Mode-2 attestation gives resilience against later
  revocation; cheap 2-year rotation.
- **Our own keys (requirements, not guidance):** root offline / cold storage /
  HSM, air-gapped; intermediate in vault/KMS with tight access + audit;
  attestation key separate, in vault; first-party signing keys in the release
  pipeline's secret management.

---

## 17. Certificate delivery and packaging

- **What the developer receives** from enrollment: the **leaf certificate** (PEM)
  and the **intermediate certificate** (PEM). Never a private key.
- **`signature.json` v2:**

```json
{
  "v": 2,
  "alg": "ecdsa-p384-sha384",
  "hashes": { "<relativePath>": "<sha512-hex>", "...": "..." },
  "signature": "<base64 developer signature over the canonical sorted hashes>",
  "certificates": {
    "leaf": "<PEM leaf cert (CN=appId)>",
    "chain": ["<PEM intermediate cert>"]
  },
  "attestation": {
    "token": "<base64 sign(hash(manifest)+T)>",
    "certificate": "<PEM attestation cert (timeStamping EKU)>"
  }
}
```

- `attestation` is **optional** — present only for Mode 2; absent = Mode 1.
- **No plaintext timestamp field.** The trusted time `T` exists **only** inside
  the signed `token`; the verifier decodes it from the verified token and uses
  that value exclusively (see §8). There is deliberately no attacker-forgeable
  plaintext copy. A debugging tool can display `T` by decoding the token.
- **Locations unchanged:** `appinfo/signature.json` (apps), `core/signature.json`
  (core). The `signature.json` file is excluded from its own manifest.
- **Everything the verifier needs beyond the root is embedded** (leaf, chain,
  attestation cert). Only the root is baked into core.
- Adding attestation after signing is safe: the manifest never hashes
  `signature.json`, so rewriting it to inject the `attestation` block invalidates
  nothing.

---

## 18. Signing tool

- **Standalone Go CLI**, decoupled from the server (the legacy `occ`
  integrity:sign-app required a bootstrapped ownCloud instance — a flaw we do not
  repeat).
- Single static cross-platform binary; core crypto entirely in the Go standard
  library (`crypto/ecdsa`, `crypto/sha512`, `crypto/x509`, `encoding/pem`,
  `encoding/json`).
- Flags: `--path`, `--key`, `--cert`, `--chain`, `--attest`.
- The tool owns the **canonicalization** (the risky part) so developers cannot
  get file-exclusion / sort / encoding rules subtly wrong. A precisely documented
  canonicalization spec + **golden test vectors** (shared with the server
  verifier) make it re-implementable and vibe-codeable. See the Go signing tool
  companion spec.

---

## 19. CA bootstrap ceremony

The one-time procedure to stand up the PKI. Phases 1–2 (root + intermediate
signing) happen in an **offline/air-gapped ceremony**; the root key never touches
a networked machine afterwards except for the rare intermediate-signing or
root-CRL-signing ceremony. Commands below use `openssl` for illustration; exact
key-storage commands depend on the chosen medium (see "Key storage" notes).

### Phase 1 — Root CA (offline)

```sh
# 1. Root EC P-384 private key (kept in cold storage / offline HSM)
openssl ecparam -name secp384r1 -genkey -noout -out root-g2.key

# 2. Self-signed root certificate, 25 years
openssl req -new -x509 -key root-g2.key -sha384 -days 9125 \
  -subj "/C=DE/O=ownCloud GmbH/CN=ownCloud Code Signing Root CA G2" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out root-g2.crt
```

**Key storage (generic):** store the root private key in cold storage. Options —
an offline HSM / hardware token (non-exportable key; the usual choice for a root
touched only a handful of times in 25 years), an air-gapped machine with the key
on encrypted removable media, or an isolated cloud KMS. The design does not
mandate one; whatever is chosen must keep the root key offline and export-proof.

### Phase 2 — Intermediate CA (same offline ceremony)

```sh
# 3. Intermediate EC P-384 key (destined for the vault; see below)
openssl ecparam -name secp384r1 -genkey -noout -out intermediate-g2.key

# 4. Intermediate CSR
openssl req -new -key intermediate-g2.key -sha384 \
  -subj "/C=DE/O=ownCloud GmbH/CN=ownCloud Code Signing Intermediate CA G2" \
  -out intermediate-g2.csr

# 5. Root signs the intermediate, 5 years, with EKU codeSigning + CRL DP
openssl x509 -req -in intermediate-g2.csr -CA root-g2.crt -CAkey root-g2.key \
  -CAcreateserial -sha384 -days 1825 \
  -extfile <(printf "%s\n" \
    "basicConstraints=critical,CA:TRUE,pathlen:0" \
    "keyUsage=critical,keyCertSign,cRLSign" \
    "extendedKeyUsage=codeSigning" \
    "subjectKeyIdentifier=hash" \
    "authorityKeyIdentifier=keyid:always" \
    "crlDistributionPoints=URI:https://owncloud.github.io/developer-certificates/crl/root.crl") \
  -out intermediate-g2.crt
```

**Key storage:** move the intermediate private key into **HashiCorp Vault**
(assumed available). Other options (cloud KMS such as AWS/GCP KMS, or another
vault) are equivalent. Prefer Vault's **Transit secrets engine** so the issuer
signs *through* Vault (send data, receive signature) and the key **never leaves
Vault / never lands in a GitHub Actions runner**. Pulling the raw PEM into the
runner is a weaker fallback to avoid if possible.

### Phase 3 — Attestation certificate (under the intermediate)

```sh
# 6. Attestation EC P-384 key — SEPARATE key from the intermediate
openssl ecparam -name secp384r1 -genkey -noout -out attestation-g2.key

# 7. CSR + intermediate signs it, EKU timeStamping, CA:FALSE
openssl req -new -key attestation-g2.key -sha384 \
  -subj "/O=ownCloud GmbH/CN=ownCloud Timestamp Attestation" \
  -out attestation-g2.csr
openssl x509 -req -in attestation-g2.csr \
  -CA intermediate-g2.crt -CAkey intermediate-g2.key -CAcreateserial \
  -sha384 -days <attestation-validity> \
  -extfile <(printf "%s\n" \
    "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=critical,timeStamping" \
    "subjectKeyIdentifier=hash" \
    "authorityKeyIdentifier=keyid:always") \
  -out attestation-g2.crt
```

Store the attestation key in Vault (same as the intermediate; Transit engine
preferred), used only by the attestation workflow.

### Phase 4 — Seed CRLs

Generate an initial **empty root CRL** (signed by the root, in the offline
ceremony) and an initial **empty intermediate CRL** (signed by the intermediate).
These become the seed CRLs bundled in core and published to the CRL URL.

### Phase 5 — Ledger seeding (first-party reservations)

Pre-claim **all first-party appIds and the core identity** in the ledger repo so
no third party can ever obtain them (§15). Commit the reservation ledger files.

### Phase 6 — Bake into core and first release

Place into the core tree (§12):

- `resources/codesigning/roots/root-g2.crt`
- `resources/codesigning/intermediates/intermediate-g2.crt` (chain-building)
- `resources/codesigning/crl/` — the seed CRLs

Ship the release. The PKI is live: the bot can issue leaves, developers can
enroll, and servers can verify.

---

## Appendix A — Topics covered (coverage map)

Every topic raised during design, and its disposition. "Decided" = resolved in
this document. "Deliverable" = decided in principle; detailed artifact lives in a
companion spec. "Deferred" = intentionally out of scope for now.

| # | Topic | Status | Section |
| --- | --- | --- | --- |
| 1 | Per-app vs per-dev certificates | Decided (per-app) | §2.3, §4 |
| 2 | Trust hierarchy (3 tiers) | Decided | §2 |
| 3 | Root cert profile | Decided | §2.1 |
| 4 | Intermediate cert profile | Decided | §2.2 |
| 5 | Leaf cert profile (CN=appId, no custom OID, cosmetic O/OU) | Decided | §2.3 |
| 6 | Attestation cert profile (separate key, timeStamping EKU) | Decided | §2.4, §8 |
| 7 | Signing algorithm & key params (EC P-384, ECDSA-SHA384, SHA-512) | Decided | §3 |
| 8 | Crypto-agility (alg+version field, allowlist) | Decided | §3 |
| 9 | PQC posture | Deferred (agility path) | §3 |
| 10 | Namespace model (`origin:owner/appId`, flat on-disk appId) | Decided | §4 |
| 11 | Owner = repo owner (Option 1) | Decided | §4 |
| 12 | CSR content vs authoritative fields | Decided | §2.3, §5.2 |
| 13 | CSR collection (GitHub issue form + bot) | Decided | §5.2 |
| 14 | Nonce mechanism | Decided | §5.3 |
| 15 | Nonce file path (`/.well-known/owncloud-codesigning-challenge.txt`) | Decided | §5.3 |
| 16 | Enrollment identity (no OAuth; GitHub-native) | Decided | §10 |
| 17 | Issuance ledger (public git repo, FCFS, same repo as intake) | Decided | §6 |
| 18 | Multiple certs per app (allowed, concurrent) | Decided | §6, §7 |
| 19 | Expiration structure (25y/5y/2y, timestamp model) | Decided | §7 |
| 20 | Intermediate rotation cadence (~2.5y remaining) | Decided | §7 |
| 21 | Revocation (CRL only, revoke-from-time) | Decided | §7, §9 |
| 22 | Signing-time attestation (Mode-1/Mode-2 hybrid) | Decided | §8 |
| 23 | Attestation intake (workflow only) + transparency log | Decided | §8 |
| 24 | Server-side verification (6-step, hard-block, per-app disable) | Decided | §9 |
| 25 | Cert rotation / emergency processes (all tiers) | Decided | §7 |
| 26 | First-party signing (Model A) | Decided | §15 |
| 27 | Signing-layer relationship (two layers; GPG retained) | Decided | §14 |
| 28 | Partner / closed-source enrollment | Decided | §11 |
| 29 | Trust anchor distribution + legacy migration + sunset | Decided | §12 |
| 30 | Developer key protection + our own key protection | Decided | §16 |
| 31 | Certificate delivery / packaging (signature.json v2) | Decided | §17 |
| 32 | Signing tool (standalone Go CLI) | Decided | §18 |
| 33 | CRL hosting (GitHub Pages B → future C) | Decided | §13 |
| 39 | Revocation intake (4 cases; signed self-service + privileged workflow) | Decided | §7.1 |
| 40 | AppId format & comparison (impersonation defense) | Decided | §4.1 |
| 41 | Trusted attestation time (token-internal only; no plaintext field) | Decided | §8, §17 |
| 42 | AppId ↔ info.xml reconciliation; enforcement at install | Decided | §5.2 |
| 43 | CA bootstrap ceremony | Decided | §19 |
| 44 | CRL availability fallback chain (fail-closed if no valid CRL) | Decided | §9 |
| 45 | Signature scope (full tree, root-only signature) | Decided | §9 |
| 46 | Ledger single-concurrency serialization (FCFS TOCTOU) | Decided | §6 |
| 47 | Attestation abuse resistance (leaf+signature verify before attesting) | Decided | §8 |
| 48 | info.xml-vs-on-disk mismatch handling (info.xml wins; stop on unresolved) | Decided | §9 |
| 34 | Enrollment bot implementation | Deliverable | companion spec |
| 35 | Attestation / CRL workflows implementation | Deliverable | companion spec |
| 36 | Core verifier implementation | Deliverable | companion spec |
| 37 | Go signing tool implementation + canonicalization + test vectors | Deliverable | companion spec |
| 38 | External developer documentation + issue-form YAML | Deliverable | companion spec |

## Appendix B — Known gaps / things to revisit

- **GitLab repo origin:** nonce-checking against GitLab is designed-for but not
  implemented; schema is prepared.
- **Partner private-appId collision:** owner-prefix is a convention, not enforced
  reservation; FCFS + manual override is the backstop.
- **Legacy CRL not refreshed:** cannot revoke a compromised G1 cert during the
  transition window.
- **Clock-tampering:** sunset and Mode-1 expiry rely on server clock; deliberate
  tampering is out of scope.
- **Canonicalization parity:** the single highest-risk implementation detail —
  the Go signer and the PHP verifier must agree byte-for-byte. Golden test
  vectors are the mitigation.
- **`.htaccess` / `.user.ini` special-casing:** **resolved and confirmed** against
  the `base` repo. App mode uses only the signature file + OS-cruft exclusions.
  Core mode: `.htaccess` marker-split verbatim (required — `base/.../50-apache.sh`
  runs `occ maintenance:update:htaccess` at every container start); `.user.ini`
  hashed as-is (the base entrypoint renders PHP config into a separate
  `owncloud.ini` from env, never into `.user.ini`; Apache+mod_php ignores
  `.user.ini` anyway). See Go signing tool spec §3.6. (Aside: the in-tree
  `.user.ini` is cosmetically stale in Docker — flag to the core team, no signing
  impact.)
- **Attestation token `bind(H, T)` byte layout (⚠️ item #2):** the exact bytes
  signed to bind manifest hash and timestamp are **not yet fixed**; blocks Mode-2
  implementation. See the attestation/CRL workflows spec §5.
- **Operational identifiers: decided** — repo `owncloud/developer-certificates`;
  CRL URLs under `https://owncloud.github.io/developer-certificates/crl/`
  (`developers.crl`, `intermediate.crl`, `root.crl`). See the header block.
- **Decided operational values:** attestation cert validity = 3 years; issuer/
  revocation poll cadence = 10 min; CRL regeneration = daily, `nextUpdate` = +7d.
- **Mode-1 revocation punishes good history (G1):** a developer who never
  attested loses *all* releases (including old, good ones) on any revocation of
  their cert. Accepted; no immediate action. Revisit with a grace/notification
  path only if this becomes a real operational pain point.
- **Nested/duplicate signatures (C2):** only the app-root `signature.json` is
  authoritative; the full tree is verified against it. Nested app-like
  directories or stray sub-directory `signature.json` files are not separately
  verified (they are covered as ordinary files by the root manifest). See §9.
- **AppId reassignment / abandonment (C3):** FCFS binds appId→repo indefinitely.
  Legitimate takeover of an abandoned app, a deleted repo, or an ownership
  transfer is currently handled **only by manual override** (admin edits the
  ledger and revokes/ supersedes as needed). No automated reassignment flow.
- **Downgrade / rollback (C4):** nothing prevents installing an older,
  validly-signed version of an app with a known vulnerability; all old versions
  remain validly signed (Mode-2 indefinitely). **Out of scope** for this PKI —
  code-signing establishes authenticity/integrity, not version currency.
- **Transient repo write = enrollment (S2):** the authorization gate is "can
  commit the nonce to the repo," which is *write control*, not *ownership*. Anyone
  with even transient write access (e.g. a briefly-merged PR, a misconfigured
  branch protection) can complete the challenge. This is weaker than "owner" and
  is accepted; FCFS + manual override is the backstop for abuse.
- **Dev-channel signing bypass (S4):** the `git`/`''` channel exemption disables
  signing enforcement globally (needed for development). An attacker able to flip
  the instance channel config to `git` thus disables all enforcement at once — a
  broader switch than the logged per-app disable. Accepted as inherent to
  supporting local development; hardening (e.g. logging/guarding channel changes)
  is a possible future improvement.
- **Ledger is issuance-time only; no protection vs. a compromised intermediate
  (S5):** the server's `CN==appId` check trusts the CA completely and does not
  consult the ledger at verify time. A stolen intermediate key can therefore mint
  a valid leaf for *any* appId, including already-claimed ones, and the server
  accepts it (Mode-1, until revocation). Intermediate revocation (all-or-nothing,
  per §7) is the only remedy. Inherent to any CA compromise; stated explicitly.

  **Status: accepted (reviewed).** A verify-time *ledger-inclusion* control was
  proposed — require the leaf's serial/fingerprint to be present in a published
  active-set, else fail (`NOT_IN_LEDGER`) — to catch a rogue-but-valid-chaining
  leaf. The proposal correctly notes that the **CRL is a denylist and structurally
  cannot catch a forged leaf** (never issued → never revoked → absent from the
  CRL). It is nonetheless **declined**, because a verify-time positive-inclusion
  gate changes the trust model rather than hardening this one:
  - It moves the trust anchor off the certificate chain. In a standard PKI, "was
    this issued by us?" *is* "does it chain to our root and validate." Requiring an
    additional central allowlist at verify time asserts the chain is no longer
    sufficient — a different architecture, not a reinforcement of this one.
  - It is internally inconsistent unless applied everywhere: the same logic would
    force a central "did we really issue this?" check on the Mode-2 attestation
    cert/tokens and on the app signatures themselves, dissolving the PKI into a
    centralized signing/verification oracle.
  - It **breaks offline verification** (a hard requirement for air-gapped
    installs). An online-only, fail-open-when-offline check is not a guarantee: an
    attacker holding the intermediate key can also suppress the active-set fetch and
    reach the fail-open path — raising the bar only from "steal the key" to "steal
    the key and block one fetch."
  - Intermediate-key compromise is the **standard CA-compromise assumption**, whose
    accepted remedy is intermediate revocation (§7). The primary control is
    protecting the intermediate key (Vault Transit so the key never leaves;
    HSM/tight-access/audit to raise the bar).

  The legitimate kernel — chain-to-root does not *detect* misissuance — belongs to
  the separately-deferred **transparency-log / external-monitoring** work
  (Certificate-Transparency-style **detection** enabling fast revocation, off the
  verify path, preserving offline verification), **not** to a verify-time gate.
  Cross-reference, do not couple: that work would shrink S5's *window*, not change
  the trust model.
