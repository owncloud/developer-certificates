# Spec — Enrollment & Revocation Bot

**Companion to:** `2026-07-06-owncloud-code-signing-pki-design.md`
**Status:** Implementation spec, buildable ("vibe-codeable") from this document
alone.
**Audience:** whoever implements the GitHub App + Actions automation that runs the
CA issuer and revocation.

> **Examples** use placeholders (`example-app`, `example-org`, `example-user`).
> The single repository that hosts intake (issues), the ledger (files), the CRL,
> and the workflows is referred to as **the codesigning repo**.

---

## 1. Components overview

All in one public GitHub repo (the codesigning repo):

- **Issue intake** — issue forms for CSR requests and revocation requests.
- **Issuer bot** — an Actions workflow (polling) that processes CSR issues:
  identity + repo-control checks, appId reconciliation, FCFS ledger claim, cert
  issuance (signing via Vault), ledger update, posts the cert back.
- **Revocation bot** — processes signed self-service revocation requests
  (automated) and the privileged internal revocation workflow.
- **Ledger** — `ledger/<appId>.json` files (design §6), plus reserved first-party
  entries.
- **CRL generation** — see the attestation/CRL workflows spec.

Signing keys (intermediate; attestation) live in **HashiCorp Vault**; the bot
signs **through Vault's Transit engine** (key never enters the runner — design
§19).

---

## 2. Global rules (apply to every workflow here)

- **Single concurrency for ledger writes.** All workflows that read-then-write the
  ledger MUST run under a global GitHub Actions `concurrency` group with
  `cancel-in-progress: false`, serializing them (design §6, P2). Additionally,
  commit to the ledger with conflict-retry (re-read, re-apply, re-push) as a
  second safeguard.
- **Read only the bot's own comments.** Any workflow reading state from an issue
  MUST filter comments to those authored by the bot/App identity. Never parse
  arbitrary user comments (design §5.3).
- **Polling, not comment-triggered.** The issuer bot runs on a schedule
  (`schedule:` cron) and on issue events; it does not act on human comment events.
- **Minimal permissions** (design §10): read issues/comments, write comments &
  labels, read public repo contents (of target repos), write to the ledger/CRL
  paths. No broad org scopes.

---

## 3. CSR intake (issue form)

Fields (exactly two; design §5.2, P1 option a):

- **CSR** (textarea) — PEM `CERTIFICATE REQUEST`.
- **Target repo** (`owner/name`).

Derived, not asked: `requester` = authenticated issue author; `owner` = repo
owner; `origin = github`. The full form YAML is in the developer-documentation
spec.

---

## 4. Issuer bot pipeline (per open CSR issue)

Run under the single-concurrency ledger lock (§2). Steps:

1. **Parse the form.** Extract CSR PEM and target repo. Malformed → comment the
   error, label `invalid`, stop.
2. **Validate the CSR.** Parse it; check key type against the allowlist (EC P-384;
   or RSA ≥ 3072 / RSA-4096 fallback; reject weak/unknown curves). Verify the CSR
   self-signature (proof of possession). Failure → comment + `invalid`, stop.
3. **Derive & canonicalize appId.** Read the CSR `CN`; ASCII-lowercase + validate
   against `^[a-z][a-z0-9_-]{1,63}$` (design §4.1). Failure → comment + stop.
4. **Read repo info.xml.** Fetch `appinfo/info.xml` from the **default branch** of
   the target repo (record the commit SHA). Extract the app `id`; ASCII-lowercase
   and validate. Absent file or non-conforming id → comment and stop.
5. **Reconcile.** Canonical CSR `CN` MUST equal canonical `info.xml` id. Mismatch →
   comment explaining, label `needs-changes`, stop. The canonical value is the
   **appId** used henceforth; the issued cert `CN` will be exactly this.
6. **Issue a nonce challenge.** If no active nonce for this issue: generate a
   random 256-bit nonce, store it by posting a **bot comment** with the value and
   instructions (commit it to `/.well-known/owncloud-codesigning-challenge.txt` on
   the default branch), set an expiry of 72h (tracked via the comment timestamp),
   label `awaiting-challenge`, stop (the poll loop re-enters later).
7. **Verify the challenge** (on a later poll). Read the nonce from the **bot's own
   comment** (§2). Fetch `/.well-known/owncloud-codesigning-challenge.txt` from the
   target repo default branch via the API; compare to the stored nonce. If absent
   or mismatched and within 72h → stay `awaiting-challenge`, stop. If past 72h →
   expire (comment, label `expired`), stop.
8. **FCFS ledger check.** Read `ledger/<appId>.json`:
   - **Absent** → new claim. Proceed to issue; will create the file bound to the
     target repo as `owner`.
   - **Present** and `owner.repo == target repo` → allowed (renewal / additional
     cert). Proceed.
   - **Present** and `owner.repo != target repo` → **reject** (appId owned by
     another repo). Comment, label `rejected`, stop.
   - Reserved first-party appId (pre-seeded) → reject for third parties.
9. **Issue the certificate.** Build the leaf per the design §2.3 profile
   (`CN = <appId>`, `O = <owner>`, `OU = github`, EC P-384, `CA:FALSE`,
   `keyUsage digitalSignature`, EKU `codeSigning`, SKI/AKI, CRL DP, 2y validity
   capped to `min(now+2y, intermediate.notAfter)`). **Sign via Vault Transit**
   under the current intermediate. Serial = random 128-bit.
10. **Update the ledger.** Create/append the `certificates[]` entry (serial,
    fingerprint, notBefore/notAfter, requester {origin, login, userId}, issueRef,
    status `active`). Commit under the concurrency lock with conflict-retry.
11. **Deliver.** Post a bot comment with the issued **leaf PEM** + the
    **intermediate PEM** (chain). Label `issued`, close the issue.

Idempotency: if the issue is already `issued`, re-runs no-op. All comments the bot
relies on later are bot-authored.

---

## 5. Revocation (design §7.1)

### 5.1 Self-service, signed (fully automated)

Revocation-request issue form fields:

- **Cert identifier** — serial and/or SHA-256 fingerprint of the cert to revoke.
- **Signed revocation request** — a small statement, signed with the cert's
  **private key**, binding the cert identifier + revoke intent. (The exact
  statement format and the OpenSSL command to produce it are in the developer-doc
  spec.)

Bot pipeline (under the ledger lock):

1. Look up the cert in the ledger by serial/fingerprint. Not found → comment,
   stop.
2. Load the cert's **public key** from the ledger/embedded cert. **Verify the
   signed revocation request** against that public key. Invalid → comment
   `invalid`, stop. (Proof-of-possession = authorization; no nonce needed. Replay
   is harmless/idempotent.)
3. Flip the ledger entry `status` → `revoked`; record `revokedFrom`
   (default: `notBefore` for a hard revoke, or a requester-supplied date ≥
   `notBefore`) and `reason = "self-service"`. Commit.
4. Trigger CRL regeneration (attestation/CRL spec). Comment `revoked`, close.

### 5.2 Privileged internal revocation (authoritative)

A `workflow_dispatch` workflow, **gated to org members** (not triggerable by
external issue filing):

- Inputs: cert identifier, `reason` (string), `revokedFrom` (date; default
  `notBefore`).
- Records the **triggering GitHub account** (`actor`).
- Flips ledger `status` → `revoked` with `revokedFrom`, `reason`, `actor`. Commit.
- Triggers CRL regeneration.

This is the path that third-party/abuse reports (via the GitHub Security Advisory
/ VDP) and lost-key cases (design §7.1 cases 3–4) ultimately run through, after
human triage.

---

## 6. Partner issuance (design §11)

A **privileged internal workflow** (`workflow_dispatch`, org-member gated — not
externally triggerable), plus an internal checklist/script ensuring correct
processing:

- Inputs: partner CSR, assigned `owner` (partner ID), and — for a **private** app
  — the appId which **must** be owner-prefixed (`<partnerid>_<app>`, design §11).
  A **public** partner app instead goes through the normal §4 flow (no prefix).
- The human operator performs the contractual identity check out-of-band before
  running the workflow.
- The workflow validates the CSR + appId (§4.1), does the FCFS ledger check,
  issues via Vault under the same intermediate with `OU = partner`,
  `O = <partner ID>`, and appends to the **same public ledger**.
- Known limitation (design §11): the owner-prefix is a convention, not a reserved
  namespace; FCFS + manual override is the backstop.

---

## 7. Ledger reservations (bootstrap; design §15, §19 Phase 5)

Pre-seed `ledger/` with entries reserving **all first-party appIds** and the
**core identity** (owner = the reserved first-party owner), so the FCFS check in
§4 step 8 rejects any third-party attempt to claim them. These entries are created
during the CA ceremony, before the first release.

---

## 8. Manual override (disputes; design §6)

No automated anti-squatting. Disputes (squatting, appId reassignment of an
abandoned app, repo transfer — design Appendix B C3) are resolved by an org member
**editing the ledger directly** (and revoking via §5.2 as needed). Because the
ledger is a git repo, every override is an auditable commit.

---

## 9. Failure/label vocabulary (issues)

`invalid` (bad CSR/form), `needs-changes` (appId mismatch), `awaiting-challenge`,
`expired` (nonce timeout), `rejected` (FCFS/reserved), `issued`, `revoked`.
Every terminal state has an explanatory bot comment.

---

## 10. OpenSSL / interoperability compatibility (REQUIRED)

Developers use the OpenSSL CLI to create CSRs and signed revocation requests, so
the bot MUST interoperate with standard OpenSSL output:

- Parse standard OpenSSL CSRs and PEM keys/certs.
- The **signed revocation request** the bot verifies MUST be exactly what the
  documented OpenSSL command produces (developer-doc spec §6). The bytes signed
  (the "revocation statement") and the signature encoding must agree
  byte-for-byte between the documented command and the bot's verifier — the same
  canonicalization discipline as the manifest. Cross-test against the `openssl`
  CLI in CI.

## 11. Open items

- **Poll cadence: 10 minutes** (decided). The issuer/revocation polling workflow
  runs on a `*/10 * * * *` schedule; nonce expiry (72h) is tracked from the bot
  comment's creation timestamp.
- **Exact signed-revocation-request statement format** (what bytes are signed):
  define alongside the developer-doc OpenSSL command so the bot's verifier and the
  documented command agree byte-for-byte (see §10).
