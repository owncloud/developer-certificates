# Spec — Core Server Verifier

**Companion to:** `2026-07-06-owncloud-code-signing-pki-design.md`
**Status:** Implementation spec, buildable from this document alone.
**Audience:** whoever reimplements `OC\IntegrityCheck\Checker` (PHP) for the new
PKI. MUST share the canonicalization rules and golden vectors with the Go signing
tool spec (`2026-07-06-spec-go-signing-tool.md` §3, §8).

> **Examples** use placeholders (`example-app`, `example-org`).

---

## 1. Scope

Replace the verification half of the legacy `OC\IntegrityCheck\Checker`. The
signing half (`integrity:sign-*`) is superseded by the standalone Go tool and is
removed from core (or left only for `--core` first-party signing in the pipeline;
see the design §15).

The verifier's job: given an app directory (or the core root), decide **pass /
fail** and, on failure, produce a structured diff. Enforcement (hard block,
per-app disable) is in §6.

---

## 2. What ships in core

Under `resources/codesigning/` (design §12):

- `roots/` — trust anchors: `root-g2.crt` now; during the transition also the
  legacy anchor `root-g1.crt`; in future `root-g3.crt`. The verifier trusts a
  chain that validates to **any** cert present in `roots/`.
- `intermediates/` — current intermediate(s), for chain-building fallback.
- `crl/` — seed CRLs (leaf CRL under the intermediate; intermediate CRL under the
  root; plus the frozen legacy CRL during the transition).

**Constants baked into the build:**

- `CRL_URL` — the core-side constant CRL fetch URL (design §9, §13). Not read from
  the cert's CRL DP.
- `LEGACY_SUNSET = 2026-12-31T23:59:59Z` — the hardcoded G1 transition cutoff
  (design §12).
- `ALG_ALLOWLIST` — permitted `alg` values (see §3).

---

## 3. Algorithm allowlist (crypto-agility gate)

`signature.json` carries `v` and `alg`. The verifier reads them first and rejects
anything not in the allowlist.

- `v = 2`, `alg = "ecdsa-p384-sha384"` — primary.
- `v = 2`, `alg = "rsa-pss-sha384"` — RSA-4096 fallback.
- **Legacy (only while `now < LEGACY_SUNSET`, and only for G1 chains):** the
  legacy RSA-PSS-SHA1 scheme. After sunset this is removed from the effective
  allowlist even if the code/files remain (design §12).
- Anything else → reject (fail).

---

## 4. Verification algorithm (per app)

Input: an app root directory with `appinfo/signature.json` (or the server root
with `core/signature.json`).

1. **Parse & algorithm-gate.** Load `signature.json`; read `v`/`alg`; if `alg`
   not permitted per §3 → **fail** (`BAD_ALGORITHM`).
2. **Chain.** Parse `certificates.leaf` and `certificates.chain[]`. Build and
   validate the chain leaf → intermediate → a root in `roots/`. If `chain[]` is
   empty, use a bundled intermediate from `intermediates/`. Enforce on the leaf:
   `basicConstraints CA:FALSE`, `keyUsage digitalSignature`, `extendedKeyUsage`
   contains `codeSigning`. On any failure → **fail** (`BAD_CHAIN`).
3. **Manifest signature.** Reconstruct the canonical manifest bytes `M` from the
   **stored `hashes`** value per the shared canonicalization (`spec-go-signing-tool`
   §3.5) — i.e. use the stored `hashes` bytes as `M` (they were written to be the
   signed bytes). Verify `signature` (base64 → DER) against the leaf public key
   using the `alg` scheme over `SHA-384(M)`. On failure → **fail**
   (`BAD_SIGNATURE`).
4. **Time + revocation (Mode branch).**
   - **Mode 2** (`attestation` present): verify the attestation `token` against
     `attestation.certificate`, which must chain to a root in `roots/` and carry
     EKU `timeStamping`. Confirm the token's bound manifest hash equals
     `SHA-384(M)`. Extract **T from inside the verified token** (never a plaintext
     field). Require `leaf.notBefore ≤ T ≤ leaf.notAfter`. Apply **revoke-from-time**
     against T: if the leaf (or any chain cert) is revoked in the CRL with a
     `revokedFrom ≤ T` → **fail** (`REVOKED`).
   - **Mode 1** (no `attestation`): require `leaf.notBefore ≤ now ≤ leaf.notAfter`.
     If the leaf (or any chain cert) appears in the CRL **at all** → **fail**
     (`REVOKED`) — Mode-1 revocation is unconditional (design §8).
   - CRL source and fallback: §5.
5. **Identity.** Determine the appId per §7 (info.xml wins; §4.1 comparison rules);
   require `leaf.CN == appId` (exact byte compare after the §7 canonicalization).
   On mismatch → **fail** (`CN_MISMATCH`).
6. **Integrity diff.** Recompute per-file SHA-512 over the on-disk tree
   (shared canonicalization, Go tool spec §3.1–§3.4, **including the exclusion
   list §3.2** — OS/file-manager cruft such as `.DS_Store`/`Thumbs.db` is excluded
   identically to the signer, so it never triggers `EXTRA_FILE`), compare to the
   `hashes` map:
   - present-and-equal → ok
   - on disk but not in manifest → `EXTRA_FILE`
   - in manifest but not on disk → `FILE_MISSING`
   - both but differ → `INVALID_HASH`
   Any non-empty diff → **fail**.

A **pass** requires all six steps clean. Result (pass, or the failure reason +
diff) is cached as today.

---

## 5. CRL handling

- **Fetch:** from the constant `CRL_URL` (§2). **Do not** follow HTTP redirects;
  HTTPS only (design §9, §13).
- **Fallback chain (design §9):**
  1. Freshly fetched CRL with a **valid signature** (chains to a root in `roots/`).
  2. Else the CRL **bundled** in `resources/codesigning/crl/`.
  3. If neither yields a signature-valid CRL → **fail-closed**: refuse
     install/update (`CRL_UNAVAILABLE`).
- A **stale but signature-valid** CRL is accepted (no staleness rejection, no
  staleness warning — design §9).
- **When fetched:** at least at app install/update. (Periodic re-verification —
  §6 — may reuse the last valid CRL.)
- **Legacy CRL** (G1, transition only): bundled, frozen, never refreshed
  (accepted risk, design §12).

---

## 6. Enforcement

- **Mandatory signing, all apps.** No production per-app "ignore missing
  signature" waiver. **Dev-only exemption**: channel `git` or `''` skips
  enforcement (design §9; note the global-bypass caveat in Appendix B / S4).
- **Hard block only.** A failing app is refused at install/update/enable. There is
  **one** exception path: an admin may **consciously disable validation for a
  specific app**; this action is **logged** (who, when, which app, prior failure
  reason). No warn-and-continue for third-party G2 apps.
- **Transition exception (§8):** valid-but-expired **G1** apps are the sole
  warn-and-allow case, time-boxed to `LEGACY_SUNSET`.
- **Timing:**
  - **Install/update/enable:** full verification (the gate).
  - **Periodic full-instance re-verification:** retained (as legacy
    `runInstanceVerification`) — the safety net that catches at-rest tampering and
    newly-revoked certs on already-installed apps. Drives the admin warning
    surface for already-installed apps that later fail (e.g. a cert revoked after
    install).

---

## 7. AppId determination and comparison (design §4.1)

- The authoritative appId is the `id` in the app's `appinfo/info.xml`.
- If the on-disk directory name and `info.xml` `id` disagree, **`info.xml` wins**;
  if a single appId cannot be resolved, **stop and do not install** (fail with a
  warning), do not guess.
- **Comparison:** ASCII-only case-fold the `info.xml` id (`A`–`Z`→`a`–`z`, the 26
  ASCII bytes only — never locale/Unicode lowercasing), validate against
  `^[a-z][a-z0-9_-]{1,63}$` (reject if it still fails), then **exact-byte compare**
  to the leaf `CN`. The leaf `CN` is validated strictly against the same regex with
  **no** normalization (it is canonical by issuance).
- Core mode: the reserved core identity is matched instead of an appId (design
  §15); the `CN==appId` rule generalizes to `CN == "core"`-equivalent reserved
  identity for the core signature.

---

## 8. Transition / legacy (G1) handling (design §12)

Three cases, evaluated per app:

1. **Invalid signature / tampered / bad chain (to any trusted root)** →
   **hard block**, always, no leniency (fails steps 2/3/6).
2. **Valid G1 (legacy) chain, cert expired** → **warn + allow**, IF ALL:
   - `now < LEGACY_SUNSET`, and
   - chain validates to the bundled **G1** anchor, and
   - the leaf is **not** revoked in the bundled **legacy CRL**, and
   - `alg` is the legacy scheme (permitted for G1 only, §3).
   The expiry check is **skipped** for this case only. This is the single
   warn-not-block exception.
3. **Valid G2 chain** → full validation (§4).

**Sunset enforcement:** `now ≥ LEGACY_SUNSET` (hardcoded constant, §2) makes case
2 fold into case 1 — G1 chains, the legacy CRL, and the legacy algorithm are all
rejected, regardless of whether the instance was updated. A later release may
delete the now-inert G1 files (cosmetic).

---

## 9. Failure reason codes (for reporting/caching)

`BAD_ALGORITHM`, `BAD_CHAIN`, `BAD_SIGNATURE`, `REVOKED`, `CRL_UNAVAILABLE`,
`CN_MISMATCH`, `FILE_MISSING`, `EXTRA_FILE`, `INVALID_HASH`, `MISSING_SIGNATURE`
(no `signature.json` where one is required), plus the legacy-transition marker
`LEGACY_ACCEPTED_WARN` (case 2). Preserve the legacy structured-diff shape for
`FILE_MISSING`/`EXTRA_FILE`/`INVALID_HASH` for UI compatibility.

---

## 10. OpenSSL / interoperability compatibility (REQUIRED)

Developer keys, CSRs, and signed revocation requests are produced with the OpenSSL
CLI. The verifier (PHP) MUST:

- Parse standard OpenSSL PEM certificates and public keys without re-encoding.
- Verify ECDSA signatures encoded as ASN.1 DER (as produced by the Go signer /
  `openssl`), and RSA-PSS-SHA384 for the fallback.
- Reconstruct the canonical manifest bytes `M` byte-for-byte per the shared rules
  (Go tool spec §3) — the parity between the PHP verifier and the Go signer is the
  single highest correctness risk; both are tested against the same golden vectors
  (§ below) **and** cross-checked against `openssl` where applicable.

## 11. Conformance

The verifier MUST pass the shared golden vectors (`spec-go-signing-tool` §8):
recompute `M` byte-for-byte, validate the expected signature, and produce the
correct diff codes under file mutation/addition/removal. Add verifier-specific
vectors for: an expired-but-valid G1 chain before/after a simulated sunset; a
Mode-2 token with T inside the leaf validity vs. outside; a revoked leaf with
`revokedFrom` before/after T.
