# Spec — Go Signing Tool (`ocsign`)

**Companion to:** `owncloud-code-signing-pki-design.md`
**Status:** Implementation spec, intended to be buildable ("vibe-codeable") from
this document alone.
**Audience:** whoever (human or agent) implements the standalone signing CLI, and
whoever implements the server-side verifier (they MUST share the canonicalization
rules in §3 and the golden test vectors in §8).

> **Examples** use placeholders (`example-app`, `example-org`, `example-user`).

---

## 1. Purpose and scope

A standalone, cross-platform Go CLI (`ocsign`) that produces a
`signature.json` (schema v2) for an ownCloud app or for core. It is **decoupled
from the server** — unlike the legacy `occ integrity:sign-app`, it needs no
bootstrapped ownCloud instance.

It does three things:

1. Walk an app tree and build the **canonical file-hash manifest** (§3).
2. Sign the canonical manifest bytes with the developer's private key and write
   `signature.json` with the embedded leaf + chain (§4, §5).
3. Optionally attach a Mode-2 attestation token obtained from the attestation
   workflow (`--attest`), by calling the workflow and embedding the returned
   token (§6).

**Out of scope:** enrollment (getting the cert), CRL handling, verification. The
tool only *produces* `signature.json`.

**The single hardest requirement:** the manifest the tool signs must be
**byte-identical** to what the server recomputes and verifies. §3 is therefore
normative and exact. Any deviation between this tool and the server verifier is a
correctness bug that manifests as "signature valid but hashes differ."

---

## 2. CLI contract

```
ocsign [flags]

Required:
  --path string     Path to the app root directory to sign (the directory whose
                    appinfo/info.xml declares the app id). For core, the core
                    server root.
  --key  string     Path to the signer's PEM private key (EC P-384, or RSA-4096
                    fallback). Never transmitted; used locally only.
  --cert string     Path to the issued leaf certificate (PEM).

Optional:
  --chain string    Path to a PEM file containing the intermediate cert(s) to
                    embed as certificates.chain[]. If omitted, the tool still
                    writes signature.json but chain[] is empty (the server can
                    fall back to its bundled intermediate; embedding is preferred).
  --core            Sign as core: write core/signature.json instead of
                    appinfo/signature.json, and apply the core file-set rules (§3.6).
  --attest          After signing, request a Mode-2 attestation token from the
                    attestation workflow and embed it (§6). Requires --attest-repo.
  --attest-repo string   owner/repo of the attestation workflow (default: the
                    canonical ownCloud codesigning repo; see developer docs).
  --out  string     Override output path (default: <path>/appinfo/signature.json,
                    or <path>/core/signature.json with --core).
  --dry-run         Compute and print the manifest + would-be signature.json to
                    stdout; write nothing.

Exit codes:
  0  success
  1  usage / input error (missing flag, unreadable key/cert/path)
  2  signing error (key/cert mismatch, unsupported key type)
  3  attestation error (--attest requested but workflow failed)
```

**Key/cert consistency check (exit 2 on failure):** the tool MUST verify that the
`--key` public key matches the `--cert` subject public key before signing, and
that the cert's `CN` matches the canonicalized appId derived from
`appinfo/info.xml` (§3.6) — refusing to sign a mismatch prevents producing a
`signature.json` that will fail server verification.

---

## 3. Canonicalization (NORMATIVE — shared with the verifier)

This section defines exactly what is hashed, how, and what bytes are signed. The
server verifier MUST implement the identical rules. The golden vectors in §8 are
the conformance test for both implementations.

### 3.1 File discovery

- Recursively enumerate **all regular files** under `--path`.
- Directories, symlinks, sockets, devices, and other non-regular entries are
  **not** hashed (a symlink is never followed; its target, if inside the tree, is
  hashed as a regular file in its own right).
- Hidden files (dotfiles) **are** included unless excluded by §3.2.

### 3.2 Exclusions (RESOLVED)

Exclude exactly these from the manifest. **The list is identical in the signer and
the verifier** and is pinned by the golden vectors (§8).

**App mode excludes:**

1. The signature file itself: `appinfo/signature.json`.
2. **OS / file-manager cruft** (by exact base filename, any directory):
   `.DS_Store` (macOS), `Thumbs.db` (Windows), `.directory` (KDE Dolphin),
   `.webapp` (Gentoo webapp-config).
3. **Cruft pattern** (by base filename regex): `^\.webapp-owncloud-.*`
   (Gentoo webapp-config).

Rationale: these are created by the operating system / file managers **at rest**,
never by the app. Excluding them prevents false `EXTRA_FILE` failures when, e.g.,
an admin browses the app directory on macOS and the OS drops a `.DS_Store`. This
is the only app-mode special handling; every genuine app file is hashed as-is.

**App mode does NOT exclude** `mimetypelist.js` (that is core-specific — §3.6).

> This list is fixed and version-pinned. Adding to it later is a canonicalization
> change and must be rolled out to signer + verifier together (and reflected in
> new golden vectors), or it breaks existing signatures.

### 3.3 Relative path normalization

For each included file, compute its manifest key:

1. Take the path relative to `--path`.
2. Convert OS path separators to **forward slash** `/` (so Windows `\` becomes
   `/`).
3. **No** leading slash, **no** `./` prefix, **no** trailing slash.
4. Do **not** alter case, Unicode-normalize, or otherwise transform the filename
   bytes. The key is the exact relative path as bytes (UTF-8 on disk).

Example keys: `appinfo/info.xml`, `lib/Controller/PageController.php`,
`js/app.js`.

### 3.4 Per-file hash

- Hash the **raw file bytes** (no newline normalization, no trimming) with
  **SHA-512**.
- Encode as **lowercase hex** (128 hex characters).

### 3.5 Manifest object and canonical bytes to sign

The manifest is a JSON object mapping path → hash. The **canonical bytes that get
signed** are produced as follows (this is the exact, reproducible serialization —
do not rely on a language's default map serialization):

1. Collect entries as `(key, hexhash)` pairs.
2. **Sort by key** using **byte-wise (lexicographic on UTF-8 bytes) ascending**
   order. (Not locale-aware, not case-insensitive — raw byte comparison.)
3. Serialize as JSON with these exact rules:
   - Object with keys in the sorted order from step 2.
   - Each key and value is a JSON string with **minimal escaping** per RFC 8259:
     escape only `"`, `\`, and control characters `U+0000`–`U+001F`
     (as `\uXXXX`, lowercase hex, except the short forms `\b \t \n \f \r`).
     Do **not** escape `/` or non-ASCII (emit UTF-8 bytes directly).
   - **No insignificant whitespace**: no spaces after `:` or `,`, no newlines, no
     indentation. Compact form.
   - Key/value separator is `:`; entry separator is `,`.
4. The resulting **UTF-8 byte sequence** is the message that is signed. Call it
   `M`.

Illustration (compact, sorted):

```json
{"appinfo/info.xml":"<sha512hex>","js/app.js":"<sha512hex>","lib/x.php":"<sha512hex>"}
```

> **Why so exact:** JSON encoders differ in key ordering, whitespace, escaping of
> `/` and non-ASCII, and control-char forms. Signing "a JSON object" without
> pinning these guarantees eventual signer/verifier divergence. Both sides build
> `M` by this algorithm and sign/verify over `M` byte-for-byte. Both sides should
> also **round-trip test against §8**.

### 3.6 Core mode special cases

Core mode (`--core`) signs the server root and carries a few special cases,
because core ships files that are legitimately modified at runtime and would
otherwise always mismatch. Core mode excludes / special-cases:

- **Exclude** `core/signature.json`.
- **Exclude** the same OS/file-manager cruft as app mode (§3.2 items 2–3).
- **Exclude** `core/js/mimetypelist.js` (regeneratable via
  `occ maintenance:mimetype:update-js`; excluded by the exact relative path).
- **`.htaccess` (server root) — marker-split (RESOLVED, still required for OC11
  Docker).** Hash **only the content above** the first occurrence of the marker
  line `#### DO NOT CHANGE ANYTHING ABOVE THIS LINE ####`; if the marker is
  absent, hash the whole file. This mirrors the legacy `Checker::generateHashes`
  and is still necessary: the OC11 Docker build (`server/v24.04/Dockerfile.multiarch`)
  does `chmod g+w .../.htaccess`, i.e. ownCloud rewrites dynamic content
  (rewrite/404/403 rules) into `.htaccess` below the marker at runtime.
- **`.user.ini` (server root) — hash as-is (RESOLVED, confirmed).** The base image
  (`base/v24.04/overlay/etc/owncloud.d/45-php.sh`) renders PHP tunables from env
  into `/etc/php/8.3/mods-available/owncloud.ini`, **not** into the app tree's
  `.user.ini`; and the image runs Apache + mod_php (which does not consume
  `.user.ini`). The shipped `.user.ini` is therefore never mutated in-container and
  is inert — hash it like any normal file. The legacy temp-copy dance is dropped
  (it was a no-op that normalized nothing).

> **DECISION CONFIRMED (both, via the `base` repo):** `.htaccess` marker-split is
> transcribed verbatim from legacy and reproduced identically in the verifier —
> **required**, because `base/.../50-apache.sh` runs `occ maintenance:update:htaccess`
> at every container start (writes dynamic content below the marker). `.user.ini`
> is hashed as-is — confirmed the base entrypoint does **not** render into it.
> App mode uses none of these (§3.2).
>
> Aside (not a signing concern): the in-tree `.user.ini` is cosmetically stale in
> Docker-only OC11 (ships `upload_max_filesize=513M` while the effective limit is
> the env-driven `owncloud.ini`, default 20G). Worth flagging to the core team,
> but it does not affect signing (the file is never touched, so it always matches
> its signed hash).

---

## 4. Signing

- **Algorithm** is fixed by the key type and recorded in `signature.json` `alg`:
  - EC P-384 key → `alg = "ecdsa-p384-sha384"`: sign `SHA-384(M)` with ECDSA.
  - RSA-4096 key (fallback) → `alg = "rsa-pss-sha384"`: RSA-PSS over `SHA-384(M)`,
    MGF1-SHA384, salt length = hash length. (Never SHA-1.)
- **ECDSA signature encoding:** ASN.1 DER (Go `ecdsa.SignASN1`), then base64
  (standard, with padding) for the `signature` field. The verifier decodes base64
  then parses DER (`ecdsa.VerifyASN1`).
- `M` is the canonical manifest bytes from §3.5 — **not** a re-encoding of the
  parsed `hashes` object. The tool signs the exact bytes it will also write as the
  `hashes` value (see §5 note).

---

## 5. Output: `signature.json` (schema v2)

```json
{
  "v": 2,
  "alg": "ecdsa-p384-sha384",
  "hashes": { "appinfo/info.xml": "<sha512hex>", "js/app.js": "<sha512hex>" },
  "signature": "<base64(DER ECDSA signature over M)>",
  "certificates": {
    "leaf": "<PEM leaf cert (CN=appId)>",
    "chain": ["<PEM intermediate cert>"]
  }
}
```

- `attestation` block is added only with `--attest` (§6); absent = Mode 1.
- **Critical write rule:** the `hashes` object written to `signature.json` MUST
  serialize (by §3.5 rules) to the exact bytes `M` that were signed. The simplest
  correct implementation: build `M` once, sign it, and write `M` verbatim as the
  value of `hashes` (i.e. treat `hashes` as pre-serialized canonical bytes rather
  than re-encoding a map). This guarantees the verifier — which reconstructs `M`
  from the on-disk files and also re-reads the stored `hashes` — sees identical
  bytes.
- PEM blocks are emitted with standard `-----BEGIN CERTIFICATE-----` framing, LF
  line endings.

---

## 6. Attestation integration (`--attest`)

After producing the Mode-1 `signature.json`:

1. Compute `H = SHA-384(M)` (the manifest hash the token will bind — same digest
   basis as the signature; the design's `hash(manifest)`).
2. Dispatch the attestation workflow (`--attest-repo`) via the GitHub API
   (`workflow_dispatch`), passing: the leaf cert (or fingerprint), `H`, and the
   developer signature (so the workflow can verify the manifest is genuinely
   signed before attesting — see the attestation workflow spec).
3. Poll for the workflow result; retrieve the returned **token**
   (`sign(H + T)` by the attestation key) and the **attestation certificate**.
4. Embed:

```json
"attestation": {
  "token": "<base64 token>",
  "certificate": "<PEM attestation cert (timeStamping EKU)>"
}
```

No plaintext `time` field (the design forbids it; `T` lives only inside `token`).

On any failure, exit 3 and leave the Mode-1 `signature.json` intact (attestation
is additive; a failed attestation must not corrupt a valid Mode-1 signature).

---

## 7. Implementation notes (Go)

- Stdlib only for crypto: `crypto/ecdsa`, `crypto/rsa`, `crypto/sha512`
  (also `sha512.Sum384` for SHA-384), `crypto/x509`, `encoding/pem`,
  `encoding/json` (used carefully — see below), `encoding/base64`, `encoding/hex`.
- **Do NOT** use `encoding/json` to produce `M`. Go's `json.Marshal` sorts map
  keys by Unicode code point (which coincides with byte order for UTF-8 in most
  cases but is not guaranteed identical semantics across implementations), escapes
  `<`, `>`, `&` by default (HTML escaping), and may differ from the verifier's
  encoder. Build `M` with an explicit serializer implementing §3.5 exactly. Use
  `json.Marshal` only for the outer `signature.json` envelope where byte-exactness
  is not security-relevant (only `hashes`/`M` must be exact).
- Single static binary; support `GOOS`/`GOARCH` cross-compilation for
  linux/darwin/windows on amd64/arm64.
- No network access except in `--attest` mode.

---

## 8. Golden test vectors (conformance — shared artifact)

Ship a `testdata/` fixture used by **both** the signer's tests and the server
verifier's tests. This is the mitigation for canonicalization drift (design
Appendix B).

Provide at least:

1. **`tree-basic/`** — a small app tree:
   ```
   tree-basic/
     appinfo/info.xml         (id = example-app)
     lib/Controller/Page.php
     js/app.js
     templates/index.php
     .hidden-config
   ```
   with:
   - `manifest.canonical.json` — the exact canonical bytes `M` (§3.5), committed
     as a byte-exact file (no trailing newline).
   - `hashes.expected.json` — the per-file SHA-512 hex values.
   - A fixed **test EC P-384 key** and a **test leaf cert** (`CN=example-app`,
     issued by a test intermediate) committed in `testdata/keys/` for
     deterministic signing.
   - `signature.expected.json` — the full expected `signature.json` (note: ECDSA
     is non-deterministic, so tests verify the *signature validates* and the
     `hashes`/`M` bytes match exactly, rather than byte-comparing `signature`).

2. **`tree-unicode/`** — filenames with non-ASCII UTF-8 bytes and a path
   containing characters requiring careful ordering, to pin §3.3/§3.5 byte
   ordering and non-escaping of non-ASCII.

3. **`tree-edge/`** — empty file (0 bytes), a file whose name sorts adjacent to
   another by byte order (e.g. `a` vs `a/b` vs `a.b` — verify `/` (0x2F) vs `.`
   (0x2E) ordering), and a deeply nested path.

4. **`tree-cruft/`** — a tree containing `.DS_Store`, `Thumbs.db`, `.directory`,
   `.webapp`, and a `.webapp-owncloud-x` file alongside real app files. The
   canonical manifest MUST exclude exactly the cruft (§3.2) and nothing else;
   verifier must NOT report `EXTRA_FILE` for these when present on disk.

**Conformance test (both signer and verifier):**
- Recompute `M` from the tree → must equal `manifest.canonical.json` byte-for-byte.
- Verify `signature.expected.json`'s signature against the test leaf over the
  recomputed `M` → must pass.
- Verifier additionally: mutate one file → hash diff must report `INVALID_HASH`;
  add a file → `EXTRA_FILE`; remove a file → `FILE_MISSING`.

---

## 9. OpenSSL compatibility (REQUIRED)

Developers generate keys and CSRs with the OpenSSL CLI (developer-doc spec §2),
and produce signed revocation requests with it. Therefore:

- The tool MUST accept **standard OpenSSL-produced** PEM private keys (both
  `-----BEGIN EC PRIVATE KEY-----` / SEC1 and `-----BEGIN PRIVATE KEY-----` /
  PKCS#8) and PEM certificates without requiring re-encoding.
- The `signature` and any signed artifacts MUST be verifiable by standard tooling
  where reasonable: ECDSA signatures are ASN.1 DER (as `openssl dgst`/`pkeyutl`
  produce and verify), base64 with standard alphabet + padding.
- Test the round-trip **against the `openssl` CLI**, not only against Go, in CI —
  a Go-only test would miss encoder incompatibilities. This applies equally to the
  verifier and to the signed-revocation-request flow (enrollment-bot spec §10).

## 10. Open items for this tool

- **App-mode exclusions (§3.2): RESOLVED** — signature file + OS/file-manager
  cruft list.
- **Core-mode `.htaccess`/`.user.ini` (§3.6): RESOLVED** — `.htaccess`
  marker-split verbatim (still required; Docker rewrites it at runtime);
  `.user.ini` hashed as-is. One flag: confirm the `owncloud/base` entrypoint does
  not render into `.user.ini` (else exclude it).
- **`--attest` workflow dispatch/poll mechanics** depend on the attestation
  workflow spec (repo, inputs, how the result token is returned to the caller —
  workflow artifact vs. a committed transparency-log entry the tool reads back).
  See also **item #2** in that spec: the `bind(H, T)` token byte-layout is not yet
  fixed and must be pinned before `--attest` can be implemented interoperably.
