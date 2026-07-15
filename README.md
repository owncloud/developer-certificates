# developer-certificates

The **codesigning repo** for the ownCloud Code-Signing PKI.

This repository is the single home the design calls for (design §6, §13): CSR
issue intake, the public issuance **ledger**, the **CRL**, and all issuance /
attestation / revocation **workflows**. It complements the standalone
[`ocsign`](https://github.com/owncloud/ocsign) signing CLI, which lives in
its own repository.

> **Status: dev / staging — private.** The production codesigning repo must be
> **public**, because its ledger is a public transparency / audit log (design
> §6, §13). This repository is private while the implementation is built and
> reviewed; it will be made public (or migrated to a fresh public production
> repo) before go-live.

## What's here today

- [`docs/specs/`](docs/specs/) — the full design record: the PKI design document
  and its five companion implementation specs (archived verbatim).
- `docs/developer-guide.md` — the external developer documentation *(landing via
  PR)*.
- `.github/ISSUE_TEMPLATE/` — the certificate-request and revocation-request
  issue forms *(landing via PR)*.
- `test/` — a conformance harness that pins the security-critical invariants of
  the issue forms and developer guide (appId regex, challenge path, no
  unresolved placeholders).

## Landing later (separate PRs)

Enrollment / revocation bot, attestation & CRL generation workflows, the core
PHP verifier, ledger seeding, and CA-ceremony artifacts. See
[`docs/specs/`](docs/specs/) for the design of each.

## Contributing

`main` is protected by convention: **all changes land through pull requests**;
nothing is pushed to `main` directly. CI (`.github/workflows/validate.yml`) must
pass. Commits are DCO signed-off (`git commit -s`) and PGP/SSH signed.
