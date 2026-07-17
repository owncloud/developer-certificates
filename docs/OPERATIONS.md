# Operations — bot write path

Bot workflows write to `main` through **auto-merged, App-signed PRs** (design:
bot-writes-via-PR). Required repo configuration:

## GitHub App
Create/-install a GitHub App on this repo with these **repository permissions**:
- `contents: write` — create branches and commit ledger/CRL files.
- `pull_requests: write` — open and merge the bot PRs.
- `issues: write` — the issuer/revoker run on the App token and comment on,
  label, and close request issues (`PostComment`/`SetLabels`/`CloseIssue`).
  Without this, enrollment and revocation fail.
- `metadata: read` — mandatory baseline for any App.

Store `BOT_APP_ID` and `BOT_APP_PRIVATE_KEY` as repo secrets. PRs created with
the App token trigger `validate.yml` (the default `GITHUB_TOKEN` would not) and
API commits are signed (satisfies `required_signatures`).

**Set `ISSUER_BOT_LOGIN` to the App's bot login** (`<app-slug>[bot]`), not
`github-actions[bot]`. The issuer now posts challenge comments under the App
identity, and it reads back only comments authored by `ISSUER_BOT_LOGIN`
(`OwnComments`). If this variable does not match the App, the issuer never sees
its own challenge nonce and re-posts a fresh challenge every poll — enrollment
can never complete.

## Branch ruleset on `main`
- Require a pull request; **required approvals: 0**.
- Require the **`validate`** status check to pass.
- Keep `required_signatures`, `required_linear_history`.
- Enable repo setting **"Allow auto-merge"**.

crlgen/issuer/revoker merge via the REST merge endpoint only after every
required check-run (`validate`) reports `conclusion: success`, preserving
"merge only on green checks".

**Squash signature.** The PR is **squash-merged**, so the App-signed branch
commit is discarded and `main` receives a new squash commit signed by GitHub's
**web-flow key**, not the App key. `required_signatures` accepts this (it is a
verified GitHub signature), so the gate holds — but if a future ruleset ever
restricts signatures to specific signers, the web-flow key (not the App) must be
on the allowlist. Switch to a merge-commit strategy in `propose.go` if the
App-signed commit must be the one on `main`.

## Re-enable workflows
`issuer` and `revocation` are `disabled_manually` until this lands:
`gh workflow enable issuer.yml && gh workflow enable revocation.yml`.
