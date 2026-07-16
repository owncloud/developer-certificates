# Operations — bot write path

Bot workflows write to `main` through **auto-merged, App-signed PRs** (design:
bot-writes-via-PR). Required repo configuration:

## GitHub App
Create/-install a GitHub App with `contents: write` + `pull_requests: write` on
this repo. Store `BOT_APP_ID` and `BOT_APP_PRIVATE_KEY` as repo secrets. PRs
created with the App token trigger `validate.yml` (the default `GITHUB_TOKEN`
would not) and API commits are signed (satisfies `required_signatures`).

## Branch ruleset on `main`
- Require a pull request; **required approvals: 0**.
- Require the **`validate`** status check to pass.
- Keep `required_signatures`, `required_linear_history`.
- Enable repo setting **"Allow auto-merge"**.

crlgen/issuer/revoker merge via the REST merge endpoint only after the combined
commit status is `success`, preserving "merge only on green checks".

## Re-enable workflows
`issuer` and `revocation` are `disabled_manually` until this lands:
`gh workflow enable issuer.yml && gh workflow enable revocation.yml`.
