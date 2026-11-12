# .github

Actions are named by release tag; the commit lives in
`.github/workflows/actions.lock`. After changing any `uses:` (workflows or
`.github/actions/`), run `gh-actions-lock` (dev shell) and commit the lockfile
with it; GitHub runs the locked commit and `check-generated` fails a stale
lockfile. Same-repo actions are written `$/.github/actions/...`, not `./`, so the
lockfile covers what they use. Never pass `--accept-moved`: a moved release tag
needs a human.

zizmor audits every workflow in CI and in the hooks. An exception goes in
`.github/zizmor.yml` with its reason.
