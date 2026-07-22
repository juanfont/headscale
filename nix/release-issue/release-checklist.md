<!--
Create this issue from inside `nix develop`:
  headscale-release-issue --version X.Y.Z [--milestone N]
Pass --dry-run to preview the rendered body without opening an issue.
The script attaches the milestone (when given), adds the "no-stale-bot"
label, and locks the issue for comments.
-->

# Release vX.Y.Z

This release is based on the work in [Milestone vX.Y.Z](https://github.com/juanfont/headscale/milestone/N).

## Prep (once, before first beta)

- [ ] Update all Go dependencies
- [ ] Update all Nix dependencies
- [ ] Bump minimum Tailscale version
- [ ] Bump headscale version in `mkdocs.yml`
- [ ] Review & tidy changelog

## Per build (copy this block for each beta / rc / stable)

### vX.Y.Z-beta.N

- [ ] Tag & push
- [ ] Verify CI / release artifacts
- [ ] Announce on Discord
- [ ] Comment on issues fixed in this build

<!-- duplicate the block above for each subsequent beta, rc, and the final stable -->

## Done

- [ ] Stable released
- [ ] Changelog finalized
- [ ] Close this issue
