#!/usr/bin/env bash
# Wrapped by nix/release-issue/default.nix. Do not invoke directly.
set -euo pipefail

TEMPLATE="${HEADSCALE_RELEASE_CHECKLIST:?HEADSCALE_RELEASE_CHECKLIST must be set by the Nix wrapper}"

usage() {
  cat >&2 <<'EOF'
Usage: headscale-release-issue --version X.Y.Z [--milestone N] [--dry-run]

Opens a GitHub release-tracking issue from the embedded checklist template.
Attaches the milestone (when given), adds the "no-stale-bot" label, and locks
the issue for comments so the checklist is not derailed by drive-by replies.

Flags:
  --version X.Y.Z   Stable release version (required). Pre-release suffixes
                    are rejected — release-tracking issues are stable-only;
                    individual betas/rcs are tracked inside the issue body.
  --milestone N     Milestone number to associate with. Optional; when
                    omitted no --milestone is passed to gh and the
                    /milestone/N URL in the body keeps its literal "N".
  --dry-run         Print the gh commands that would run, do not open or lock.
  -h, --help        Show this help.
EOF
}

VERSION=""
MILESTONE=""
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      [[ $# -ge 2 ]] || { echo "--version requires a value" >&2; exit 2; }
      VERSION="$2"; shift 2 ;;
    --milestone)
      [[ $# -ge 2 ]] || { echo "--milestone requires a value" >&2; exit 2; }
      MILESTONE="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$VERSION" ]]; then
  echo "--version is required" >&2
  usage
  exit 2
fi

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "--version must be a stable X.Y.Z (no pre-release suffix), got: $VERSION" >&2
  exit 2
fi

if [[ -n "$MILESTONE" ]] && ! [[ "$MILESTONE" =~ ^[1-9][0-9]*$ ]]; then
  echo "--milestone must be a positive integer, got: $MILESTONE" >&2
  exit 2
fi

[[ -r "$TEMPLATE" ]] || { echo "template not readable: $TEMPLATE" >&2; exit 1; }

BODY=$(sed "s/vX\.Y\.Z/v${VERSION}/g" "$TEMPLATE")

MILESTONE_TITLE=""
if [[ -n "$MILESTONE" ]]; then
  BODY=$(printf '%s\n' "$BODY" | sed "s|/milestone/N|/milestone/${MILESTONE}|g")
  if ! MILESTONE_TITLE=$(gh api "repos/{owner}/{repo}/milestones/${MILESTONE}" --jq .title); then
    echo "could not resolve milestone #${MILESTONE} title via gh api" >&2
    exit 1
  fi
fi

TITLE="Release v${VERSION}"

CREATE_ARGS=(--title "$TITLE" --body "$BODY" --label no-stale-bot)
if [[ -n "$MILESTONE_TITLE" ]]; then
  CREATE_ARGS+=(--milestone "$MILESTONE_TITLE")
fi

if [[ "$DRY_RUN" == "1" ]]; then
  printf 'Would run: gh issue create --title %q --label no-stale-bot' "$TITLE"
  [[ -n "$MILESTONE_TITLE" ]] && printf -- ' --milestone %q' "$MILESTONE_TITLE"
  printf ' --body <body>\n'
  printf 'Then:      gh issue lock <url-from-create>\n\n'
  printf -- '--- rendered body ---\n%s\n--- end body ---\n' "$BODY"
  exit 0
fi

URL=$(gh issue create "${CREATE_ARGS[@]}")
echo "$URL"
gh issue lock "$URL" </dev/null
