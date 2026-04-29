# Commit message linter for headscale.
#
# Mirrors the rule in tailscale/issuebot (cmd/issuebot/issuebot.go:107-145):
# every non-trivial commit in a pull request must reference an issue.
#
# A commit passes if any of the following hold:
#
#   - The author name or email contains "[bot]" (dependabot, renovate, etc.).
#   - The subject starts with "Revert " (revert inherits context).
#   - A line in the body equals "#cleanup" (trivial cleanup escape hatch).
#   - The token "skip-issuebot" appears anywhere in the body.
#   - At least one line in subject or body matches:
#       (?i)^\s*(close[ds]?|fix(es|ed)?|resolve[ds]?|updates|for)\b.*(#|github.com)
#
# Cross-repo refs (org/repo#N) and full GitHub issue URLs are accepted because
# the rule only requires the literal "#" or substring "github.com" on the
# matching line.

const ISSUE_REF_PATTERN = '(?im)^\s*(close[ds]?|fix(es|ed)?|resolve[ds]?|updates|for)\b.*(#|github\.com)'

# Pure rule check. Returns {ok: bool, reason: string}.
export def check-commit-message [
    author: string,
    subject: string,
    body: string,
] {
    if ($author | str contains '[bot]') {
        return {ok: true, reason: "skip:bot-author"}
    }

    if ($subject | str starts-with 'Revert ') {
        return {ok: true, reason: "skip:revert"}
    }

    let lines = ($body | lines)

    if ($lines | any {|l| ($l | str trim) == '#cleanup' }) {
        return {ok: true, reason: "skip:cleanup"}
    }

    if ($lines | any {|l| $l | str contains 'skip-issuebot' }) {
        return {ok: true, reason: "skip:skip-issuebot"}
    }

    if ($body =~ $ISSUE_REF_PATTERN) {
        return {ok: true, reason: "ref:matched"}
    }

    {ok: false, reason: "no issue reference"}
}

# Walk `git rev-list $base..$head` and lint each commit. Emits GitHub
# workflow annotations on failure and exits 1 if any commit fails.
export def lint-range [base: string, head: string] {
    let raw = (git rev-list $"($base)..($head)" | str trim)
    if ($raw | is-empty) {
        print "No commits to lint."
        return
    }
    let shas = ($raw | lines)

    mut failed = 0
    for sha in $shas {
        let author = (git log -1 --format='%an <%ae>' $sha | str trim)
        let subject = (git log -1 --format='%s' $sha | str trim)
        let body = (git log -1 --format='%B' $sha)
        let result = (check-commit-message $author $subject $body)
        let short = ($sha | str substring 0..7)
        if $result.ok {
            print $"ok    ($short)  ($result.reason)  ($subject)"
        } else {
            print $"::error::Commit ($sha) does not reference an issue. Add 'Fixes #N' or 'Updates #N', or use a skip token."
            print $"  subject: ($subject)"
            print $"  author:  ($author)"
            $failed = $failed + 1
        }
    }

    if $failed > 0 {
        print $"::error::($failed) commits missing issue reference."
        exit 1
    }
}
