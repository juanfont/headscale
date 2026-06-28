# Unit tests for commit-lint.nu.
#
# Drives the pure rule with fixture records (no git, no I/O). Run with:
#
#     nu .github/scripts/commit-lint.test.nu
#
# Exits non-zero on the first failing case.

use std/assert
use commit-lint.nu *

def cases [] {
    [
        # [label, author, subject, body, expect_ok]

        # Accepted refs.
        ["fixes #N",         "user <u@e>",         "feat: x",            "feat: x\n\nFixes #1",                              true],
        ["updates #N",       "user <u@e>",         "feat: x",            "feat: x\n\nUpdates #1",                            true],
        ["closes #N",        "user <u@e>",         "feat: x",            "feat: x\n\nCloses #1",                             true],
        ["resolves #N",      "user <u@e>",         "feat: x",            "feat: x\n\nResolves #1",                           true],
        ["for #N",           "user <u@e>",         "feat: x",            "feat: x\n\nFor #1",                                true],
        ["lowercase fixes",  "user <u@e>",         "feat: x",            "feat: x\n\nfixes #1",                              true],
        ["closed past",      "user <u@e>",         "feat: x",            "feat: x\n\nclosed #1",                             true],
        ["fixed past",       "user <u@e>",         "feat: x",            "feat: x\n\nfixed #1",                              true],
        ["resolved past",    "user <u@e>",         "feat: x",            "feat: x\n\nresolved #1",                           true],
        ["cross-repo",       "user <u@e>",         "feat: x",            "feat: x\n\nUpdates juanfont/headscale#1",          true],
        ["url form",         "user <u@e>",         "feat: x",            "feat: x\n\nFixes https://github.com/o/r/issues/1", true],
        ["leading whitespace","user <u@e>",        "feat: x",            "feat: x\n\n  Fixes #1",                            true],

        # Skip tokens.
        ["bot author",       "dependabot[bot] <>", "bump deps",          "bump deps",                                        true],
        ["renovate bot",     "renovate[bot] <>",   "deps",               "deps",                                             true],
        ["bot author email", "ci <bot@example>",   "feat: x",            "feat: x",                                          false],
        ["revert subject",   "user <u@e>",         "Revert \"feat: x\"", "Revert \"feat: x\"",                               true],
        ["#cleanup token",   "user <u@e>",         "fmt",                "fmt\n\n#cleanup",                                  true],
        ["#cleanup w space", "user <u@e>",         "fmt",                "fmt\n\n  #cleanup  ",                              true],
        ["skip-issuebot",    "user <u@e>",         "wip",                "wip\n\nskip-issuebot",                             true],

        # Rejected.
        ["no ref",           "user <u@e>",         "feat: x",            "feat: x",                                          false],
        ["verb without #",   "user <u@e>",         "feat: x",            "feat: x\n\nFixes the parser",                      false],
        ["# without verb",   "user <u@e>",         "feat: x",            "feat: x\n\nrelated to bug #1",                     false],
        ["fake bot in body", "user <u@e>",         "feat: x",            "feat: x\n\nlooks like a [bot]",                    false],
        ["fake revert body", "user <u@e>",         "feat: x",            "feat: x\n\nRevert this later",                     false],
        ["#cleanup not alone","user <u@e>",        "feat: x",            "feat: x\n\nstart #cleanup end",                    false],
    ]
}

def main [] {
    let rows = (cases)
    mut passed = 0
    for row in $rows {
        let label = ($row | get 0)
        let author = ($row | get 1)
        let subject = ($row | get 2)
        let body = ($row | get 3)
        let expected = ($row | get 4)
        let result = (check-commit-message $author $subject $body)
        assert ($result.ok == $expected) $"case '($label)': expected ok=($expected), got ($result)"
        $passed = $passed + 1
    }
    print $"all ($passed) cases passed"
}
