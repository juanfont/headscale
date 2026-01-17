# Advanced Git Commands

This guide covers advanced Git commands that are useful for Headscale contributors. Understanding these commands will help you manage your development workflow more effectively.

## git stash

`git stash` temporarily shelves changes you've made to your working directory so you can work on something else, then come back and re-apply the changes later.

### Basic Usage

```bash
# Stash your current changes
git stash

# Stash with a descriptive message
git stash save "Work in progress on route optimization"

# Stash including untracked files
git stash -u
```

### Viewing Stashes

```bash
# List all stashes
git stash list

# Show the contents of a specific stash
git stash show stash@{0}

# Show detailed diff of a stash
git stash show -p stash@{0}
```

### Applying Stashes

```bash
# Apply the most recent stash and keep it in the stash list
git stash apply

# Apply a specific stash
git stash apply stash@{2}

# Apply the most recent stash and remove it from the stash list
git stash pop

# Apply a specific stash and remove it
git stash pop stash@{2}
```

### Removing Stashes

```bash
# Drop a specific stash
git stash drop stash@{1}

# Clear all stashes
git stash clear
```

### Example Workflow

```bash
# You're working on a feature when a critical bug needs immediate attention
git stash save "WIP: Adding new ACL validation"

# Switch to main branch to fix the bug
git checkout main
git pull origin main
git checkout -b fix/critical-bug

# Fix the bug and commit
# ... make changes ...
git commit -m "fix: critical security issue in policy evaluation"

# Push and create PR
git push origin fix/critical-bug

# Go back to your feature work
git checkout feature/acl-validation
git stash pop

# Continue working on your feature
```

## git cherry-pick

`git cherry-pick` applies the changes from specific commits to your current branch. This is useful when you want to apply a specific fix or feature from one branch to another without merging the entire branch.

### Basic Usage

```bash
# Cherry-pick a single commit
git cherry-pick <commit-hash>

# Cherry-pick multiple commits
git cherry-pick <commit-hash1> <commit-hash2>

# Cherry-pick a range of commits
git cherry-pick <start-commit>..<end-commit>
```

### Advanced Options

```bash
# Cherry-pick without committing (stage changes only)
git cherry-pick -n <commit-hash>

# Cherry-pick and edit the commit message
git cherry-pick -e <commit-hash>

# Cherry-pick and sign off the commit
git cherry-pick -s <commit-hash>

# Continue after resolving conflicts
git cherry-pick --continue

# Abort a cherry-pick in progress
git cherry-pick --abort
```

### Example Workflow

```bash
# You have a bug fix in a feature branch that's also needed in main
git checkout main
git pull origin main

# Find the commit hash of the fix
git log feature/new-derp-support --oneline

# Cherry-pick the specific bug fix commit
git cherry-pick a1b2c3d

# If there are conflicts, resolve them and continue
# ... resolve conflicts ...
git add .
git cherry-pick --continue

# Push the fix
git push origin main
```

### Use Case: Backporting Fixes

```bash
# A critical security fix was made in main, but needs to be in v0.27 release
git checkout release/v0.27
git pull origin release/v0.27

# Cherry-pick the security fix
git cherry-pick 8f3e9a1

# Push to the release branch
git push origin release/v0.27
```

## git revert

`git revert` creates a new commit that undoes the changes from a previous commit. Unlike `git reset`, it doesn't rewrite history, making it safe for public branches.

### Basic Usage

```bash
# Revert the most recent commit
git revert HEAD

# Revert a specific commit
git revert <commit-hash>

# Revert multiple commits
git revert <commit-hash1> <commit-hash2>

# Revert a range of commits
git revert <start-commit>..<end-commit>
```

### Advanced Options

```bash
# Revert without committing (stage changes only)
git revert -n <commit-hash>

# Revert and edit the commit message
git revert -e <commit-hash>

# Revert a merge commit (specify parent number)
git revert -m 1 <merge-commit-hash>

# Continue after resolving conflicts
git revert --continue

# Abort a revert in progress
git revert --abort
```

### Example Workflow

```bash
# A commit introduced a bug and needs to be reverted
git log --oneline
# ... find the problematic commit: c4d5e6f ...

# Revert the commit
git revert c4d5e6f

# This creates a new commit that undoes the changes
# Edit the commit message if needed, then save

# Push the revert
git push origin main
```

### Use Case: Reverting Multiple Commits

```bash
# Multiple commits need to be reverted but history should be preserved
git revert --no-commit abc123
git revert --no-commit def456
git revert --no-commit ghi789

# Review the combined changes
git diff --staged

# Create a single revert commit
git commit -m "revert: undo problematic policy changes from commits abc123, def456, ghi789"

# Push the changes
git push origin main
```

## git reset

`git reset` moves the current branch pointer to a different commit. It can be used to undo changes, unstage files, or rewrite local history. **Warning:** This rewrites history and should not be used on public/shared branches.

### Three Modes

1. **Soft reset** (`--soft`): Moves HEAD, keeps staged changes and working directory changes
2. **Mixed reset** (`--mixed`, default): Moves HEAD, unstages changes, keeps working directory changes
3. **Hard reset** (`--hard`): Moves HEAD, discards staged changes and working directory changes

### Basic Usage

```bash
# Undo the last commit, keep changes staged
git reset --soft HEAD~1

# Undo the last commit, unstage changes (default)
git reset HEAD~1

# Undo the last commit, discard all changes
git reset --hard HEAD~1

# Reset to a specific commit
git reset --hard <commit-hash>

# Unstage a specific file
git reset HEAD <file>
```

### Example Workflows

#### Undo Last Commit (Keep Changes)

```bash
# You committed too early and want to add more changes
git reset --soft HEAD~1

# Your changes are still staged, add more changes
# ... make more changes ...
git add .

# Commit everything together
git commit -m "feat: complete implementation of node expiration logic"
```

#### Clean Up Local Commits Before Pushing

```bash
# You made several messy local commits
git log --oneline
# 5a6b7c8 WIP
# 4d5e6f7 fix typo
# 3c4d5e6 fix another typo
# 2b3c4d5 actually working now

# Reset to before your commits (soft to keep changes)
git reset --soft 2b3c4d5^

# All changes are now staged, make a clean commit
git commit -m "feat: implement NodeStore optimization"
```

#### Discard Local Changes

```bash
# You made experimental changes that didn't work out
git reset --hard HEAD

# Or discard all changes and sync with remote
git fetch origin
git reset --hard origin/main
```

#### Unstage Files

```bash
# You accidentally staged files you don't want to commit
git add .
git reset HEAD docs/debug.log

# Only docs/debug.log is unstaged, other files remain staged
```

### Important Warnings

!!! danger "Never use reset on public branches"
    Using `git reset` on branches that others have based work on will cause problems. The commits you remove will still exist in their repositories, leading to conflicts when they try to push.

!!! warning "Hard reset is destructive"
    `git reset --hard` permanently discards changes. Make sure you really want to throw away your work before using it. Consider using `git stash` instead if you might need the changes later.

### Safe Alternative: Revert Instead of Reset

```bash
# Instead of:
git reset --hard HEAD~1  # Dangerous on public branches

# Use:
git revert HEAD  # Safe for public branches, creates new commit
```

## Comparing the Commands

| Command | Changes History | Safe for Public Branches | Use Case |
|---------|----------------|-------------------------|----------|
| `git stash` | No | Yes | Temporarily save work in progress |
| `git cherry-pick` | No (adds commits) | Yes | Apply specific commits to another branch |
| `git revert` | No (adds commits) | Yes | Undo commits while preserving history |
| `git reset` | Yes | **No** | Rewrite local history or unstage files |

## Best Practices for Headscale Development

### Before Starting Work

```bash
# Always start from an up-to-date main branch
git checkout main
git pull origin main
git checkout -b feature/your-feature
```

### During Development

```bash
# Use stash to switch contexts quickly
git stash save "WIP: current feature"
git checkout other-branch
# ... do other work ...
git checkout feature/your-feature
git stash pop
```

### Fixing Mistakes

```bash
# Wrong commit message on unpushed commit
git commit --amend -m "feat: correct commit message"

# Need to modify the last commit
git add forgotten-file.go
git commit --amend --no-edit

# Accidentally committed to wrong branch (before pushing)
git reset --soft HEAD~1
git stash
git checkout correct-branch
git stash pop
git commit -m "feat: your change"
```

### Cleaning Up Before PR

```bash
# Squash multiple commits into one
git reset --soft HEAD~3
git commit -m "feat: comprehensive feature implementation"

# Or use interactive rebase (covered in advanced topics)
git rebase -i HEAD~3
```

## Getting Help

If you're unsure about a Git command:

```bash
# Show detailed help for any command
git help stash
git help cherry-pick
git help revert
git help reset

# Quick reference
git stash --help
git cherry-pick --help
```

For Headscale-specific development questions, see:

- [Contributing Guide](../about/contributing.md)
- [Development documentation](https://github.com/juanfont/headscale/blob/main/AGENTS.md)
- [Discord community](https://discord.gg/c84AZQhmpx)
