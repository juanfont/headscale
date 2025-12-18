# Headscale Fork Customization Todo List

## Overview
Streamline the headscale repository for personal use:
- Remove unnecessary testing infrastructure
- Focus on amd64 builds only
- Simplify Docker packaging
- Remove all references to original repo (skitzo2000/headscale)
- Clean up GitHub Actions for minimal build pipeline

## Tasks

### 1. Repository Analysis
- [x] Create task list and reference file
- [ ] Identify all references to skitzo2000/headscale
- [ ] Map testing infrastructure files
- [ ] Review GitHub Actions workflows
- [ ] Identify Docker build configurations

### 2. Remove Original Repo References
- [ ] Update go.mod module path to skitzo2000/headscale
- [ ] Update import statements across all Go files
- [ ] Update documentation references
- [ ] Update GitHub Actions workflow references
- [ ] Update Dockerfiles and build scripts
- [ ] Update README and CONTRIBUTING files
- [ ] Update proto/buf.yaml module references

### 3. Simplify Testing Infrastructure
- [ ] Remove integration test runner (cmd/hi)
- [ ] Remove integration test suite (integration/)
- [ ] Keep essential unit tests only
- [ ] Remove test-specific Dockerfiles (Dockerfile.integration*)
- [ ] Clean up Makefile test targets
- [ ] Remove test documentation

### 4. Streamline Build System
- [ ] Simplify .goreleaser.yml for amd64 only
- [ ] Update Makefile to remove multi-arch builds
- [ ] Keep only main Dockerfile for amd64
- [ ] Remove unnecessary build targets

### 5. Clean Up GitHub Actions
- [ ] Simplify CI workflow for amd64 only
- [ ] Remove integration test workflows
- [ ] Keep only Docker build and release workflows
- [ ] Update release workflow for skitzo2000/headscale
- [ ] Remove unnecessary matrix builds

### 6. Documentation Updates
- [ ] Update README with fork information
- [ ] Simplify AGENTS.md (remove testing sections)
- [ ] Update CONTRIBUTING.md for simplified workflow
- [ ] Remove or update CLAUDE.md

### 7. Final Cleanup
- [ ] Remove unused dependencies from go.mod
- [ ] Clean up Nix configuration if not needed
- [ ] Remove development tool configurations not needed
- [ ] Verify all builds work

### 8. Git Operations
- [ ] Create new branch 0.28.007
- [ ] Commit all changes
- [ ] Push to skitzo2000/headscale

## Notes
- Keep core headscale functionality intact
- Maintain amd64 Docker builds
- Remove integration testing complexity
- Simplify development workflow

