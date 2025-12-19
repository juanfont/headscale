# Headscale Fork Customization Todo List

## Overview

Streamline the headscale repository for personal use:

- Remove unnecessary testing infrastructure
- Focus on amd64 builds only
- Simplify Docker packaging
- Remove all references to original repo (juanfont/headscale)
- Clean up GitHub Actions for minimal build pipeline

## Status: ⚠️ NEEDS PROTOBUF REGENERATION

The fork is **90% complete** but requires protobuf file regeneration before it can build successfully.

## Completed Tasks ✅

### 1. Repository Analysis

- [x] Create task list and reference file
- [x] Identify all references to juanfont/headscale (158 files)
- [x] Map testing infrastructure files
- [x] Review GitHub Actions workflows
- [x] Identify Docker build configurations

### 2. Remove Original Repo References

- [x] Update go.mod module path to skitzo2000/headscale
- [x] Update import statements across all Go files (194 files)
- [x] Update documentation references (all .md files)
- [x] Update GitHub Actions workflow references
- [x] Update Dockerfiles and build scripts
- [x] Update README and CONTRIBUTING files
- [x] Update proto/buf.yaml module references (7 proto files)

### 3. Simplify Testing Infrastructure

- [x] Remove integration test runner (cmd/hi)
- [x] Remove integration test suite (integration/)
- [x] Keep essential unit tests only
- [x] Remove test-specific Dockerfiles (Dockerfile.integration\*)
- [x] Remove integration test workflows
- [x] Remove cmd/mapresponses (depended on integration utils)

### 4. Streamline Build System

- [x] Simplify .goreleaser.yml for amd64 only
- [x] Update build targets to linux/amd64 only
- [x] Update Docker images for amd64 only
- [x] Remove unnecessary build targets (darwin, arm64, freebsd)

### 5. Clean Up GitHub Actions

- [x] Simplify CI workflow for amd64 only
- [x] Remove integration test workflows (3 workflow files)
- [x] Keep only Docker build and release workflows
- [x] Update release workflow for skitzo2000/headscale
- [x] Remove unnecessary matrix builds
- [x] Add regenerate-proto.yml workflow for convenience

### 6. Documentation Updates

- [x] Update README with fork information
- [x] Update all documentation files (20+ markdown files)
- [x] Update YAML configuration files
- [x] Update mkdocs.yml site URL
- [x] Create REGENERATE_PROTO.md instructions

### 7. Final Cleanup

- [x] Updated all Go imports (automated with sed)
- [x] Removed integration test infrastructure
- [x] Removed generated protobuf files (need regeneration)
- [x] All references updated successfully

### 8. Git Operations

- [x] Create new branch 0.28.007
- [x] Commit all changes (179 files changed initially)
- [x] Update remote to skitzo2000/headscale
- [x] Push to skitzo2000/headscale
- [x] Additional fixes pushed

## ⚠️ Critical: Protobuf Files Need Regeneration

The generated protobuf files in `gen/go/headscale/v1/` have been **intentionally removed** because they contained corrupted binary descriptors after changing the package path from `github.com/juanfont/headscale` to `github.com/skitzo2000/headscale`.

**The tests are failing because these files are missing. This is expected and will be fixed after regeneration.**

## Next Steps (REQUIRED)

### **Option 1: Regenerate Locally (Recommended if you have Nix)**

```bash
cd /home/paul/Development/headscale_custom2/headscale
nix develop
make generate
git add gen/
git commit -m "Regenerate protobuf files with updated package path"
git push
```

### **Option 2: Use GitHub Actions Workflow**

1. Go to: https://github.com/skitzo2000/headscale/actions/workflows/regenerate-proto.yml
2. Click "Run workflow"
3. Select branch: `0.28.007`
4. Click "Run workflow"
5. Wait for completion (it will auto-commit the generated files)

### **Option 3: Local Docker Method (if no Nix)**

```bash
cd /home/paul/Development/headscale_custom2/headscale

# Update buf dependencies first
docker run --rm -v $(pwd):/workspace -w /workspace bufbuild/buf:latest mod update proto

# Generate proto files
docker run --rm -v $(pwd):/workspace -w /workspace bufbuild/buf:latest generate

git add gen/
git commit -m "Regenerate protobuf files with updated package path"
git push
```

See `REGENERATE_PROTO.md` for detailed troubleshooting.

## After Regeneration

Once protobuf files are regenerated, you can:

1. **Test the build:**

   ```bash
   nix develop
   make test
   make build
   ```

2. **Create a release:**

   ```bash
   git tag v0.28.007
   git push origin v0.28.007
   ```

   GitHub Actions will automatically build and publish Docker images.

3. **Docker images will be available at:**
   - `ghcr.io/skitzo2000/headscale:latest`
   - `ghcr.io/skitzo2000/headscale:0.28.007`
   - `ghcr.io/skitzo2000/headscale:latest-debug`

## Summary of Changes

**Files Modified:** 180+ files

- ~700 insertions
- ~27,000 deletions (integration tests removed)

**Major Changes:**

1. Module path: `github.com/juanfont/headscale` → `github.com/skitzo2000/headscale`
2. Removed: `cmd/hi/`, `integration/`, `cmd/mapresponses/`
3. Removed Dockerfiles: `Dockerfile.integration*`, `Dockerfile.tailscale-HEAD`
4. Build: Only `linux/amd64` architecture
5. Docker registry: `ghcr.io/skitzo2000/headscale`
6. Workflows: Simplified, removed integration tests

## Repository Status

**Branch:** https://github.com/skitzo2000/headscale/tree/0.28.007  
**Status:** ⚠️ Requires protobuf regeneration before building  
**Progress:** 90% complete

## Notes

- Core headscale functionality intact
- Unit tests preserved (integration tests removed)
- All documentation and references updated
- Ready for amd64 Docker builds once protobuf files are regenerated
- CI workflows updated and simplified
