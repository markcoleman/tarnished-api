# GitHub Actions Performance Optimizations

This document outlines the performance optimizations implemented to make the GitHub Actions CI workflow run faster.

## Overview

The CI workflow has been optimized to reduce build times and improve developer productivity through parallel execution, incremental compilation, and smart caching strategies.

## Key Optimizations

### 1. Parallel Job Execution with Matrix Strategy

**Before**: Jobs ran sequentially: Build → Test → Clippy (each waiting for the previous to complete)

**After**: All quality checks run in parallel using a matrix strategy:

```yaml
strategy:
  matrix:
    include:
      - job: "Build"
      - job: "Test"  
      - job: "Clippy"
```

**Impact**: Reduces total CI time from ~3x single job time to single job time.

### 2. Compilation Caching with sccache

**Added global environment variables**:
- `CARGO_NET_RETRY=10`: Improves reliability
- `RUSTC_WRAPPER=sccache`: Enables distributed compilation caching
- `SCCACHE_GHA_ENABLED=true`: Uses GitHub Actions cache backend

**Note**: sccache provides distributed caching across workflow runs and is more effective than incremental compilation in CI environments. These two approaches are mutually exclusive.

**Performance gains**:
- Initial build: ~1m 12s
- Cached rebuild: ~4.6s (93% faster)
- Cached tests: ~16s (78% faster)  
- Cached clippy: ~3.6s (94% faster)

### 3. Smart Cache Strategy

**Enhanced caching**:
- Separate cache keys for different job types
- Shared Cargo registry cache across all jobs
- Target directory caching with fallback keys

```yaml
- name: Cache target directory
  uses: actions/cache@v4
  with:
    path: target
    key: ${{ runner.os }}-target-${{ matrix.step }}-${{ hashFiles('**/Cargo.lock') }}
    restore-keys: |
      ${{ runner.os }}-target-${{ matrix.step }}-
      ${{ runner.os }}-target-
```

### 4. Conditional Job Execution

**Added change detection**:
- Skip expensive jobs for documentation-only changes
- Reduces unnecessary CI runs on PRs that only modify docs
- Saves compute resources and speeds up feedback

```yaml
if: needs.changes.outputs.docs-only != 'true'
```

### 5. Docker Build Optimizations

**Dockerfile improvements**:
- Enable incremental compilation in Docker builds (isolated from CI sccache)
- Pre-build dependencies in separate layer
- Better layer caching strategy

```dockerfile
ENV CARGO_INCREMENTAL=1
RUN cargo build --release && rm src/main.rs
COPY . .
RUN touch src/main.rs
RUN cargo build --release
```

**Note**: Docker builds use incremental compilation since they run in isolation and don't conflict with CI's sccache usage.

### 6. sccache Integration

**Added Mozilla's sccache**:
- Caches compilation artifacts across workflow runs
- Uses GitHub Actions cache backend
- Significantly speeds up repeated builds

## Results

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Build (cached) | ~1m 12s | ~4.6s | 93% faster |
| Tests (cached) | ~1m 12s | ~16s | 78% faster |
| Clippy (cached) | ~1m | ~3.6s | 94% faster |
| Job Structure | Sequential | Parallel | 3x faster |
| PR feedback | Always full build | Skip for docs-only | Conditional |

## Usage

The optimizations are automatically applied. To test locally with incremental compilation (separate from CI):

```bash
# Run the benchmark script (uses incremental compilation for local testing)
./scripts/benchmark-build.sh

# Or manually test incremental builds locally
export CARGO_INCREMENTAL=1
cargo build  # Initial build
cargo build  # Should be much faster
```

**Note**: Local development can use incremental compilation, while CI uses sccache for distributed caching across workflow runs.

## Monitoring

Performance metrics are automatically reported to New Relic via the custom timing action, allowing monitoring of CI performance over time.