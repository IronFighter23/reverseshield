#!/usr/bin/env bash
#
# Build the reverseshield-core Rust crate to WebAssembly for browser use.
#
# What this produces:
#   packages/core/pkg/reverseshield_core.js         — wasm-bindgen JS glue (ES module)
#   packages/core/pkg/reverseshield_core_bg.wasm    — the WASM binary
#   packages/core/pkg/reverseshield_core.d.ts       — TypeScript definitions
#   packages/core/pkg/reverseshield_core_bg.wasm.d.ts
#
# These are the inputs the JS agent will consume in sub-step 2c. They are gitignored:
# CI (or your local machine) rebuilds them on demand, we do not commit generated code.
#
# Idempotent — safe to re-run. Cached cargo state makes the second run near-instant.
#
# Requirements:
#   * rustup on PATH (used to install the wasm32 target)
#   * cargo on PATH (used to install wasm-bindgen-cli)
#   * gzip on PATH (used for the size report; every reasonable *nix ships this)
#
# WASM_BINDGEN_VERSION must match the `wasm-bindgen` dep pin in packages/core/Cargo.toml.
# If they drift, `wasm-bindgen` refuses to process the .wasm with a "schema version
# mismatch" error. Bump both together, never one alone.

set -euo pipefail

WASM_BINDGEN_VERSION="0.2.100"

# Resolve REPO_ROOT so this script works regardless of where the caller invokes it.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

echo "==> Ensuring wasm32-unknown-unknown target is installed"
rustup target add wasm32-unknown-unknown

echo "==> Ensuring wasm-bindgen-cli@$WASM_BINDGEN_VERSION is installed"
# `cargo install` no-ops when the exact version is already present, so this is fast
# on cached CI runners. First-time install compiles from source (~2 min on cold cache).
cargo install wasm-bindgen-cli --version "$WASM_BINDGEN_VERSION" --locked

echo "==> Building reverseshield-core for wasm32-unknown-unknown (release, --no-default-features)"
# --no-default-features drops serde_yaml, which alone is ~50 KB of gzipped code the
# browser has no use for (browsers receive rules as pre-parsed JSON from the reporting API).
cargo build \
    --release \
    --target wasm32-unknown-unknown \
    --no-default-features \
    -p reverseshield-core

WASM_INPUT="target/wasm32-unknown-unknown/release/reverseshield_core.wasm"
if [ ! -f "$WASM_INPUT" ]; then
    echo "ERROR: cargo did not produce $WASM_INPUT" >&2
    exit 1
fi

echo "==> Running wasm-bindgen to generate browser-loadable glue"
mkdir -p packages/core/pkg
wasm-bindgen \
    --target web \
    --out-dir packages/core/pkg \
    "$WASM_INPUT"

WASM_OUTPUT="packages/core/pkg/reverseshield_core_bg.wasm"
if [ ! -f "$WASM_OUTPUT" ]; then
    echo "ERROR: expected $WASM_OUTPUT but wasm-bindgen did not produce it" >&2
    exit 1
fi

# --- Size report --------------------------------------------------------------------
#
# Report raw and gzipped size. Gzipped is what the user's bandwidth actually pays for,
# and what we compare against the eventual hard budget in sub-step 2c.
#
# `stat -c%s` is GNU (Linux, CI); `stat -f%z` is BSD (macOS local dev). Try both.
if RAW_SIZE=$(stat -c%s "$WASM_OUTPUT" 2>/dev/null); then :; else RAW_SIZE=$(stat -f%z "$WASM_OUTPUT"); fi
GZIP_SIZE=$(gzip -9 -c "$WASM_OUTPUT" | wc -c | tr -d ' ')

echo ""
echo "==> Build complete"
echo "    Raw WASM:  $RAW_SIZE bytes"
echo "    Gzipped:   $GZIP_SIZE bytes (what the browser actually downloads)"

# Soft budget: warn if over, but do not fail. This is intentional for sub-step 2b —
# we are establishing an unoptimized baseline. Sub-step 2c will lock in a hard failure
# threshold once we know what "reasonable" looks like in practice.
SOFT_BUDGET_GZIP=80000
if [ "$GZIP_SIZE" -gt "$SOFT_BUDGET_GZIP" ]; then
    # GitHub Actions picks up ::warning:: annotations and surfaces them on the run page.
    # In local runs it's just an extra echo line — harmless either way.
    echo "::warning file=$WASM_OUTPUT::gzipped WASM size $GZIP_SIZE B exceeds soft budget of $SOFT_BUDGET_GZIP B"
fi

echo ""
echo "==> Generated files in packages/core/pkg/:"
ls -la packages/core/pkg/
