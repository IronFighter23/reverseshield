#!/usr/bin/env node
/**
 * Copy the wasm-bindgen output from packages/core/pkg/ into src/wasm/, or write a
 * stub if the real build hasn't run yet. Idempotent — safe to run repeatedly.
 *
 * Called by: `npm run wasm` (explicit), and `pretest` / `prebuild` / `prelint` hooks.
 *
 * Design: this script *never* triggers a Rust build. That's build-wasm.sh's job. Here
 * we just move bytes from where the WASM build produced them to where esbuild and
 * vitest expect to find them. If the real files don't exist, we write a stub so that
 * TypeScript / esbuild / vitest can still resolve imports — the runtime behavior of
 * the stub is to throw, which the silent-fail wrapper in scoring.ts catches.
 *
 * Consequence: `npm test` never fails just because the user forgot to build WASM.
 * Tests that require real WASM detect its absence via file existence and skip. The
 * mock-based scoring tests always pass.
 */

import { existsSync, mkdirSync, copyFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const packageDir = resolve(__dirname, "..");
const repoRoot = resolve(packageDir, "..", "..");

const src = {
  js: resolve(repoRoot, "packages/core/pkg/reverseshield_core.js"),
  wasm: resolve(repoRoot, "packages/core/pkg/reverseshield_core_bg.wasm"),
  dts: resolve(repoRoot, "packages/core/pkg/reverseshield_core.d.ts"),
  wasmDts: resolve(repoRoot, "packages/core/pkg/reverseshield_core_bg.wasm.d.ts"),
};

const dst = {
  js: resolve(packageDir, "src/wasm/reverseshield_core.js"),
  wasm: resolve(packageDir, "src/wasm/reverseshield_core_bg.wasm"),
  dts: resolve(packageDir, "src/wasm/reverseshield_core.d.ts"),
  wasmDts: resolve(packageDir, "src/wasm/reverseshield_core_bg.wasm.d.ts"),
};

mkdirSync(resolve(packageDir, "src/wasm"), { recursive: true });

const STUB_JS = `// Auto-written stub — placeholder for the wasm-bindgen output that lives here after
// running \`bash packages/core/build-wasm.sh\`. The real file is generated and NOT
// committed. This stub keeps TypeScript / esbuild / vitest happy in a fresh checkout;
// at runtime it throws, which the silent-fail wrapper in scoring.ts catches and
// converts into a null scorer (no local scoring, agent continues shipping events).
const NOT_BUILT = "reverseshield-core WASM has not been built for this workspace";
export default async function init() { throw new Error(NOT_BUILT); }
export function scoreFromWeights() { throw new Error(NOT_BUILT); }
export function scoreSignalsJson() { throw new Error(NOT_BUILT); }
`;

const STUB_DTS = `// Auto-written stub — see reverseshield_core.js for context.
export default function init(input?: unknown): Promise<unknown>;
export function scoreFromWeights(weights: Uint32Array): number;
export function scoreSignalsJson(rulesJson: string, signalsJson: string): string;
`;

if (existsSync(src.js) && existsSync(src.wasm)) {
  copyFileSync(src.js, dst.js);
  copyFileSync(src.wasm, dst.wasm);
  if (existsSync(src.dts)) copyFileSync(src.dts, dst.dts);
  if (existsSync(src.wasmDts)) copyFileSync(src.wasmDts, dst.wasmDts);
  console.log("[prepare-wasm] copied real WASM from packages/core/pkg/");
} else {
  writeFileSync(dst.js, STUB_JS);
  writeFileSync(dst.dts, STUB_DTS);
  // Deliberately do NOT write a stub .wasm binary — its absence is how tests detect
  // "no real WASM present, skip the integration tests".
  console.log("[prepare-wasm] real WASM not built; wrote stub to src/wasm/");
  console.log("[prepare-wasm]   → run `bash packages/core/build-wasm.sh` for local scoring");
}
