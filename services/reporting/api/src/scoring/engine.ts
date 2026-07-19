/**
 * Lazy loader for the shared reverseshield-core WASM engine, used by POST /api/v1/score.
 *
 * Design:
 *   * WASM is loaded once per process on first request. The result — engine or `null` —
 *     is cached; subsequent requests reuse it without re-reading the .wasm binary.
 *   * If loading fails (WASM not built, JS glue absent, WebAssembly.instantiate throws),
 *     the cache stores `null` and the scoring endpoint returns 503. The server stays up.
 *   * Loading is deferred to first request, not startup. That means `npm run dev` on a
 *     fresh checkout without WASM built doesn't error — the server boots, and every
 *     score request returns 503 with a clear "run build-wasm.sh" message.
 *
 * The dynamic `import()` intentionally uses a runtime-computed string so TypeScript
 * doesn't try to resolve the target at typecheck time (the JS glue may not exist yet).
 * Same pattern packages/agent-js uses via scripts/prepare-wasm.mjs, adapted for a Node
 * server: no stub file, just a `null` engine that the endpoint translates into 503.
 */

import { existsSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

import type { ApiConfig } from "../config.js";

/**
 * The subset of wasm-bindgen exports the score endpoint actually uses. Keeping this
 * narrow means a future change to what the WASM exposes doesn't accidentally leak
 * into HTTP-layer code.
 */
export interface WasmEngine {
  scoreFromWeights: (weights: Uint32Array) => number;
  scoreSignalsJson: (rulesJson: string, signalsJson: string) => string;
}

// undefined = never loaded; null = loaded, failed; WasmEngine = loaded, ready.
let cached: WasmEngine | null | undefined = undefined;
let loadingPromise: Promise<WasmEngine | null> | null = null;

/**
 * Get the WASM engine, loading it if this is the first call this process has seen.
 * Never throws — a failed load resolves to `null` and stays cached that way. Callers
 * are expected to check for `null` and return an HTTP 503.
 *
 * Concurrent first-call safety: if multiple requests hit before the first load
 * finishes, they share the same in-flight promise instead of racing to open the file
 * six times.
 */
export async function getEngine(config: ApiConfig): Promise<WasmEngine | null> {
  if (cached !== undefined) return cached;
  if (loadingPromise !== null) return loadingPromise;
  loadingPromise = loadOnce(config);
  const result = await loadingPromise;
  cached = result;
  loadingPromise = null;
  return result;
}

/** Test-only escape hatch. Resets the module cache so a subsequent load re-reads disk. */
export function __resetEngineForTests(): void {
  cached = undefined;
  loadingPromise = null;
}

async function loadOnce(config: ApiConfig): Promise<WasmEngine | null> {
  const wasmPath = config.wasmBundlePath;
  const gluePath = config.wasmGlueJsPath;

  if (!existsSync(wasmPath) || !existsSync(gluePath)) {
    return null;
  }

  try {
    const wasmBytes = readFileSync(wasmPath);
    // Runtime-computed specifier defeats TS static resolution — the JS glue is
    // generated code that may not exist at compile time. See the pattern in
    // packages/agent-js/test/scoring.wasm.test.ts.
    const glueSpecifier = pathToFileURL(gluePath).href;
    const mod = await import(/* @vite-ignore */ glueSpecifier);
    await mod.default(wasmBytes);
    return {
      scoreFromWeights: mod.scoreFromWeights,
      scoreSignalsJson: mod.scoreSignalsJson,
    };
  } catch {
    // Any failure — bad binary, glue import throws, WebAssembly instantiation error —
    // gets swallowed into a `null` engine. We do NOT log here: the endpoint handler
    // logs once when it converts null into a 503, which is where operator attention
    // needs to land anyway.
    return null;
  }
}
