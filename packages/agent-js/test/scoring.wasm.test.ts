/**
 * Integration test for the real wasm-bindgen output.
 *
 * This file only runs meaningful assertions when `src/wasm/reverseshield_core_bg.wasm`
 * exists — that is, when `bash packages/core/build-wasm.sh` has been run at some point
 * before `npm test`. In a fresh checkout without the Rust toolchain, the file is
 * absent and the whole describe block is skipped with a helpful log line.
 *
 * On CI the WASM is always built by the `js` job's WASM step, so these tests always
 * run in the pipeline. On a contributor's local machine they run if that contributor
 * has Rust installed; otherwise the mock-based tests in scoring.test.ts carry the
 * silent-fail coverage and this file no-ops.
 *
 * What this file proves that scoring.test.ts cannot: that the JS ↔ WASM bridge
 * actually round-trips real bytes through wasm-bindgen's generated glue, real
 * WebAssembly.instantiate, and the shared crate::scoring code path. If a serde
 * attribute drifts or a wasm-bindgen JS-name annotation is wrong, this test breaks
 * loudly; the mocks would happily go on lying.
 */

import { describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const wasmDir = resolve(__dirname, "..", "src", "wasm");
const wasmBinaryPath = resolve(wasmDir, "reverseshield_core_bg.wasm");
const wasmJsPath = resolve(wasmDir, "reverseshield_core.js");

const wasmPresent = existsSync(wasmBinaryPath);
if (!wasmPresent) {
  // eslint-disable-next-line no-console
  console.warn(
    "[scoring.wasm.test] skipping real-WASM tests — src/wasm/reverseshield_core_bg.wasm not present.\n" +
      "  Run `bash packages/core/build-wasm.sh && node packages/agent-js/scripts/prepare-wasm.mjs` to enable.",
  );
}

// Canonical rules matching packages/core/src/scoring.rs tests. If Rust's `to_json_string`
// output shape ever drifts this fixture will drift with it — regenerate from the crate.
const CANONICAL_RULES = JSON.stringify([
  { id: "honeypot-field-fill", description: "h", signal: "honeypot_triggered", weight: 80, action: "flag" },
  { id: "rate-limit-exceeded", description: "r", signal: "rate_limit_exceeded", weight: 40, action: "flag" },
  { id: "canary-embedded", description: "c", signal: "canary_embedded", weight: 0, action: "flag" },
]);

describe.skipIf(!wasmPresent)("scoring.wasm — real WASM round-trip", () => {
  it("loads the WASM module and exports scoreFromWeights + scoreSignalsJson", async () => {
    // Import the real (non-stub) module. If this file was written by prepare-wasm's
    // "real files" branch, it's the wasm-bindgen output; if the stub, this test was
    // skipped above and we never get here.
    const mod = await import("../src/wasm/reverseshield_core.js");
    // Pass the .wasm binary as a Uint8Array — wasm-bindgen's --target web init()
    // accepts this shape and calls WebAssembly.instantiate() under the hood, which
    // is what works in Node without any streaming-fetch polyfill.
    const bytes = readFileSync(wasmBinaryPath);
    await mod.default(bytes);
    expect(typeof mod.scoreFromWeights).toBe("function");
    expect(typeof mod.scoreSignalsJson).toBe("function");
  });

  it("scoreFromWeights([80, 40]) clamps to 0 (SPEC §3.4 canonical case)", async () => {
    const mod = await import("../src/wasm/reverseshield_core.js");
    await mod.default(readFileSync(wasmBinaryPath));
    // 100 - (80 + 40) = -20 → clamped to 0. Same test as
    // packages/core/src/scoring.rs::multiple_weights_sum_and_subtract.
    expect(mod.scoreFromWeights(Uint32Array.from([80, 40]))).toBe(0);
  });

  it("scoreFromWeights([]) returns baseline 100", async () => {
    const mod = await import("../src/wasm/reverseshield_core.js");
    await mod.default(readFileSync(wasmBinaryPath));
    expect(mod.scoreFromWeights(new Uint32Array(0))).toBe(100);
  });

  it("scoreSignalsJson returns the correct band for honeypot_triggered alone", async () => {
    const mod = await import("../src/wasm/reverseshield_core.js");
    await mod.default(readFileSync(wasmBinaryPath));

    const raw = mod.scoreSignalsJson(CANONICAL_RULES, JSON.stringify(["honeypot_triggered"]));
    const result = JSON.parse(raw);

    // 100 - 80 = 20 → LikelyBot.
    expect(result.score).toBe(20);
    expect(result.band).toBe("likely_bot");
    expect(result.triggered_rule_ids).toEqual(["honeypot-field-fill"]);
    expect(result.total_weight).toBe(80);
  });

  it("scoreSignalsJson throws on malformed rules (caller responsible for catch)", async () => {
    const mod = await import("../src/wasm/reverseshield_core.js");
    await mod.default(readFileSync(wasmBinaryPath));
    // The Rust side returns a Result<String, JsError>; wasm-bindgen turns Err into
    // a JS throw. scoring.ts wraps this in try/catch so callers never see it —
    // but the raw binding itself does throw, which we verify here.
    expect(() => mod.scoreSignalsJson("not-json", "[]")).toThrow();
  });
});

describe.skipIf(!wasmPresent)("scoring.wasm — end-to-end via scoring.ts wrapper", () => {
  it("initScoring returns a working Scorer against a mocked rules endpoint", async () => {
    // Serve the canonical rules via mocked fetch, and pass a Uint8Array to init via
    // the wasmUrl config — but since we're in Node, use a file:// data URL trick:
    // we monkey-patch fetch to return the same rules for the rules URL, and the wasm
    // module's init() to load from the local bytes.
    //
    // This flexes the whole silent-fail wrapper on real WASM: if any adapter layer
    // (JSON escaping, Uint32Array conversion, JSON parse of ScoreResult) is broken,
    // this test catches it.
    const { initScoring, __resetScoringForTests } = await import("../src/scoring.js");
    __resetScoringForTests();

    const { vi } = await import("vitest");
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      if (String(url).includes("/rules.json")) {
        return Promise.resolve({ ok: true, status: 200, text: () => Promise.resolve(CANONICAL_RULES) } as Response);
      }
      // The wasmUrl request will be redirected: we can't actually fetch a wasm URL
      // in Node without a real HTTP server, but we don't need to — we prime the
      // WASM module below by calling init() ourselves with the file bytes.
      return Promise.reject(new TypeError("unstubbed url"));
    }));

    // Pre-init the wasm module with the local .wasm bytes so that when scoring.ts
    // calls `await init(config.wasmUrl)`, the module is already ready and the URL
    // fetch is a no-op inside wasm-bindgen.
    const mod = await import("../src/wasm/reverseshield_core.js");
    await mod.default(readFileSync(wasmBinaryPath));

    const scorer = await initScoring({
      siteId: "s",
      endpoint: "https://x",
      seed: "seed",
      honeypotCount: 2,
      debug: false,
      behavioralSnapshotDelayMs: 10_000,
      localScoring: true,
      rulesUrl: "https://x/api/v1/sites/s/rules.json",
      wasmUrl: "https://x/agent/reverseshield_core_bg.wasm",
      rulesTimeoutMs: 5_000,
    });

    expect(scorer).not.toBeNull();
    const result = scorer!.score(["honeypot_triggered", "rate_limit_exceeded"]);
    expect(result).not.toBeNull();
    expect(result!.score).toBe(0);
    expect(result!.band).toBe("likely_bot");

    vi.unstubAllGlobals();
  });
});
