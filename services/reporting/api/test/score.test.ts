/**
 * Integration tests for POST /api/v1/score.
 *
 * The endpoint has two failure surfaces that need distinct coverage:
 *
 *   1. HTTP-layer / validation errors — bad body, unknown site, malformed rules.
 *      These fire regardless of whether WASM is loaded; they're pure request-processing
 *      logic and every one of them can be exercised in isolation.
 *
 *   2. WASM engine availability — the "is the .wasm file on disk?" question. In CI
 *      the JS job builds WASM before running tests, so the engine loads and real
 *      scoring runs. Locally without a build, the engine is null and the endpoint
 *      returns 503. This file tests both branches, gating the "engine present"
 *      tests behind file existence so a fresh checkout still passes.
 *
 * Everything about this file mirrors the shape of rules.test.ts — same tmpdir harness,
 * same insertSite pattern, same CORS assertion. Consistency helps the next contributor
 * add a new endpoint test file by copying rather than inventing.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import request from "supertest";
import type { Express } from "express";
import { existsSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { openDatabase, type ReverseShieldDb } from "../src/db/index.js";
import { createApp } from "../src/server.js";
import { loadConfig, type ApiConfig } from "../src/config.js";
import { __resetEngineForTests } from "../src/scoring/engine.js";

const CANONICAL_YAML = `
- id: honeypot-field-fill
  description: "Bot filled a hidden form field"
  signal: honeypot_triggered
  weight: 80
  action: flag
- id: rate-limit-exceeded
  description: "Session exceeded request rate threshold"
  signal: rate_limit_exceeded
  weight: 40
  action: flag
`;

/**
 * Real WASM paths — the JS glue and .wasm binary produced by build-wasm.sh. The engine
 * loader reads these at first call. If either is missing, the engine caches null and
 * the endpoint returns 503; that branch is worth testing on its own.
 */
const REAL_WASM_BINARY = join(
  __dirname,
  "..",
  "..",
  "..",
  "..",
  "packages/core/pkg/reverseshield_core_bg.wasm",
);
const REAL_WASM_GLUE = join(
  __dirname,
  "..",
  "..",
  "..",
  "..",
  "packages/core/pkg/reverseshield_core.js",
);
const WASM_PRESENT = existsSync(REAL_WASM_BINARY) && existsSync(REAL_WASM_GLUE);

/**
 * Test harness — tmp rules file + optional override for WASM paths. Passing empty
 * strings for wasm paths guarantees the engine loader hits the "file not present"
 * branch, which is what the "scoring unavailable" test needs regardless of whether
 * the developer has built WASM.
 */
function makeApp(opts: {
  rulesContent: string | null;
  wasmPresent: boolean;
}): {
  app: Express;
  db: ReverseShieldDb;
  config: ApiConfig;
  cleanup: () => void;
} {
  const tmpDir = mkdtempSync(join(tmpdir(), "rs-score-test-"));
  const rulesPath = join(tmpDir, "core-rules.yaml");
  if (opts.rulesContent !== null) {
    writeFileSync(rulesPath, opts.rulesContent, "utf8");
  }

  // For the "WASM absent" branch, point both paths at files that definitively don't
  // exist. The engine loader's existsSync check short-circuits to null before any
  // dynamic import attempt, giving a deterministic 503 without touching disk.
  const wasmPath = opts.wasmPresent ? REAL_WASM_BINARY : join(tmpDir, "nope.wasm");
  const gluePath = opts.wasmPresent ? REAL_WASM_GLUE : join(tmpDir, "nope.js");

  const config = loadConfig({
    NODE_ENV: "test",
    RS_PORT: "3001",
    RS_PUBLIC_URL: "http://api.test",
    RS_CORS_DASHBOARD_ORIGIN: "http://dashboard.test",
    RS_RULES_FILE_PATH: rulesPath,
    RS_WASM_BUNDLE_PATH: wasmPath,
    RS_WASM_GLUE_JS_PATH: gluePath,
  });

  const db = openDatabase(":memory:");
  const app = createApp(db, config);

  // Reset the module-level engine cache so each harness starts fresh. Without this
  // one test's null-engine result would poison the next test's real-engine attempt.
  __resetEngineForTests();

  return {
    app,
    db,
    config,
    cleanup: () => {
      db.close();
      rmSync(tmpDir, { recursive: true, force: true });
      __resetEngineForTests();
    },
  };
}

// -----------------------------------------------------------------------------
// Validation & site-check branches — deterministic, no WASM required.
// -----------------------------------------------------------------------------

describe("POST /api/v1/score — request validation", () => {
  let harness: ReturnType<typeof makeApp>;

  beforeEach(() => {
    harness = makeApp({ rulesContent: CANONICAL_YAML, wasmPresent: false });
  });

  afterEach(() => harness.cleanup());

  it("returns 400 invalid_score_request on missing body", async () => {
    const res = await request(harness.app).post("/api/v1/score").send({});
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_score_request");
  });

  it("returns 400 when site_id is not a UUID", async () => {
    const res = await request(harness.app)
      .post("/api/v1/score")
      .send({ site_id: "not-a-uuid", signals: ["honeypot_triggered"] });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_score_request");
  });

  it("returns 400 when signals is not an array", async () => {
    const res = await request(harness.app)
      .post("/api/v1/score")
      .send({ site_id: crypto.randomUUID(), signals: "honeypot_triggered" });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_score_request");
  });

  it("returns 400 when signals contains empty strings", async () => {
    const res = await request(harness.app)
      .post("/api/v1/score")
      .send({ site_id: crypto.randomUUID(), signals: ["honeypot_triggered", ""] });
    expect(res.status).toBe(400);
  });

  it("rejects unknown fields in the request body (deny_unknown)", async () => {
    // Same rationale as ruleSchema being lenient but scoreRequestSchema being strict:
    // scoring is a call from a middleware that thinks it knows what it's asking, so
    // an unknown field is more likely a mistake than an extension.
    const res = await request(harness.app)
      .post("/api/v1/score")
      .send({
        site_id: crypto.randomUUID(),
        signals: ["honeypot_triggered"],
        extra_field: "surprise",
      });
    expect(res.status).toBe(400);
  });

  it("returns 404 unknown_site for a registered-looking but unknown site UUID", async () => {
    const res = await request(harness.app)
      .post("/api/v1/score")
      .send({ site_id: crypto.randomUUID(), signals: ["honeypot_triggered"] });
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: "unknown_site" });
  });
});

// -----------------------------------------------------------------------------
// "WASM absent" branch — deterministic 503 regardless of dev environment.
// -----------------------------------------------------------------------------

describe("POST /api/v1/score — WASM unavailable", () => {
  it("returns 503 scoring_unavailable when the WASM binary is not on disk", async () => {
    const harness = makeApp({ rulesContent: CANONICAL_YAML, wasmPresent: false });
    const siteId = crypto.randomUUID();
    harness.db.insertSite(siteId, "example.com");

    try {
      const res = await request(harness.app)
        .post("/api/v1/score")
        .send({ site_id: siteId, signals: ["honeypot_triggered"] });
      expect(res.status).toBe(503);
      expect(res.body.error).toBe("scoring_unavailable");
      expect(res.body.message).toMatch(/build-wasm\.sh/);
    } finally {
      harness.cleanup();
    }
  });
});

// -----------------------------------------------------------------------------
// Rules-file failure surface — 500 rules_unavailable branch.
// -----------------------------------------------------------------------------

describe("POST /api/v1/score — rules file failures", () => {
  it("returns 500 rules_unavailable when the rules file is missing", async () => {
    // Point WASM at something that would work IF we got that far, so we prove the
    // rules check happens before the engine call.
    const harness = makeApp({ rulesContent: null, wasmPresent: false });
    const siteId = crypto.randomUUID();
    harness.db.insertSite(siteId, "example.com");

    try {
      const res = await request(harness.app)
        .post("/api/v1/score")
        .send({ site_id: siteId, signals: ["honeypot_triggered"] });
      expect(res.status).toBe(500);
      expect(res.body.error).toBe("rules_unavailable");
    } finally {
      harness.cleanup();
    }
  });

  it("returns 500 rules_unavailable on malformed YAML", async () => {
    const harness = makeApp({ rulesContent: "not: valid: yaml: [", wasmPresent: false });
    const siteId = crypto.randomUUID();
    harness.db.insertSite(siteId, "example.com");

    try {
      const res = await request(harness.app)
        .post("/api/v1/score")
        .send({ site_id: siteId, signals: [] });
      expect(res.status).toBe(500);
      expect(res.body.error).toBe("rules_unavailable");
    } finally {
      harness.cleanup();
    }
  });
});

// -----------------------------------------------------------------------------
// Real WASM — end-to-end scoring. Skipped when WASM not built (dev without Rust).
// -----------------------------------------------------------------------------

describe.skipIf(!WASM_PRESENT)("POST /api/v1/score — end-to-end with real WASM", () => {
  let harness: ReturnType<typeof makeApp>;
  let siteId: string;

  beforeEach(() => {
    harness = makeApp({ rulesContent: CANONICAL_YAML, wasmPresent: true });
    siteId = crypto.randomUUID();
    harness.db.insertSite(siteId, "example.com");
  });

  afterEach(() => harness.cleanup());

  it("returns baseline 100 / likely_human for an empty signals list", async () => {
    const res = await request(harness.app)
      .post("/api/v1/score")
      .send({ site_id: siteId, signals: [] });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      score: 100,
      band: "likely_human",
      triggered_rule_ids: [],
      total_weight: 0,
    });
  });

  it("scores honeypot_triggered alone at 20 / likely_bot", async () => {
    // 100 − 80 = 20. Same math as scoring.rs::honeypot_alone_lands_in_suspicious_band.
    const res = await request(harness.app)
      .post("/api/v1/score")
      .send({ site_id: siteId, signals: ["honeypot_triggered"] });

    expect(res.status).toBe(200);
    expect(res.body.score).toBe(20);
    expect(res.body.band).toBe("likely_bot");
    expect(res.body.triggered_rule_ids).toEqual(["honeypot-field-fill"]);
    expect(res.body.total_weight).toBe(80);
  });

  it("clamps to 0 when combined weights exceed baseline", async () => {
    const res = await request(harness.app)
      .post("/api/v1/score")
      .send({ site_id: siteId, signals: ["honeypot_triggered", "rate_limit_exceeded"] });

    expect(res.status).toBe(200);
    expect(res.body.score).toBe(0);
    expect(res.body.band).toBe("likely_bot");
    expect(res.body.total_weight).toBe(120);
  });

  it("ignores signals that no rule reacts to", async () => {
    const res = await request(harness.app)
      .post("/api/v1/score")
      .send({ site_id: siteId, signals: ["signal_that_no_rule_matches"] });

    expect(res.status).toBe(200);
    expect(res.body.score).toBe(100);
    expect(res.body.triggered_rule_ids).toEqual([]);
  });

  it("emits permissive CORS so cross-origin callers (browser fallback) can reach it", async () => {
    const res = await request(harness.app)
      .post("/api/v1/score")
      .set("Origin", "https://arbitrary-customer-site.com")
      .send({ site_id: siteId, signals: ["honeypot_triggered"] });

    expect(res.status).toBe(200);
    expect(res.headers["access-control-allow-origin"]).toBe("*");
  });
});
