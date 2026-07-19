/**
 * Integration tests for GET /api/v1/sites/:site_id/rules.json.
 *
 * Coverage matrix (failure mode × expected browser behavior):
 *
 *   file present + valid YAML + registered site   →  200 JSON       → Scorer materializes
 *   file present + valid YAML + unknown site      →  404 unknown_site → null Scorer
 *   file missing                                  →  500 rules_unavailable → null Scorer
 *   file has malformed YAML                       →  500 rules_unavailable → null Scorer
 *   file has invalid schema (missing weight)      →  500 rules_unavailable → null Scorer
 *   file has duplicate rule IDs                   →  500 rules_unavailable → null Scorer
 *   file has non-array top-level shape            →  500 rules_unavailable → null Scorer
 *
 * The browser side (packages/agent-js/src/scoring.ts) treats every non-2xx as "no
 * local scoring for this session"; these tests verify the server-side half of that
 * contract emits the right shape so the wrapper's failure paths are actually hit.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import request from "supertest";
import type { Express } from "express";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { openDatabase, type ReverseShieldDb } from "../src/db/index.js";
import { createApp } from "../src/server.js";
import { loadConfig, type ApiConfig } from "../src/config.js";

/** Canonical valid rules YAML — mirrors rules/core-rules.yaml. */
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
 * Test harness: builds an app around a temp rules file so each test can control
 * exactly what the endpoint sees on disk. Returns a cleanup function that removes
 * the temp dir + closes the db.
 */
function makeApp(rulesContent: string | null): {
  app: Express;
  db: ReverseShieldDb;
  config: ApiConfig;
  cleanup: () => void;
} {
  const tmpDir = mkdtempSync(join(tmpdir(), "rs-rules-test-"));
  const rulesPath = join(tmpDir, "core-rules.yaml");
  if (rulesContent !== null) {
    writeFileSync(rulesPath, rulesContent, "utf8");
  }
  // If rulesContent === null, we leave the file absent — that's the "missing file" case.

  const config = loadConfig({
    NODE_ENV: "test",
    RS_PORT: "3001",
    RS_PUBLIC_URL: "http://api.test",
    RS_CORS_DASHBOARD_ORIGIN: "http://dashboard.test",
    RS_RULES_FILE_PATH: rulesPath,
  });

  const db = openDatabase(":memory:");
  const app = createApp(db, config);

  return {
    app,
    db,
    config,
    cleanup: () => {
      db.close();
      rmSync(tmpDir, { recursive: true, force: true });
    },
  };
}

describe("GET /api/v1/sites/:site_id/rules.json — happy path", () => {
  let harness: ReturnType<typeof makeApp>;
  let siteId: string;

  beforeEach(() => {
    harness = makeApp(CANONICAL_YAML);
    siteId = crypto.randomUUID(); harness.db.insertSite(siteId, "test.example.com");
  });

  afterEach(() => harness.cleanup());

  it("returns the canonical rules as a JSON array", async () => {
    const res = await request(harness.app)
      .get(`/api/v1/sites/${siteId}/rules.json`)
      .set("Origin", "https://any-origin.example.com");

    expect(res.status).toBe(200);
    expect(res.type).toBe("application/json");
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body).toHaveLength(2);
    expect(res.body[0]).toEqual({
      id: "honeypot-field-fill",
      description: "Bot filled a hidden form field",
      signal: "honeypot_triggered",
      weight: 80,
      action: "flag",
    });
  });

  it("emits permissive CORS so browser agents on any origin can fetch", async () => {
    // The whole point of registering this route with openReadOrigin BEFORE the blanket
    // /api/v1 dashboardOnly middleware. If the wildcard header isn't here, the browser
    // fleet can't reach the endpoint.
    const res = await request(harness.app)
      .get(`/api/v1/sites/${siteId}/rules.json`)
      .set("Origin", "https://arbitrary-customer-site.com");
    expect(res.status).toBe(200);
    expect(res.headers["access-control-allow-origin"]).toBe("*");
  });

  it("sets a short-lived cache header so operator edits propagate quickly", async () => {
    const res = await request(harness.app).get(`/api/v1/sites/${siteId}/rules.json`);
    expect(res.headers["cache-control"]).toMatch(/max-age=60/);
  });

  it("defaults action to 'flag' when the YAML omits it", async () => {
    harness.cleanup();
    harness = makeApp(`
- id: no-action
  description: "action omitted"
  signal: honeypot_triggered
  weight: 10
`);
    siteId = crypto.randomUUID(); harness.db.insertSite(siteId, "example.com");

    const res = await request(harness.app).get(`/api/v1/sites/${siteId}/rules.json`);
    expect(res.status).toBe(200);
    expect(res.body[0].action).toBe("flag");
  });

  it("accepts an empty rules file as a valid empty rule set", async () => {
    // Operators may deploy the file before writing any rules — SPEC §3.3 empty-file
    // handling on the Rust side is mirrored here.
    harness.cleanup();
    harness = makeApp("");
    siteId = crypto.randomUUID(); harness.db.insertSite(siteId, "example.com");

    const res = await request(harness.app).get(`/api/v1/sites/${siteId}/rules.json`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
  });
});

describe("GET /api/v1/sites/:site_id/rules.json — failure modes", () => {
  it("returns 404 unknown_site for an unregistered site_id", async () => {
    const harness = makeApp(CANONICAL_YAML);
    try {
      const res = await request(harness.app).get(
        "/api/v1/sites/not-a-real-site-id/rules.json",
      );
      expect(res.status).toBe(404);
      expect(res.body).toEqual({ error: "unknown_site" });
    } finally {
      harness.cleanup();
    }
  });

  it("returns 500 rules_unavailable when the rules file is missing", async () => {
    const harness = makeApp(null); // no file written
    const siteId = crypto.randomUUID(); harness.db.insertSite(siteId, "example.com");
    try {
      const res = await request(harness.app).get(`/api/v1/sites/${siteId}/rules.json`);
      expect(res.status).toBe(500);
      expect(res.body.error).toBe("rules_unavailable");
      expect(res.body.message).toMatch(/could not read/i);
    } finally {
      harness.cleanup();
    }
  });

  it("returns 500 rules_unavailable when the YAML is syntactically broken", async () => {
    const harness = makeApp("not: valid: yaml: [unbalanced");
    const siteId = crypto.randomUUID(); harness.db.insertSite(siteId, "example.com");
    try {
      const res = await request(harness.app).get(`/api/v1/sites/${siteId}/rules.json`);
      expect(res.status).toBe(500);
      expect(res.body.error).toBe("rules_unavailable");
      expect(res.body.message).toMatch(/malformed/i);
    } finally {
      harness.cleanup();
    }
  });

  it("returns 500 rules_unavailable when a rule is missing a required field", async () => {
    const harness = makeApp(`
- id: missing-weight
  description: "no weight field"
  signal: honeypot_triggered
`);
    const siteId = crypto.randomUUID(); harness.db.insertSite(siteId, "example.com");
    try {
      const res = await request(harness.app).get(`/api/v1/sites/${siteId}/rules.json`);
      expect(res.status).toBe(500);
      expect(res.body.error).toBe("rules_unavailable");
      expect(res.body.message).toMatch(/schema validation/i);
    } finally {
      harness.cleanup();
    }
  });

  it("returns 500 rules_unavailable on duplicate rule IDs", async () => {
    const harness = makeApp(`
- id: dup
  description: first
  signal: s
  weight: 1
- id: dup
  description: second
  signal: s
  weight: 2
`);
    const siteId = crypto.randomUUID(); harness.db.insertSite(siteId, "example.com");
    try {
      const res = await request(harness.app).get(`/api/v1/sites/${siteId}/rules.json`);
      expect(res.status).toBe(500);
      expect(res.body.error).toBe("rules_unavailable");
      expect(res.body.message).toMatch(/duplicate rule id/i);
    } finally {
      harness.cleanup();
    }
  });

  it("returns 500 rules_unavailable when the top-level shape is not an array", async () => {
    // Realistic mistake: someone wraps the rules in a top-level object thinking
    // "rules:" is required, breaking the schema silently on the Rust side otherwise.
    const harness = makeApp("rules:\n  - id: x\n    description: y\n    signal: s\n    weight: 1\n");
    const siteId = crypto.randomUUID(); harness.db.insertSite(siteId, "example.com");
    try {
      const res = await request(harness.app).get(`/api/v1/sites/${siteId}/rules.json`);
      expect(res.status).toBe(500);
      expect(res.body.error).toBe("rules_unavailable");
    } finally {
      harness.cleanup();
    }
  });

  it("returns 500 rules_unavailable when a weight is negative", async () => {
    const harness = makeApp(`
- id: bad
  description: negative weight
  signal: s
  weight: -1
`);
    const siteId = crypto.randomUUID(); harness.db.insertSite(siteId, "example.com");
    try {
      const res = await request(harness.app).get(`/api/v1/sites/${siteId}/rules.json`);
      expect(res.status).toBe(500);
      expect(res.body.error).toBe("rules_unavailable");
    } finally {
      harness.cleanup();
    }
  });
});

describe("GET /api/v1/sites/:site_id/rules.json — round-trip guarantee", () => {
  // The whole point of the JSON wire format is that what the Node service emits
  // deserializes cleanly on the Rust side. This test doesn't run WASM, but it does
  // verify that the shape matches what the Rust `Rule` struct expects field-for-field:
  // no extra fields (Rust denies unknown), no missing required fields, correct types.
  it("emits rules with exactly the fields the Rust Rule struct accepts, in the correct types", async () => {
    const harness = makeApp(CANONICAL_YAML);
    const siteId = crypto.randomUUID(); harness.db.insertSite(siteId, "example.com");
    try {
      const res = await request(harness.app).get(`/api/v1/sites/${siteId}/rules.json`);
      expect(res.status).toBe(200);

      for (const rule of res.body) {
        // Exact field set — no more, no less.
        expect(Object.keys(rule).sort()).toEqual(
          ["action", "description", "id", "signal", "weight"].sort(),
        );
        expect(typeof rule.id).toBe("string");
        expect(typeof rule.description).toBe("string");
        expect(typeof rule.signal).toBe("string");
        expect(Number.isInteger(rule.weight)).toBe(true);
        expect(rule.weight).toBeGreaterThanOrEqual(0);
        expect(["flag", "throttle", "block"]).toContain(rule.action);
      }
    } finally {
      harness.cleanup();
    }
  });

  it("re-reads the file on every request so operator edits take effect immediately", async () => {
    // No in-memory cache is the design choice. Verify it by editing the file between
    // requests and confirming the endpoint reflects the new content.
    const harness = makeApp(CANONICAL_YAML);
    const siteId = crypto.randomUUID(); harness.db.insertSite(siteId, "example.com");
    try {
      const first = await request(harness.app).get(`/api/v1/sites/${siteId}/rules.json`);
      expect(first.body).toHaveLength(2);

      writeFileSync(
        harness.config.rulesFilePath,
        `
- id: only-one
  description: replaced
  signal: honeypot_triggered
  weight: 5
`,
        "utf8",
      );

      const second = await request(harness.app).get(`/api/v1/sites/${siteId}/rules.json`);
      expect(second.body).toHaveLength(1);
      expect(second.body[0].id).toBe("only-one");
    } finally {
      harness.cleanup();
    }
  });
});
