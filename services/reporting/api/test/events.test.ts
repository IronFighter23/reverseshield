import { describe, it, expect, beforeEach, afterEach } from "vitest";
import request from "supertest";
import { randomUUID } from "node:crypto";
import type { Express } from "express";
import { openDatabase, type ReverseShieldDb } from "../src/db/index.js";
import { createApp } from "../src/server.js";
import { loadConfig } from "../src/config.js";

const config = loadConfig({
  NODE_ENV: "test",
  RS_PUBLIC_URL: "http://api.test",
  RS_CORS_DASHBOARD_ORIGIN: "http://dashboard.test",
  RS_IP_HASH_PEPPER: "test-pepper",
});

function makeValidEvent(overrides: Record<string, unknown> = {}) {
  return {
    event_id: randomUUID(),
    site_id: randomUUID(),
    timestamp: new Date().toISOString(),
    source: "browser",
    session_id: randomUUID(),
    type: "canary_embedded",
    score_delta: 0,
    details: { token: "rs_abcdef12_ABC123456789" },
    ip_hash: null,
    user_agent: "vitest",
    asn: null,
    ...overrides,
  };
}

describe("POST /api/v1/events", () => {
  let db: ReverseShieldDb;
  let app: Express;
  let siteId: string;

  beforeEach(async () => {
    db = openDatabase(":memory:");
    app = createApp(db, config);
    // Register a site so events have somewhere to land.
    const reg = await request(app)
      .post("/api/v1/sites")
      .set("Origin", "http://dashboard.test")
      .send({ name: "t" });
    siteId = reg.body.site_id;
  });

  afterEach(() => {
    db.close();
  });

  it("accepts a valid event with 202", async () => {
    const evt = makeValidEvent({ site_id: siteId });
    const res = await request(app).post("/api/v1/events").send(evt);
    expect(res.status).toBe(202);
    expect(res.body.ok).toBe(true);
  });

  it("rejects event with bad event_id (not a UUID)", async () => {
    const evt = makeValidEvent({ site_id: siteId, event_id: "not-a-uuid" });
    const res = await request(app).post("/api/v1/events").send(evt);
    expect(res.status).toBe(400);
    expect(res.body.path).toBe("event_id");
  });

  it("rejects event with bad timestamp", async () => {
    const evt = makeValidEvent({ site_id: siteId, timestamp: "yesterday" });
    const res = await request(app).post("/api/v1/events").send(evt);
    expect(res.status).toBe(400);
  });

  it("rejects event with source outside enum", async () => {
    const evt = makeValidEvent({ site_id: siteId, source: "malicious-agent" });
    const res = await request(app).post("/api/v1/events").send(evt);
    expect(res.status).toBe(400);
  });

  it("rejects event with type outside enum", async () => {
    const evt = makeValidEvent({ site_id: siteId, type: "buffer_overflow" });
    const res = await request(app).post("/api/v1/events").send(evt);
    expect(res.status).toBe(400);
  });

  it("rejects event with non-integer score_delta", async () => {
    const evt = makeValidEvent({ site_id: siteId, score_delta: 3.14 });
    const res = await request(app).post("/api/v1/events").send(evt);
    expect(res.status).toBe(400);
  });

  it("rejects event with extra unknown fields (strict schema)", async () => {
    const evt = { ...makeValidEvent({ site_id: siteId }), sneaky_extra: "gotcha" };
    const res = await request(app).post("/api/v1/events").send(evt);
    expect(res.status).toBe(400);
  });

  it("404s when site_id refers to a nonexistent site", async () => {
    const evt = makeValidEvent(); // fresh random site_id, not registered
    const res = await request(app).post("/api/v1/events").send(evt);
    expect(res.status).toBe(404);
    expect(res.body.error).toBe("unknown_site");
  });

  it("returns 409 on duplicate event_id (idempotency)", async () => {
    const evt = makeValidEvent({ site_id: siteId });
    const first = await request(app).post("/api/v1/events").send(evt);
    expect(first.status).toBe(202);
    const dup = await request(app).post("/api/v1/events").send(evt);
    expect(dup.status).toBe(409);
    expect(dup.body.error).toBe("duplicate_event");
  });

  it("stores a server-computed ip_hash even when client sends null", async () => {
    const evt = makeValidEvent({ site_id: siteId, ip_hash: null });
    await request(app).post("/api/v1/events").send(evt);
    const row = db.raw
      .prepare("SELECT ip_hash FROM events WHERE event_id = ?")
      .get(evt.event_id) as { ip_hash: string | null };
    expect(row.ip_hash).not.toBeNull();
    expect(row.ip_hash).toMatch(/^[0-9a-f]{16}$/); // SHA-256 truncated to 16 hex
  });

  it("ignores client-supplied ip_hash and recomputes server-side", async () => {
    // A malicious agent could try to smuggle in a bogus ip_hash to shift blame. Server
    // must never trust it.
    const evt = makeValidEvent({
      site_id: siteId,
      ip_hash: "ffffffffffffffff", // client tries to forge
    });
    await request(app).post("/api/v1/events").send(evt);
    const row = db.raw
      .prepare("SELECT ip_hash FROM events WHERE event_id = ?")
      .get(evt.event_id) as { ip_hash: string };
    expect(row.ip_hash).not.toBe("ffffffffffffffff");
  });
});

describe("CORS policy (SPEC guardrail)", () => {
  let db: ReverseShieldDb;
  let app: Express;

  beforeEach(() => {
    db = openDatabase(":memory:");
    app = createApp(db, config);
  });

  afterEach(() => {
    db.close();
  });

  it("POST /api/v1/events allows any origin (agents install anywhere)", async () => {
    // Reflects the requesting origin rather than sending "*". Same threat model —
    // the events response is {ok:true}, nothing sensitive — but reflection is
    // required because the browser agent's fetch sends credentials:'include' and
    // browsers reject "*" when credentials are involved.
    const arbitraryOrigin = "https://random-customer-site.com";
    const res = await request(app)
      .options("/api/v1/events")
      .set("Origin", arbitraryOrigin)
      .set("Access-Control-Request-Method", "POST");
    expect(res.headers["access-control-allow-origin"]).toBe(arbitraryOrigin);
    expect(res.headers["access-control-allow-credentials"]).toBe("true");

    // Prove a completely different origin also gets reflected — this is the
    // "allows any origin" guarantee, just via reflection instead of wildcard.
    const otherOrigin = "https://another-customer.example";
    const res2 = await request(app)
      .options("/api/v1/events")
      .set("Origin", otherOrigin)
      .set("Access-Control-Request-Method", "POST");
    expect(res2.headers["access-control-allow-origin"]).toBe(otherOrigin);
  });

  it("GET /api/v1/sites reflects only the dashboard origin", async () => {
    // A random attacker origin should NOT be permitted to read.
    const res = await request(app)
      .get("/api/v1/sites")
      .set("Origin", "https://attacker.example");
    // The cors middleware sets a specific origin (or nothing) — not '*' — for locked
    // routes. The exact behavior when origin mismatches is that ACAO is omitted, which
    // browsers treat as no cross-origin permission.
    expect(res.headers["access-control-allow-origin"]).not.toBe("*");
    if (res.headers["access-control-allow-origin"]) {
      expect(res.headers["access-control-allow-origin"]).toBe("http://dashboard.test");
    }
  });

  it("GET /api/v1/sites permits the configured dashboard origin", async () => {
    const res = await request(app)
      .get("/api/v1/sites")
      .set("Origin", "http://dashboard.test");
    expect(res.headers["access-control-allow-origin"]).toBe("http://dashboard.test");
  });
});
