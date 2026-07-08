import { describe, it, expect, beforeEach, afterEach } from "vitest";
import request from "supertest";
import type { Express } from "express";
import { openDatabase, type ReverseShieldDb } from "../src/db/index.js";
import { createApp } from "../src/server.js";
import { loadConfig } from "../src/config.js";

const config = loadConfig({
  NODE_ENV: "test",
  RS_PORT: "3001",
  RS_PUBLIC_URL: "http://api.test",
  RS_CORS_DASHBOARD_ORIGIN: "http://dashboard.test",
});

describe("sites routes", () => {
  let db: ReverseShieldDb;
  let app: Express;

  beforeEach(() => {
    db = openDatabase(":memory:");
    app = createApp(db, config);
  });

  afterEach(() => {
    db.close();
  });

  it("POST /api/v1/sites registers a site and returns install_snippet", async () => {
    const res = await request(app)
      .post("/api/v1/sites")
      .set("Origin", "http://dashboard.test")
      .send({ name: "example.com" });

    expect(res.status).toBe(201);
    expect(res.body.site_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    expect(res.body.name).toBe("example.com");
    expect(res.body.install_snippet).toContain(res.body.site_id);
    expect(res.body.install_snippet).toContain("http://api.test");
    expect(res.body.install_snippet).toContain("/agent.js");
  });

  it("POST /api/v1/sites rejects missing name", async () => {
    const res = await request(app)
      .post("/api/v1/sites")
      .set("Origin", "http://dashboard.test")
      .send({});
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_site");
  });

  it("POST /api/v1/sites rejects unknown fields (strict schema)", async () => {
    const res = await request(app)
      .post("/api/v1/sites")
      .set("Origin", "http://dashboard.test")
      .send({ name: "x", extra_evil_field: "smuggled" });
    expect(res.status).toBe(400);
  });

  it("GET /api/v1/sites lists all registered sites", async () => {
    for (const name of ["site-a", "site-b"]) {
      await request(app)
        .post("/api/v1/sites")
        .set("Origin", "http://dashboard.test")
        .send({ name });
    }
    const res = await request(app)
      .get("/api/v1/sites")
      .set("Origin", "http://dashboard.test");
    expect(res.status).toBe(200);
    expect(res.body.sites).toHaveLength(2);
  });

  it("GET /api/v1/sites/:id/summary aggregates by type and score band", async () => {
    // Register a site
    const reg = await request(app)
      .post("/api/v1/sites")
      .set("Origin", "http://dashboard.test")
      .send({ name: "example.com" });
    const site_id = reg.body.site_id as string;

    // Insert some events directly through the DB (avoids exercising the events route,
    // which has its own test file).
    const { randomUUID } = await import("node:crypto");
    const nowIso = new Date().toISOString();

    // One human-like session
    db.insertEvent({
      event_id: randomUUID(),
      site_id,
      timestamp: nowIso,
      source: "browser",
      session_id: randomUUID(),
      type: "canary_embedded",
      score_delta: 0,
      details: "{}",
      ip_hash: null,
      user_agent: "test",
      asn: null,
    });
    // One bot-like session (triggered honeypot)
    db.insertEvent({
      event_id: randomUUID(),
      site_id,
      timestamp: nowIso,
      source: "browser",
      session_id: randomUUID(),
      type: "honeypot_triggered",
      score_delta: -80,
      details: "{}",
      ip_hash: null,
      user_agent: "test",
      asn: null,
    });

    const res = await request(app)
      .get(`/api/v1/sites/${site_id}/summary?range=24h`)
      .set("Origin", "http://dashboard.test");
    expect(res.status).toBe(200);
    expect(res.body.total_events).toBe(2);
    expect(res.body.by_type.canary_embedded).toBe(1);
    expect(res.body.by_type.honeypot_triggered).toBe(1);
    expect(res.body.score_bands.likely_human).toBe(1);
    expect(res.body.score_bands.likely_bot).toBe(1);
  });

  it("GET summary rejects malformed range", async () => {
    const reg = await request(app)
      .post("/api/v1/sites")
      .set("Origin", "http://dashboard.test")
      .send({ name: "x" });
    const res = await request(app)
      .get(`/api/v1/sites/${reg.body.site_id}/summary?range=abc`)
      .set("Origin", "http://dashboard.test");
    expect(res.status).toBe(400);
  });

  it("GET summary 404s on unknown site", async () => {
    const res = await request(app)
      .get(`/api/v1/sites/00000000-0000-4000-8000-000000000000/summary`)
      .set("Origin", "http://dashboard.test");
    expect(res.status).toBe(404);
  });
});
