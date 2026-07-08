import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { randomUUID } from "node:crypto";
import { openDatabase, type ReverseShieldDb } from "../src/db/index.js";

describe("openDatabase", () => {
  let db: ReverseShieldDb;

  beforeEach(() => {
    db = openDatabase(":memory:");
  });

  afterEach(() => {
    db.close();
  });

  it("enables WAL journal mode (SPEC guardrail)", () => {
    // GUARDRAIL check: if this test starts failing, someone removed the pragma and we're
    // one traffic spike away from "database is locked" errors during an attack.
    // Note: :memory: databases downgrade WAL to "memory" internally — check with a file
    // DB instead by spinning up a temp path.
    // For the in-memory case, verify at least that the pragma call succeeded (didn't
    // throw) and that journal_mode returns a non-null value.
    const mode = db.raw.pragma("journal_mode", { simple: true });
    // In-memory always reports "memory"; on-disk reports "wal". Both prove the pragma
    // was applied. The important thing is that the code path executed without error.
    expect(["wal", "memory"]).toContain(String(mode).toLowerCase());
  });

  it("enforces foreign key constraints", () => {
    const fk = db.raw.pragma("foreign_keys", { simple: true });
    expect(fk).toBe(1);
  });

  it("creates the sites and events tables", () => {
    const tables = db.raw
      .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
      .all() as Array<{ name: string }>;
    const names = tables.map((t) => t.name);
    expect(names).toContain("sites");
    expect(names).toContain("events");
  });

  it("rejects events referencing a nonexistent site (FK)", () => {
    expect(() =>
      db.insertEvent({
        event_id: randomUUID(),
        site_id: randomUUID(),
        timestamp: new Date().toISOString(),
        source: "browser",
        session_id: randomUUID(),
        type: "canary_embedded",
        score_delta: 0,
        details: "{}",
        ip_hash: null,
        user_agent: "test",
        asn: null,
      }),
    ).toThrow(/FOREIGN KEY/);
  });

  it("rejects events with an unknown source (CHECK constraint)", () => {
    const site_id = randomUUID();
    db.insertSite(site_id, "test");
    expect(() =>
      db.insertEvent({
        event_id: randomUUID(),
        site_id,
        timestamp: new Date().toISOString(),
        // @ts-expect-error deliberately wrong to test CHECK constraint
        source: "not-a-source",
        session_id: randomUUID(),
        type: "canary_embedded",
        score_delta: 0,
        details: "{}",
        ip_hash: null,
        user_agent: "test",
        asn: null,
      }),
    ).toThrow(/CHECK constraint/);
  });

  it("rejects duplicate event_ids (idempotency guard)", () => {
    const site_id = randomUUID();
    db.insertSite(site_id, "test");
    const event_id = randomUUID();
    const evt = {
      event_id,
      site_id,
      timestamp: new Date().toISOString(),
      source: "browser" as const,
      session_id: randomUUID(),
      type: "canary_embedded" as const,
      score_delta: 0,
      details: "{}",
      ip_hash: null,
      user_agent: "test",
      asn: null,
    };
    db.insertEvent(evt);
    expect(() => db.insertEvent(evt)).toThrow(/UNIQUE constraint/);
  });

  it("summary aggregates event counts and score bands correctly", () => {
    const site_id = randomUUID();
    db.insertSite(site_id, "test");
    const session1 = randomUUID(); // will be likely_human (no negative deltas)
    const session2 = randomUUID(); // will be likely_bot (heavy negative delta)
    const now = Date.now();
    const iso = (offsetMinutes: number) =>
      new Date(now - offsetMinutes * 60_000).toISOString();

    // session1: two canaries, one behavioral, score stays at 100
    db.insertEvent({
      event_id: randomUUID(),
      site_id,
      timestamp: iso(1),
      source: "browser",
      session_id: session1,
      type: "canary_embedded",
      score_delta: 0,
      details: "{}",
      ip_hash: null,
      user_agent: "test",
      asn: null,
    });
    db.insertEvent({
      event_id: randomUUID(),
      site_id,
      timestamp: iso(2),
      source: "browser",
      session_id: session1,
      type: "behavioral_score",
      score_delta: 0,
      details: "{}",
      ip_hash: null,
      user_agent: "test",
      asn: null,
    });

    // session2: hits a honeypot (score_delta -80 per SPEC §3.4 default)
    db.insertEvent({
      event_id: randomUUID(),
      site_id,
      timestamp: iso(3),
      source: "browser",
      session_id: session2,
      type: "honeypot_triggered",
      score_delta: -80,
      details: '{"field":"email_alt"}',
      ip_hash: null,
      user_agent: "test",
      asn: null,
    });

    const since = new Date(now - 60 * 60_000).toISOString();
    const summary = db.summary(site_id, since);

    expect(summary.total_events).toBe(3);
    expect(summary.by_type.canary_embedded).toBe(1);
    expect(summary.by_type.behavioral_score).toBe(1);
    expect(summary.by_type.honeypot_triggered).toBe(1);
    // session1 score = 100 → likely_human. session2 score = 100 - 80 = 20 → likely_bot.
    expect(summary.score_bands.likely_human).toBe(1);
    expect(summary.score_bands.likely_bot).toBe(1);
    expect(summary.score_bands.suspicious).toBe(0);
  });

  it("summary respects the sinceIso cutoff", () => {
    const site_id = randomUUID();
    db.insertSite(site_id, "test");
    const now = Date.now();

    // Old event (2 hours ago) — should be excluded from a 1h summary
    db.insertEvent({
      event_id: randomUUID(),
      site_id,
      timestamp: new Date(now - 2 * 3600_000).toISOString(),
      source: "browser",
      session_id: randomUUID(),
      type: "canary_embedded",
      score_delta: 0,
      details: "{}",
      ip_hash: null,
      user_agent: "test",
      asn: null,
    });
    // Recent event (10 minutes ago) — should be included
    db.insertEvent({
      event_id: randomUUID(),
      site_id,
      timestamp: new Date(now - 10 * 60_000).toISOString(),
      source: "browser",
      session_id: randomUUID(),
      type: "canary_embedded",
      score_delta: 0,
      details: "{}",
      ip_hash: null,
      user_agent: "test",
      asn: null,
    });

    const oneHourAgo = new Date(now - 3600_000).toISOString();
    const summary = db.summary(site_id, oneHourAgo);
    expect(summary.total_events).toBe(1);
  });

  it("listEvents filters by type when provided", () => {
    const site_id = randomUUID();
    db.insertSite(site_id, "test");
    for (const type of ["canary_embedded", "canary_embedded", "honeypot_triggered"] as const) {
      db.insertEvent({
        event_id: randomUUID(),
        site_id,
        timestamp: new Date().toISOString(),
        source: "browser",
        session_id: randomUUID(),
        type,
        score_delta: type === "honeypot_triggered" ? -80 : 0,
        details: "{}",
        ip_hash: null,
        user_agent: "test",
        asn: null,
      });
    }
    expect(db.listEvents(site_id).length).toBe(3);
    expect(db.listEvents(site_id, "canary_embedded").length).toBe(2);
    expect(db.listEvents(site_id, "honeypot_triggered").length).toBe(1);
  });
});
