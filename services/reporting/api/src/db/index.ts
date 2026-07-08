/**
 * SQLite database layer for the reporting API.
 *
 * CRITICAL: WAL mode is enabled on every open connection. Without it we get
 * "database is locked" errors under the highly concurrent, write-heavy traffic patterns
 * that this API sees during an active attack — exactly when we can least afford outages.
 *
 * Design notes:
 *  * `better-sqlite3` is synchronous, which is a feature here — Node's event loop stays
 *    responsive because SQLite operations are microsecond-scale, and we avoid the
 *    "sqlite3" package's callback pyramid.
 *  * Schema loaded from schema.sql. `CREATE TABLE IF NOT EXISTS` means a fresh DB is
 *    auto-created; the API is truly zero-config for self-host.
 *  * All prepared statements are built once at open time and reused. This is the standard
 *    better-sqlite3 pattern and gives ~10x speedup vs re-preparing per call.
 */

import Database from "better-sqlite3";
import { readFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA_SQL = readFileSync(resolve(HERE, "schema.sql"), "utf-8");

export type EventType =
  | "honeypot_triggered"
  | "canary_embedded"
  | "rate_limit_exceeded"
  | "behavioral_score"
  | "attestation_failed"
  | "request_fingerprint";

export type EventSource = "browser" | "server";

export interface SiteRow {
  site_id: string;
  name: string;
  created_at: string;
}

export interface EventRow {
  event_id: string;
  site_id: string;
  timestamp: string;
  source: EventSource;
  session_id: string;
  type: EventType;
  score_delta: number;
  details: string; // JSON string
  ip_hash: string | null;
  user_agent: string | null;
  asn: string | null;
  received_at: string;
}

export interface EventInsert {
  event_id: string;
  site_id: string;
  timestamp: string;
  source: EventSource;
  session_id: string;
  type: EventType;
  score_delta: number;
  details: string;
  ip_hash: string | null;
  user_agent: string | null;
  asn: string | null;
}

export interface SummaryRow {
  total_events: number;
  by_type: Record<EventType, number>;
  score_bands: { likely_human: number; suspicious: number; likely_bot: number };
}

export interface ReverseShieldDb {
  raw: Database.Database;
  insertSite: (siteId: string, name: string) => void;
  getSite: (siteId: string) => SiteRow | undefined;
  listSites: () => SiteRow[];
  insertEvent: (row: EventInsert) => void;
  listEvents: (siteId: string, type?: EventType, limit?: number) => EventRow[];
  summary: (siteId: string, sinceIso: string) => SummaryRow;
  close: () => void;
}

/**
 * Open a database at `path` (or `:memory:` for tests). Applies WAL + hardening pragmas,
 * runs the schema migration, and returns a wrapper with prepared-statement helpers.
 */
export function openDatabase(path: string): ReverseShieldDb {
  if (path !== ":memory:") {
    mkdirSync(dirname(path), { recursive: true });
  }

  const db = new Database(path);

  // GUARDRAIL: WAL mode. Non-negotiable for a write-heavy security tool.
  // In WAL mode readers don't block writers and writers don't block readers — the exact
  // property that keeps ingestion responsive while the dashboard is being queried.
  db.pragma("journal_mode = WAL");
  // synchronous=NORMAL is safe under WAL and materially faster than FULL. Loses at most
  // the last transaction on OS crash (not on process crash).
  db.pragma("synchronous = NORMAL");
  // Enforce FK constraints so a stray event with a bogus site_id can't land.
  db.pragma("foreign_keys = ON");
  // Reasonable busy timeout in case a batch write blocks briefly.
  db.pragma("busy_timeout = 5000");

  db.exec(SCHEMA_SQL);

  // Prepared statements — built once, reused per call.
  const stmtInsertSite = db.prepare(
    `INSERT INTO sites (site_id, name) VALUES (?, ?)`,
  );
  const stmtGetSite = db.prepare<[string], SiteRow>(
    `SELECT site_id, name, created_at FROM sites WHERE site_id = ?`,
  );
  const stmtListSites = db.prepare<[], SiteRow>(
    `SELECT site_id, name, created_at FROM sites ORDER BY created_at DESC`,
  );
  const stmtInsertEvent = db.prepare(
    `INSERT INTO events
       (event_id, site_id, timestamp, source, session_id, type, score_delta,
        details, ip_hash, user_agent, asn)
     VALUES
       (@event_id, @site_id, @timestamp, @source, @session_id, @type, @score_delta,
        @details, @ip_hash, @user_agent, @asn)`,
  );
  const stmtListEventsAll = db.prepare<[string, number], EventRow>(
    `SELECT * FROM events WHERE site_id = ? ORDER BY timestamp DESC LIMIT ?`,
  );
  const stmtListEventsFiltered = db.prepare<
    [string, EventType, number],
    EventRow
  >(
    `SELECT * FROM events
       WHERE site_id = ? AND type = ?
       ORDER BY timestamp DESC LIMIT ?`,
  );
  const stmtCountByType = db.prepare<
    [string, string],
    { type: EventType; count: number }
  >(
    `SELECT type, COUNT(*) AS count FROM events
       WHERE site_id = ? AND timestamp >= ?
       GROUP BY type`,
  );
  const stmtTotalEvents = db.prepare<[string, string], { total: number }>(
    `SELECT COUNT(*) AS total FROM events
       WHERE site_id = ? AND timestamp >= ?`,
  );
  // Score band computation via SPEC §3.4 formula:
  //   session_score = clamp(100 + sum(score_delta), 0, 100)
  //   band =
  //     'likely_human' if session_score >= 70 else
  //     'suspicious'   if session_score >= 40 else
  //     'likely_bot'
  const stmtScoreBands = db.prepare<
    [string, string],
    { band: string; sessions: number }
  >(
    `WITH session_scores AS (
       SELECT session_id,
              MAX(0, MIN(100, 100 + COALESCE(SUM(score_delta), 0))) AS score
         FROM events
        WHERE site_id = ? AND timestamp >= ?
        GROUP BY session_id
     )
     SELECT CASE
              WHEN score >= 70 THEN 'likely_human'
              WHEN score >= 40 THEN 'suspicious'
              ELSE 'likely_bot'
            END AS band,
            COUNT(*) AS sessions
       FROM session_scores
      GROUP BY band`,
  );

  const emptyByType: Record<EventType, number> = {
    honeypot_triggered: 0,
    canary_embedded: 0,
    rate_limit_exceeded: 0,
    behavioral_score: 0,
    attestation_failed: 0,
    request_fingerprint: 0,
  };

  return {
    raw: db,

    insertSite(siteId, name) {
      stmtInsertSite.run(siteId, name);
    },

    getSite(siteId) {
      return stmtGetSite.get(siteId);
    },

    listSites() {
      return stmtListSites.all();
    },

    insertEvent(row) {
      stmtInsertEvent.run(row);
    },

    listEvents(siteId, type, limit = 100) {
      if (type) {
        return stmtListEventsFiltered.all(siteId, type, limit);
      }
      return stmtListEventsAll.all(siteId, limit);
    },

    summary(siteId, sinceIso) {
      const total = stmtTotalEvents.get(siteId, sinceIso)?.total ?? 0;

      const byTypeRows = stmtCountByType.all(siteId, sinceIso);
      const by_type: Record<EventType, number> = { ...emptyByType };
      for (const row of byTypeRows) by_type[row.type] = row.count;

      const bandRows = stmtScoreBands.all(siteId, sinceIso);
      const score_bands = { likely_human: 0, suspicious: 0, likely_bot: 0 };
      for (const row of bandRows) {
        if (row.band === "likely_human") score_bands.likely_human = row.sessions;
        else if (row.band === "suspicious") score_bands.suspicious = row.sessions;
        else if (row.band === "likely_bot") score_bands.likely_bot = row.sessions;
      }

      return { total_events: total, by_type, score_bands };
    },

    close() {
      db.close();
    },
  };
}
