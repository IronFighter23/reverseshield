-- ReverseShield reporting DB schema (v1)
--
-- Design notes:
--  * All timestamps stored as ISO-8601 TEXT. SQLite has no native datetime type but
--    ISO-8601 sorts lexicographically the same as chronologically. Simpler than INTEGER
--    epochs and preserves the timezone info the browser sent.
--  * Enum fields use CHECK constraints as belt-and-braces alongside zod validation at
--    the route layer. A malformed event that somehow slips past zod (e.g. via a raw SQL
--    tool used against the DB directly) still can't corrupt the table.
--  * `details` stored as JSON TEXT. SQLite has JSON1 built in — we can query into it
--    with json_extract() when we build filtered views in Phase 2.
--  * received_at is server clock; timestamp is client clock. Both kept so we can detect
--    replay/clock-skew attacks later.

CREATE TABLE IF NOT EXISTS sites (
  site_id      TEXT PRIMARY KEY NOT NULL,
  name         TEXT NOT NULL,
  created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS events (
  event_id     TEXT PRIMARY KEY NOT NULL,
  site_id      TEXT NOT NULL,
  timestamp    TEXT NOT NULL,
  source       TEXT NOT NULL CHECK (source IN ('browser', 'server')),
  session_id   TEXT NOT NULL,
  type         TEXT NOT NULL CHECK (type IN (
                 'honeypot_triggered',
                 'canary_embedded',
                 'rate_limit_exceeded',
                 'behavioral_score',
                 'attestation_failed',
                 'request_fingerprint'
               )),
  score_delta  INTEGER NOT NULL,
  details      TEXT NOT NULL,
  ip_hash      TEXT,
  user_agent   TEXT,
  asn          TEXT,
  received_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  FOREIGN KEY (site_id) REFERENCES sites(site_id) ON DELETE CASCADE
);

-- Dominant read patterns:
--  * Summary/list for a site, ordered by recency
CREATE INDEX IF NOT EXISTS idx_events_site_timestamp
  ON events(site_id, timestamp DESC);

--  * Filtering by type on the /events?type= endpoint
CREATE INDEX IF NOT EXISTS idx_events_site_type
  ON events(site_id, type, timestamp DESC);

--  * Score band computation aggregates by session
CREATE INDEX IF NOT EXISTS idx_events_session
  ON events(site_id, session_id);
