import { Router, type Request, type Response } from "express";
import { createHash } from "node:crypto";
import type { ReverseShieldDb } from "../db/index.js";
import type { ApiConfig } from "../config.js";
import { eventSchema } from "../validators.js";

/**
 * Truncated SHA-256 of the request IP, mixed with the install pepper.
 *
 * SPEC §3.1: "sha256 truncated, never store raw IP by default". Truncated to 16 hex
 * chars (64 bits) — enough entropy to keep unique IPs distinct within reasonable
 * per-site traffic volumes, without offering enough surface to brute-force an IP
 * back out. The pepper (set via RS_IP_HASH_PEPPER) prevents cross-install correlation.
 */
function hashIp(ip: string, pepper: string): string {
  return createHash("sha256").update(pepper).update(ip).digest("hex").slice(0, 16);
}

export function eventsRouter(db: ReverseShieldDb, config: ApiConfig) {
  const router = Router();

  router.post("/", (req: Request, res: Response) => {
    const parsed = eventSchema.safeParse(req.body);
    if (!parsed.success) {
      // Return the first validation issue with the offending path so agents/dev tools
      // can log a specific problem, not a generic "400". Only the first — we don't need
      // to enumerate every field for a debugger.
      const issue = parsed.error.issues[0];
      return res.status(400).json({
        error: "invalid_event",
        message: issue.message,
        path: issue.path.join("."),
      });
    }
    const event = parsed.data;

    // The site referenced by the event must exist. Otherwise a bad actor could flood the
    // DB with events pointing at nonexistent site_ids, wasting storage.
    const site = db.getSite(event.site_id);
    if (!site) {
      return res.status(404).json({ error: "unknown_site", site_id: event.site_id });
    }

    // Compute ip_hash server-side, regardless of what the client sent. The client's
    // ip_hash field is always null for browser events; for server-side agents we still
    // recompute so a compromised agent can't forge attributions.
    const clientIp = req.ip ?? req.socket.remoteAddress ?? "";
    const ip_hash = clientIp ? hashIp(clientIp, config.ipHashPepper) : null;

    try {
      db.insertEvent({
        event_id: event.event_id,
        site_id: event.site_id,
        timestamp: event.timestamp,
        source: event.source,
        session_id: event.session_id,
        type: event.type,
        score_delta: event.score_delta,
        details: JSON.stringify(event.details),
        ip_hash,
        user_agent: event.user_agent,
        asn: event.asn,
      });
    } catch (err) {
      // Duplicate event_id → 409 (client retry, don't double-count).
      // Any other DB error → surface as 500 but log for triage.
      const message = err instanceof Error ? err.message : String(err);
      if (/UNIQUE constraint failed: events\.event_id/i.test(message)) {
        return res.status(409).json({ error: "duplicate_event" });
      }
      // eslint-disable-next-line no-console
      console.error("[events] insert failed:", message);
      return res.status(500).json({ error: "insert_failed" });
    }

    // 202 Accepted: signal to fire-and-forget agents that ingestion succeeded without
    // implying any downstream processing has completed.
    return res.status(202).json({ ok: true });
  });

  return router;
}

/**
 * GET /api/v1/sites/:site_id/events (read side). Kept in this module so both
 * ingestion and retrieval of the same resource live together.
 */
export function siteEventsRouter(db: ReverseShieldDb) {
  const router = Router({ mergeParams: true });

  router.get("/", (req: Request, res: Response) => {
    const siteId = req.params.site_id as string;
    if (!db.getSite(siteId)) {
      return res.status(404).json({ error: "unknown_site" });
    }

    const type = typeof req.query.type === "string" ? req.query.type : undefined;
    const validTypes = new Set([
      "honeypot_triggered",
      "canary_embedded",
      "rate_limit_exceeded",
      "behavioral_score",
      "attestation_failed",
      "request_fingerprint",
    ]);
    if (type && !validTypes.has(type)) {
      return res.status(400).json({ error: "invalid_type", value: type });
    }

    const limitParam = req.query.limit;
    const limit =
      typeof limitParam === "string" && /^\d+$/.test(limitParam)
        ? Math.min(Number(limitParam), 500)
        : 100;

    const rows = db.listEvents(
      siteId,
      type as Parameters<ReverseShieldDb["listEvents"]>[1],
      limit,
    );

    // Parse the JSON details back into objects for the wire response — clients don't want
    // a stringified JSON blob inside a JSON envelope.
    const events = rows.map((r) => ({ ...r, details: JSON.parse(r.details) }));
    return res.json({ events, count: events.length });
  });

  return router;
}
