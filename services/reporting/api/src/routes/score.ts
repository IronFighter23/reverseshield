import { type Request, type Response, type RequestHandler } from "express";

import type { ReverseShieldDb } from "../db/index.js";
import type { ApiConfig } from "../config.js";
import { scoreRequestSchema } from "../validators.js";
import { loadRules } from "./rules.js";
import { getEngine } from "../scoring/engine.js";

/**
 * POST /api/v1/score — compute the trust score for a session given a list of signals.
 *
 * Consumers: server-side middlewares (WordPress plugin, Laravel middleware) that have
 * detected local signals — honeypot fill, rate-limit exceed, etc. — and want the
 * canonical score attached to their event payload. Also usable by the browser agent
 * as a fallback when WASM fails to load locally.
 *
 * Why a POST and not a query string: the signals list is variable-length and, while
 * short in v1, will grow (fingerprint hashes, behavioral vectors). Encoding it as
 * request body future-proofs the endpoint.
 *
 * Scoring reuses the exact same WASM binary the browser fleet does — RuleSet parsed
 * from the same core-rules.yaml, ScoreResult with the same field shape. That's the
 * whole reason for POSTing to the reporting service rather than reimplementing the
 * math in PHP: single source of truth, zero drift between enforcement points.
 *
 * Failure modes:
 *   * Body validation fails             → 400 invalid_score_request
 *   * Unknown site_id                   → 404 unknown_site
 *   * Rules file missing/malformed      → 500 rules_unavailable
 *   * WASM not built / failed to load   → 503 scoring_unavailable
 *   * WASM scoring throws at runtime    → 500 scoring_failed
 *
 * On the middleware side, every one of these becomes "no score attached to the event".
 * The middleware never blocks a valid request because scoring was unavailable — that
 * fail-open contract is enforced at the caller's timeout, not this endpoint.
 */
export function scoreHandler(
  db: ReverseShieldDb,
  config: ApiConfig,
): RequestHandler {
  return async (req: Request, res: Response) => {
    const parsed = scoreRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      res.status(400).json({
        error: "invalid_score_request",
        message: issue.message,
        path: issue.path.join("."),
      });
      return;
    }

    const { site_id: siteId, signals } = parsed.data;

    if (!db.getSite(siteId)) {
      res.status(404).json({ error: "unknown_site" });
      return;
    }

    // Load rules once per request. This mirrors GET /rules.json — same hot-reload
    // semantics, same failure surface (missing file / malformed YAML / duplicate IDs).
    let rulesJson: string;
    try {
      const rules = loadRules(config.rulesFilePath);
      rulesJson = JSON.stringify(rules);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (config.nodeEnv !== "test") {
        // eslint-disable-next-line no-console
        console.error("[score] rules load failed:", message);
      }
      res.status(500).json({ error: "rules_unavailable", message });
      return;
    }

    const engine = await getEngine(config);
    if (engine === null) {
      // Log once at info-level so operators can distinguish "not built" from real errors.
      // In test env the tests exercise this deliberately; stay quiet.
      if (config.nodeEnv !== "test") {
        // eslint-disable-next-line no-console
        console.warn(
          "[score] WASM engine unavailable — run `bash packages/core/build-wasm.sh`",
        );
      }
      res.status(503).json({
        error: "scoring_unavailable",
        message: "WASM engine not loaded on the server; run build-wasm.sh",
      });
      return;
    }

    try {
      const raw = engine.scoreSignalsJson(rulesJson, JSON.stringify(signals));
      // The Rust side returns valid JSON — but we don't blindly trust that, we parse
      // it so a corrupted response surfaces as 500 rather than the client getting
      // half a JSON blob concatenated with a garbage tail.
      const result = JSON.parse(raw);
      res.status(200).json(result);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (config.nodeEnv !== "test") {
        // eslint-disable-next-line no-console
        console.error("[score] engine.scoreSignalsJson threw:", message);
      }
      res.status(500).json({ error: "scoring_failed", message });
    }
  };
}
