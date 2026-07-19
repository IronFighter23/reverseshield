import { type Request, type Response, type RequestHandler } from "express";
import { readFileSync } from "node:fs";
import * as yaml from "js-yaml";

import type { ReverseShieldDb } from "../db/index.js";
import type { ApiConfig } from "../config.js";
import { ruleSetSchema, type ValidatedRule } from "../validators.js";

/**
 * GET /api/v1/sites/:site_id/rules.json — serve the current rule set as JSON.
 *
 * Consumed by browser agents (see packages/agent-js/src/scoring.ts) which fetch this
 * once per page load and hand the response body to the WASM engine's
 * `RuleSet::from_json_str`. Response shape is exactly what Rust's
 * `serde_json::to_string(&rules)` produces — that's the whole design promise of using
 * JSON as the wire format (SPEC §3.4 clarification made in Phase 2 step 2a).
 *
 * v1 semantics: all sites see the same global rule set. The site_id path segment is
 * still validated so an unregistered site can't leak the fact that a rules endpoint
 * exists. v2 (per SPEC §4.D) will add per-site rule overrides on top of this.
 *
 * Cache policy: the file is re-read on every request. That's deliberate — matches
 * the hot-reload semantics of the Rust engine, and the file is small enough that
 * parsing cost is nanoseconds. A caching layer is easy to add later if load ever
 * makes it worthwhile.
 *
 * Failure modes:
 *   * Unknown site_id                → 404 unknown_site
 *   * Rules file missing             → 500 rules_unavailable (config-level breakage)
 *   * YAML malformed                 → 500 rules_unavailable (operator edit broke)
 *   * Schema validation fails        → 500 rules_unavailable (with issue detail)
 *   * Duplicate rule IDs             → 500 rules_unavailable
 *
 * On the browser side, every one of these becomes a null Scorer via the silent-fail
 * wrapper — the host site keeps working, events keep shipping, and only local scoring
 * is disabled for that session.
 *
 * Returned as a plain handler (not an Express Router) because it's a single-endpoint
 * feature and mounting a Router at a full path is awkward with Express's mount-path
 * stripping. Wired in server.ts via `app.get(path, cors(...), rulesHandler(db,cfg))`.
 */
export function rulesHandler(db: ReverseShieldDb, config: ApiConfig): RequestHandler {
  return (req: Request, res: Response) => {
    const siteId = req.params.site_id;
    if (!db.getSite(siteId)) {
      res.status(404).json({ error: "unknown_site" });
      return;
    }

    let rules: ValidatedRule[];
    try {
      rules = loadRules(config.rulesFilePath);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      // Log once per failure so operators can diagnose without needing to reproduce.
      // In `test` env we stay quiet — the tests exercise these paths deliberately.
      if (config.nodeEnv !== "test") {
        // eslint-disable-next-line no-console
        console.error("[rules] failed to load rules file:", message);
      }
      res.status(500).json({ error: "rules_unavailable", message });
      return;
    }

    // Cache-Control: short-lived. The rules file can be hot-edited; we don't want
    // browsers holding onto stale copies. 60 seconds matches "responsive to edits
    // without hammering the endpoint on every page load in a busy site".
    res.set("Cache-Control", "public, max-age=60");
    res.type("application/json");
    res.json(rules);
  };
}

/**
 * Read and validate the rules file. Throws with a diagnostic message on any failure —
 * the caller converts to an HTTP response. Extracted so tests can drive it directly
 * against fixture paths without a full app instance.
 */
export function loadRules(path: string): ValidatedRule[] {
  let contents: string;
  try {
    contents = readFileSync(path, "utf8");
  } catch (err) {
    const cause = err instanceof Error ? err.message : String(err);
    throw new Error(`could not read rules file at ${path}: ${cause}`);
  }

  let parsed: unknown;
  try {
    // An empty/whitespace file yields `undefined` from js-yaml. Normalize that to an
    // empty array so operators can deploy the file before writing any rules —
    // same semantics as the Rust engine's empty-yaml handling.
    parsed = yaml.load(contents) ?? [];
  } catch (err) {
    const cause = err instanceof Error ? err.message : String(err);
    throw new Error(`rules file YAML is malformed: ${cause}`);
  }

  const validation = ruleSetSchema.safeParse(parsed);
  if (!validation.success) {
    const issue = validation.error.issues[0];
    const location = issue.path.join(".");
    throw new Error(
      `rules file failed schema validation at \`${location || "<root>"}\`: ${issue.message}`,
    );
  }

  // Duplicate-ID check mirrors the Rust engine's `RuleError::DuplicateId`. Same
  // invariant enforced in both engines: no rule can share an id with another.
  const seen = new Set<string>();
  for (const rule of validation.data) {
    if (seen.has(rule.id)) {
      throw new Error(`duplicate rule id \`${rule.id}\` in rules file`);
    }
    seen.add(rule.id);
  }

  return validation.data;
}
