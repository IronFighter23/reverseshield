import { Router, type Request, type Response } from "express";
import { randomUUID } from "node:crypto";
import type { ReverseShieldDb } from "../db/index.js";
import type { ApiConfig } from "../config.js";
import { registerSiteSchema } from "../validators.js";

/**
 * Build the install snippet returned by POST /sites.
 *
 * v1 approach: ESM import from the API's own /agent.js endpoint. This is the shortest
 * path from "site registered" to "events flowing" — no CDN, no bundler config on the
 * user's side. Production installs typically swap the src for their own CDN.
 */
function buildInstallSnippet(siteId: string, endpoint: string): string {
  return [
    `<!-- ReverseShield install snippet -->`,
    `<script type="module">`,
    `  import { init } from "${endpoint}/agent.js";`,
    `  init({ siteId: "${siteId}", endpoint: "${endpoint}" });`,
    `</script>`,
  ].join("\n");
}

export function sitesRouter(db: ReverseShieldDb, config: ApiConfig) {
  const router = Router();

  // POST /api/v1/sites — register a new site.
  router.post("/", (req: Request, res: Response) => {
    const parsed = registerSiteSchema.safeParse(req.body);
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      return res.status(400).json({
        error: "invalid_site",
        message: issue.message,
        path: issue.path.join("."),
      });
    }

    const site_id = randomUUID();
    try {
      db.insertSite(site_id, parsed.data.name);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      // eslint-disable-next-line no-console
      console.error("[sites] insert failed:", message);
      return res.status(500).json({ error: "insert_failed" });
    }

    return res.status(201).json({
      site_id,
      name: parsed.data.name,
      install_snippet: buildInstallSnippet(site_id, config.publicUrl),
    });
  });

  // GET /api/v1/sites — list sites. Convenience for the dashboard site picker.
  // Not explicitly in SPEC §3.5 but implied by the "per-site filter" dashboard feature.
  router.get("/", (_req: Request, res: Response) => {
    const sites = db.listSites();
    return res.json({ sites });
  });

  // GET /api/v1/sites/:site_id/summary?range=24h — aggregated counts and score bands.
  router.get("/:site_id/summary", (req: Request, res: Response) => {
    const siteId = req.params.site_id;
    if (!db.getSite(siteId)) {
      return res.status(404).json({ error: "unknown_site" });
    }

    const range = typeof req.query.range === "string" ? req.query.range : "24h";
    const rangeMs = parseRange(range);
    if (rangeMs === null) {
      return res.status(400).json({
        error: "invalid_range",
        message: "range must match /^\\d+[hdw]$/ (e.g. 24h, 7d, 4w)",
      });
    }
    const sinceIso = new Date(Date.now() - rangeMs).toISOString();

    const summary = db.summary(siteId, sinceIso);
    return res.json({ site_id: siteId, range, since: sinceIso, ...summary });
  });

  return router;
}

/** Parse "24h" / "7d" / "4w" into ms. Returns null on malformed input. */
export function parseRange(range: string): number | null {
  const match = /^(\d+)([hdw])$/.exec(range);
  if (!match) return null;
  const n = Number(match[1]);
  const unit = match[2];
  if (n <= 0 || n > 1000) return null;
  const multipliers = { h: 3_600_000, d: 86_400_000, w: 604_800_000 };
  return n * multipliers[unit as "h" | "d" | "w"];
}
