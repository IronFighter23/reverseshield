import { Router, type Request, type Response } from "express";
import type { ReverseShieldDb } from "../db/index.js";

/**
 * GET /api/v1/sites/:site_id/recommendations
 *
 * SPEC §4.D explicitly places the recommendations engine in v2 — for v1 this endpoint
 * exists to prevent 404s from clients that check it, and returns an empty list along
 * with a note explaining the state.
 *
 * When v2 lands, this file grows: static checks for missing rate limits, permissive
 * robots.txt, missing security headers — each producing a Recommendation object with
 * an `id`, `severity`, `title`, and `remediation`.
 */
export function recommendationsRouter(db: ReverseShieldDb) {
  const router = Router({ mergeParams: true });

  router.get("/", (req: Request, res: Response) => {
    const siteId = req.params.site_id as string;
    if (!db.getSite(siteId)) {
      return res.status(404).json({ error: "unknown_site" });
    }
    return res.json({
      site_id: siteId,
      recommendations: [],
      // TODO(v2): populate from a static-check pipeline per SPEC §4.D.
      note: "Recommendations engine ships in v2 (see SPEC §4.D). This endpoint is stubbed for v1.",
    });
  });

  return router;
}
