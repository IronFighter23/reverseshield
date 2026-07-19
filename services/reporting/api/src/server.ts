import express, { type Express } from "express";
import cors, { type CorsOptions } from "cors";
import helmet from "helmet";
import { existsSync } from "node:fs";

import type { ApiConfig } from "./config.js";
import type { ReverseShieldDb } from "./db/index.js";
import { eventsRouter, siteEventsRouter } from "./routes/events.js";
import { sitesRouter } from "./routes/sites.js";
import { recommendationsRouter } from "./routes/recommendations.js";
import { rulesHandler } from "./routes/rules.js";
import { scoreHandler } from "./routes/score.js";

/**
 * Build the Express app. Exposed as a factory so tests can construct instances against
 * an in-memory DB without starting a listener.
 *
 * CORS policy (SPEC guardrail for this phase):
 *   * POST /api/v1/events           — Origin: *  (browser agents install on any domain)
 *   * GET  /agent.js                — Origin: *  (script must load cross-origin)
 *   * everything else               — Origin: <dashboard origin>, credentials allowed
 *
 * The events endpoint's response body is trivial (`{ok:true}`) — nothing sensitive leaks
 * even under Origin:*. Every read endpoint that could leak attack data is locked down.
 */
export function createApp(db: ReverseShieldDb, config: ApiConfig): Express {
  const app = express();

  // Behind a proxy in production. This makes req.ip return the X-Forwarded-For head IP,
  // which is what we hash for ip_hash.
  app.set("trust proxy", true);

  // Security headers on every response. helmet defaults are fine for an API.
  // We explicitly disable CSP because we're an API, not an HTML surface — CSP on JSON
  // responses is meaningless and creates noise.
  app.use(helmet({ contentSecurityPolicy: false }));

  app.use(express.json({ limit: "64kb" }));

  // Per-route CORS configuration ---------------------------------------------------------
  const openOrigin: CorsOptions = {
    origin: "*",
    methods: ["POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
    credentials: false,
    maxAge: 86400,
  };

  const openReadOrigin: CorsOptions = {
    // For the agent.js asset — must be reachable from any origin.
    origin: "*",
    methods: ["GET", "HEAD", "OPTIONS"],
    credentials: false,
    maxAge: 86400,
  };

  const dashboardOnly: CorsOptions = {
    origin: config.dashboardOrigin,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
    credentials: true,
    maxAge: 86400,
  };
  // --------------------------------------------------------------------------------------

  // Health check — trivially open (no data leak, useful for load balancers).
  app.get("/healthz", (_req, res) => {
    res.json({ ok: true, service: "reverseshield-reporting-api" });
  });

  // GET /agent.js — serve the browser agent bundle. ESM, permissive CORS.
  app.get("/agent.js", cors(openReadOrigin), (_req, res) => {
    const path = config.agentBundlePath;
    if (!existsSync(path)) {
      return res.status(503).json({
        error: "agent_bundle_missing",
        message:
          "Build packages/agent-js first: npm run --workspace @reverseshield/agent build",
        expected_path: path,
      });
    }
    res.type("application/javascript");
    // Cache for a modest window in dev; production deployments should serve this from a
    // CDN with a versioned URL and long-cache headers instead.
    res.set("Cache-Control", "public, max-age=300");
    res.sendFile(path);
  });

  // GET /agent/reverseshield_core_bg.wasm — serve the WASM binary. Same CORS + cache
  // policy as /agent.js. In production this endpoint is typically fronted by a CDN
  // (see .env.example: RS_WASM_BUNDLE_PATH), but the fallback keeps the "one URL, zero
  // config" install story working for self-hosters.
  app.get("/agent/reverseshield_core_bg.wasm", cors(openReadOrigin), (_req, res) => {
    const path = config.wasmBundlePath;
    if (!existsSync(path)) {
      return res.status(503).json({
        error: "wasm_bundle_missing",
        message:
          "Build the WASM first: bash packages/core/build-wasm.sh",
        expected_path: path,
      });
    }
    res.type("application/wasm");
    res.set("Cache-Control", "public, max-age=300");
    res.sendFile(path);
  });

  // Events ingestion — must accept from any origin (browser agents live everywhere).
  const eventsPath = "/api/v1/events";
  app.options(eventsPath, cors(openOrigin));
  app.use(eventsPath, cors(openOrigin), eventsRouter(db, config));

  // Score computation — called by server-side PHP middlewares, and available as a
  // browser-agent fallback if local WASM fails to load. Permissive CORS matches
  // events for the same reason: the caller can be anywhere.
  const scorePath = "/api/v1/score";
  app.options(scorePath, cors(openOrigin));
  app.post(scorePath, cors(openOrigin), scoreHandler(db, config));

  // Rules distribution — same asymmetry as events. Browser agents on arbitrary origins
  // fetch this once per page load. Registered BEFORE the blanket `/api/v1` middleware
  // below so its permissive CORS wins the match. Only exposes the current rule set,
  // so no leak surface even under Origin:*.
  const rulesPath = "/api/v1/sites/:site_id/rules.json";
  app.options(rulesPath, cors(openReadOrigin));
  app.get(rulesPath, cors(openReadOrigin), rulesHandler(db, config));

  // Everything else on /api/v1 — locked to the dashboard origin.
  app.use("/api/v1", cors(dashboardOnly));
  app.options("/api/v1/*", cors(dashboardOnly));

  app.use("/api/v1/sites", sitesRouter(db, config));
  app.use("/api/v1/sites/:site_id/events", siteEventsRouter(db));
  app.use("/api/v1/sites/:site_id/recommendations", recommendationsRouter(db));

  // 404 fallback for unknown API routes.
  app.use("/api", (_req, res) => {
    res.status(404).json({ error: "not_found" });
  });

  // Global error handler. Keeps error responses uniform and avoids leaking stack traces.
  // Signature must be (err, req, res, next) — Express dispatches by arity.
  app.use(
    (
      err: Error,
      _req: express.Request,
      res: express.Response,
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      _next: express.NextFunction,
    ) => {
      // eslint-disable-next-line no-console
      console.error("[api] unhandled error:", err.message);
      res.status(500).json({ error: "internal_error" });
    },
  );

  return app;
}
