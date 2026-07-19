/**
 * API configuration, resolved from environment variables with safe local-dev defaults.
 *
 * Every field is required internally; missing env values fall back to the defaults below.
 * That means the API boots on a fresh clone with zero env setup — same design intent as
 * SPEC §4.D "SQLite storage (zero-config self-host)".
 */

import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

export interface ApiConfig {
  /** Port the HTTP server binds to. Default: 3001. */
  port: number;
  /** Absolute path to the SQLite database file. Default: <api>/data/reporting.sqlite. */
  databasePath: string;
  /**
   * Origin allowed to read from the API (dashboard, admin tools).
   * The events ingestion endpoint always allows `*` regardless of this setting — browser
   * agents install on arbitrary domains that we can't enumerate up front.
   */
  dashboardOrigin: string;
  /**
   * Public URL of this API instance. Used to fill the `install_snippet` returned by
   * POST /api/v1/sites. Default: http://localhost:${port}.
   */
  publicUrl: string;
  /**
   * Optional pepper mixed into the IP hash. Set this in production so that hashes from
   * different installs can't be trivially correlated. Empty by default — dev only.
   */
  ipHashPepper: string;
  /**
   * Absolute path to the built browser agent bundle (dist/index.js from packages/agent-js).
   * Used to serve GET /agent.js. Default resolves via the monorepo layout.
   */
  agentBundlePath: string;
  /**
   * Absolute path to the compiled WASM binary produced by `bash packages/core/build-wasm.sh`.
   * Used to serve GET /agent/reverseshield_core_bg.wasm. Default resolves via the monorepo
   * layout. In production this is typically overridden to a CDN — see .env.example.
   */
  wasmBundlePath: string;
  /**
   * Absolute path to the rules file — `rules/core-rules.yaml` — the single source of
   * truth consumed by the Rust engine, the reporting API, and (via the API) the browser
   * agents. The API reads it fresh on every rules request to preserve hot-reload
   * semantics; no in-memory cache means editing the file takes effect immediately.
   */
  rulesFilePath: string;
  /** Node env — 'test' disables noisy startup logging in vitest runs. */
  nodeEnv: "development" | "production" | "test";
}

/**
 * Compute the default path to the agent bundle, relative to this source file.
 * Walks up from `services/reporting/api/src/config.ts` to the repo root, then down
 * into `packages/agent-js/dist/index.js`.
 */
function defaultAgentBundlePath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  // src → api → reporting → services → <repo root>
  return resolve(here, "../../../..", "packages/agent-js/dist/index.js");
}

function defaultWasmBundlePath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return resolve(here, "../../../..", "packages/core/pkg/reverseshield_core_bg.wasm");
}

function defaultRulesFilePath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return resolve(here, "../../../..", "rules/core-rules.yaml");
}

function defaultDatabasePath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  // src → api
  return resolve(here, "..", "data/reporting.sqlite");
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): ApiConfig {
  const port = env.RS_PORT ? Number(env.RS_PORT) : 3001;
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`RS_PORT must be a valid port number, got: ${env.RS_PORT}`);
  }

  const nodeEnv =
    env.NODE_ENV === "production" || env.NODE_ENV === "test"
      ? env.NODE_ENV
      : "development";

  return {
    port,
    databasePath: env.RS_DATABASE_PATH ?? defaultDatabasePath(),
    dashboardOrigin: env.RS_CORS_DASHBOARD_ORIGIN ?? "http://localhost:5173",
    publicUrl: env.RS_PUBLIC_URL ?? `http://localhost:${port}`,
    ipHashPepper: env.RS_IP_HASH_PEPPER ?? "",
    agentBundlePath: env.RS_AGENT_BUNDLE_PATH ?? defaultAgentBundlePath(),
    wasmBundlePath: env.RS_WASM_BUNDLE_PATH ?? defaultWasmBundlePath(),
    rulesFilePath: env.RS_RULES_FILE_PATH ?? defaultRulesFilePath(),
    nodeEnv,
  };
}
