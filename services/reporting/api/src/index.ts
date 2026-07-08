/**
 * Bootstrap for the reporting API. Kept intentionally thin — createApp() does all the
 * real wiring so tests can construct app instances without touching the network.
 */

import { loadConfig } from "./config.js";
import { openDatabase } from "./db/index.js";
import { createApp } from "./server.js";

const config = loadConfig();
const db = openDatabase(config.databasePath);
const app = createApp(db, config);

const server = app.listen(config.port, () => {
  if (config.nodeEnv !== "test") {
    // eslint-disable-next-line no-console
    console.log(
      `[reverseshield-reporting-api] listening on http://localhost:${config.port}`,
    );
    // eslint-disable-next-line no-console
    console.log(`  database: ${config.databasePath}`);
    // eslint-disable-next-line no-console
    console.log(`  dashboard origin allowed: ${config.dashboardOrigin}`);
  }
});

// Graceful shutdown — flush the WAL journal, close listeners cleanly. Without this,
// SQLite may leave a stale -wal / -shm file that gets recovered next boot (harmless
// but noisy).
function shutdown(signal: string): void {
  // eslint-disable-next-line no-console
  console.log(`[api] received ${signal}, shutting down`);
  server.close(() => {
    try {
      db.close();
    } catch {
      // ignore
    }
    process.exit(0);
  });
  // Force-exit after 10s if something's stuck.
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
