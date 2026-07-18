# Changelog

All notable changes to ReverseShield are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Phase 2: Rust core engine with WASM build target and PHP FFI bindings
- Phase 3: response actions (block / JS challenge / drop), recommendations
  engine, Docker Compose deployment

## [0.1.0] — 2026-07-17

First functional release. Complete Phase 1 per the original build plan.

### Added

**Browser agent** (`packages/agent-js`)
- Deterministic per-site honeypot field name derivation (FNV-1a + Mulberry32 +
  Fisher-Yates over a 16-word vocabulary)
- Canary token generation matching SPEC §3.2 format
- Behavioural telemetry: mouse moves, mouse distance, scroll events, keyboard
  timing
- `sendBeacon` transport with `fetch` fallback, both fire-and-forget
- Single-init guard, SSR-safe, silent-by-default logging
- Dual ESM/CJS bundles: 3.4 KB ESM / 3.8 KB CJS gzipped
- 61 unit tests

**Reporting API** (`services/reporting/api`)
- `POST /api/v1/events` with strict zod validation of every SPEC §3.1 field
- `POST /api/v1/sites` returns install snippet with the site's UUID
- `GET /api/v1/sites/:id/summary` aggregates event counts + score bands
- `GET /api/v1/sites/:id/events` with optional `type` filter and paging
- `GET /api/v1/sites/:id/recommendations` — v1 stub, populated in Phase 3
- `GET /agent.js` serves the browser bundle for self-contained deployment
- `GET /healthz` for load balancer health checks
- SQLite storage via `better-sqlite3`, WAL mode enabled at open, prepared
  statement pool
- Server-computed IP hash with configurable pepper — client-supplied `ip_hash`
  always ignored (defence against forged attributions)
- Asymmetric CORS: `Origin: *` on events ingestion, dashboard-origin-only on
  reads
- Graceful shutdown on SIGTERM/SIGINT flushes WAL journal
- 30 integration tests via vitest + supertest

**Dashboard** (`services/reporting/dashboard`)
- React 18 + Vite 7 + Tailwind 4
- Site registration form with install snippet display
- Site picker
- Events-by-type panel scoped to last 24 hours
- Score bands panel with color coding (emerald/amber/rose) per SPEC §3.4
- Recent events table
- Vite dev proxy sidesteps CORS during development

**WordPress plugin** (`packages/middleware-wordpress`)
- `wp_head` snippet injection at priority 5
- 5 decoy REST routes under `reverseshield-decoy/v1/`
- Server-injected honeypot fields on comment and login forms
- Login rate limit: 5 failed attempts per 5 minutes per IP → WP_Error 429
- REST API rate monitoring (detect-only, not enforced)
- Config via `wp-config.php` constants — no admin UI attack surface
- PHP 7.4+ compatible
- 64 CLI smoke tests via `php test/plugin-test.php`

**Laravel package** (`packages/middleware-laravel`)
- Service provider with config publishing, decoy route registration, and
  optional auto-registration on the global HTTP kernel middleware stack
- `ReverseShieldMiddleware` with `safeCheck` / `safeExecute` fail-open
  primitives
- `EventReporter` service with 200ms `Http::timeout`, fire-and-forget POST
- `@reverseshieldHoneypot` Blade directive for one-line form protection
- Rate limiting via `Illuminate\Support\Facades\RateLimiter`
- Snippet injection via response body pattern replace, only on `text/html`
- Laravel 10 and 11 compat, PHP 8.1+
- 34 PHPUnit tests via Orchestra Testbench

**Infrastructure**
- GitHub Actions CI with 3 parallel jobs (JS, Rust, PHP), ~2 minutes total
- Repository-wide `.gitignore` covering node_modules, target, vendor, SQLite
  WAL sidecars, PHPUnit caches, .env files, and composer.phar
- `.gitattributes` normalising LF line endings across platforms

### Guardrails verified

- **No hardcoded honeypot names** — derived from `sha256(site_id)` in both
  server-side integrations, enforced by dedicated tests
- **Fail-open** — verified end-to-end by killing the reporting API during a
  live WP demo (page continued to render) and by 7 dedicated Laravel PHPUnit
  tests covering ConnectionException, HTTP 500, malformed response, internal
  reporter throw, and non-blocking dispatch
- **Score band math** — SPEC §3.4 formula (`100 - Σ score_delta` per session,
  clamped to `[0, 100]`, bucketed at 70/40) verified by DB-level tests and
  live dashboard demo
- **CORS lockdown** — read endpoints reject non-dashboard origins; events
  endpoint accepts any origin (agents install everywhere)

### Migration notes

None (initial release).

[Unreleased]: https://github.com/IronFighter23/reverseshield/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/IronFighter23/reverseshield/releases/tag/v0.1.0
