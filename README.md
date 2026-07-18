# ReverseShield

[![CI](https://github.com/IronFighter23/reverseshield/actions/workflows/ci.yml/badge.svg)](https://github.com/IronFighter23/reverseshield/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-189%20passing-brightgreen.svg)](#running-the-tests)
[![PHP 8.1+](https://img.shields.io/badge/PHP-8.1%2B-777bb4.svg)](#requirements)
[![Node 20+](https://img.shields.io/badge/Node-20%2B-339933.svg)](#requirements)

**Self-hosted, open-source bot & scraper defense with real attack visibility.**

ReverseShield sits in front of your site as a browser agent, WordPress plugin, and Laravel middleware — catching bots at the edge, reporting them to a reporting API you run yourself, and surfacing what's happening in a dashboard. No SaaS. No cross-site tracking. No data leaving your infrastructure.

## What it does

- **Detects bots and scrapers** via three parallel channels: browser-side behavioural telemetry, server-side honeypot form fields, and decoy REST routes that only automated tools ever hit
- **Rate-limits brute-force attempts** on login endpoints (per-IP, configurable threshold)
- **Reports attacks in real time** to your own reporting API, which stores everything in SQLite and shows aggregated event counts, per-session score bands, and the raw event stream in a React dashboard
- **Fails open by design** — every hot path is wrapped in `try/catch (Throwable)`. If any component of ReverseShield breaks or its reporting API goes down, the request continues to render normally. A security tool should never take down the site it protects.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Your site (WordPress, Laravel, or any HTML page)               │
│                                                                 │
│  ┌──────────────────────┐    ┌──────────────────────────────┐   │
│  │  Browser agent       │    │  Server-side middleware      │   │
│  │  packages/agent-js   │    │  packages/middleware-wordpress│  │
│  │                      │    │  packages/middleware-laravel │   │
│  │  • Honeypot fields   │    │  • Snippet injection         │   │
│  │  • Canary tokens     │    │  • Decoy routes              │   │
│  │  • Behavioural       │    │  • Rate limiting             │   │
│  │    telemetry         │    │  • Honeypot detection        │   │
│  └──────────┬───────────┘    └──────────────┬───────────────┘   │
└─────────────┼──────────────────────────────┼───────────────────┘
              │                              │
              │  POST /api/v1/events         │  POST /api/v1/events
              │  (fire-and-forget beacon)    │  (fire-and-forget, 200ms cap)
              │                              │
              ▼                              ▼
        ┌────────────────────────────────────────────┐
        │  Reporting API (Express + SQLite)          │
        │  services/reporting/api                    │
        │                                            │
        │  • Strict §3.1 payload validation (zod)    │
        │  • Server-computed IP hash (never trust    │
        │    client-supplied)                        │
        │  • WAL mode for concurrent writes          │
        │  • Asymmetric CORS: * on events, locked    │
        │    down on reads                           │
        └───────────────────┬────────────────────────┘
                            │
                            │  GET /api/v1/sites/:id/summary
                            │  GET /api/v1/sites/:id/events
                            ▼
        ┌────────────────────────────────────────────┐
        │  Dashboard (React + Vite + Tailwind)       │
        │  services/reporting/dashboard              │
        │                                            │
        │  • Site picker, event counts by type       │
        │  • Score bands (likely_human / suspicious  │
        │    / likely_bot) per session               │
        │  • Recent events table                     │
        └────────────────────────────────────────────┘
```

For details see [docs/architecture.md](docs/architecture.md).

## Quick start

Full walkthrough in [docs/getting-started.md](docs/getting-started.md). The 60-second version:

```bash
# Clone + install
git clone https://github.com/IronFighter23/reverseshield.git
cd reverseshield
npm install

# Terminal 1 — reporting API on :3001
npm run --workspace @reverseshield/reporting-api dev

# Terminal 2 — dashboard on :5173
npm run --workspace @reverseshield/reporting-dashboard dev
```

Open http://localhost:5173, click **+ Register site**, copy the site UUID from the install snippet. That's what you paste into your WordPress `wp-config.php`, your Laravel `.env`, or your custom HTML page.

## What's in the box

| Component | Language | Status | Tests |
|---|---|---|---|
| Browser agent (SDK) | TypeScript | ✅ | 61 |
| Reporting API | TypeScript + SQLite | ✅ | 30 |
| Dashboard | React + Vite + Tailwind | ✅ | live-verified |
| WordPress plugin | PHP 7.4+ | ✅ | 64 |
| Laravel package | PHP 8.1+, Laravel 10/11 | ✅ | 34 |
| Rust core engine (unified scoring) | Rust + WASM | 📋 Phase 2 | — |
| Docker compose deployment | YAML | 📋 Phase 3 | — |

**189 automated tests** running on every push across 3 CI jobs (JS, Rust, PHP).

### Feature checklist

**Browser agent** (SPEC §3.2, §4.A)
- [x] Deterministic per-site honeypot field name derivation (not hardcoded)
- [x] Canary token generation matching SPEC §3.2 format
- [x] Behavioural telemetry (mouse moves, scroll, keyboard rhythm)
- [x] `sendBeacon` transport with `fetch` fallback, both fire-and-forget
- [x] Single-init guard, SSR-safe, `console.warn` only in debug mode
- [x] Dual ESM/CJS bundle (3.4 KB / 3.8 KB gzipped — 35% of the SPEC's 10 KB budget)

**Reporting API** (SPEC §3.1, §3.5)
- [x] `POST /api/v1/events` with strict zod validation of every §3.1 field
- [x] `POST /api/v1/sites` returns ready-to-paste install snippet
- [x] `GET /api/v1/sites/:id/summary` aggregates event counts + score bands
- [x] `GET /api/v1/sites/:id/events` with `type` filter
- [x] `GET /agent.js` serves the browser bundle (self-contained deployment)
- [x] SQLite with WAL mode, `synchronous=NORMAL`, `foreign_keys=ON`
- [x] Server-computed IP hash — client-supplied `ip_hash` always ignored
- [x] Duplicate `event_id` → 409, not 500

**Dashboard**
- [x] Site registration form
- [x] Site picker
- [x] Events-by-type panel (last 24h)
- [x] Score bands panel with color coding (emerald/amber/rose)
- [x] Recent events table with details column

**WordPress plugin**
- [x] Snippet injection via `wp_head` hook, priority 5
- [x] Decoy REST routes under `reverseshield-decoy/v1/*`
- [x] Server-injected honeypot fields on comment and login forms
- [x] Login rate limit via `authenticate` filter + `wp_login_failed` counter
- [x] Config via `wp-config.php` constants only (no admin UI attack surface)
- [x] PHP 7.4+ compatible, fail-open via `try/catch (Throwable)` on every hook

**Laravel package**
- [x] Auto-registers as global HTTP middleware on boot
- [x] `@reverseshieldHoneypot` Blade directive
- [x] Config publishable via `php artisan vendor:publish`
- [x] Rate limiting via `Illuminate\Support\Facades\RateLimiter`
- [x] Fire-and-forget outbound event via `Http::timeout(0.2)`
- [x] Laravel 10 and 11 compat, PHP 8.1+

**Guardrails enforced across the whole stack**
- [x] SPEC §8 no-hardcoded-honeypot-names: derived from `sha256(site_id . '::honeypot')`, verified by dedicated tests
- [x] Fail-open: proven by killing the reporting API mid-session (WP demo) and 7 dedicated Laravel PHPUnit tests covering ConnectionException/500/malformed response/internal reporter throw
- [x] SPEC §3.4 score band math (100 - Σ score_deltas per session, clamped 0-100, bucketed at 70/40)
- [x] Copyright and licensing: MIT throughout, no vendored code from other projects

## Documentation

- [docs/getting-started.md](docs/getting-started.md) — 10-minute quick start (recommended first read)
- [docs/architecture.md](docs/architecture.md) — how the pieces fit together
- [docs/api-reference.md](docs/api-reference.md) — complete reporting API reference
- [docs/deployment.md](docs/deployment.md) — production self-hosting guide
- [docs/security.md](docs/security.md) — threat model, data handling, IP hashing
- [CONTRIBUTING.md](CONTRIBUTING.md) — dev setup, test running, code style
- [CHANGELOG.md](CHANGELOG.md) — release notes

Per-package docs:
- [packages/agent-js](packages/agent-js) — browser SDK
- [packages/middleware-wordpress/README.md](packages/middleware-wordpress/README.md) — WordPress install + DoD demo
- [packages/middleware-laravel/README.md](packages/middleware-laravel/README.md) — Laravel install + usage

## Requirements

- **Node.js 20 or newer** (for the reporting API, dashboard, and browser agent build)
- **PHP 7.4 or newer** for the WordPress plugin
- **PHP 8.1 or newer** for the Laravel package
- **SQLite** (bundled via `better-sqlite3` npm package — no separate install)
- **Rust stable** if you plan to work on the core engine (Phase 2)

## Running the tests

Full suite runs in under 3 minutes locally, 2 minutes in CI.

```bash
# JS + TypeScript (91 tests across browser agent and API)
npm run test --workspaces --if-present

# WordPress plugin (64 tests, pure PHP CLI, no WP install needed)
php packages/middleware-wordpress/test/plugin-test.php

# Laravel package (34 tests)
cd packages/middleware-laravel
composer install
vendor/bin/phpunit
```

## What's next

**Phase 2** — the Rust core engine. Unifies scoring across browser and server so editing `rules/core-rules.yaml` changes behaviour on every surface without touching either agent. Compiled to WASM for the browser and exposed via PHP FFI for WordPress/Laravel.

**Phase 3** — response actions (block, JS challenge, drop), Docker-compose one-command deployment, and the recommendations engine (static config checks: missing rate limits, permissive robots.txt, missing security headers).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Short version: fork, branch, write a test, submit a PR. All three CI jobs must be green.

## License

MIT — see [LICENSE](LICENSE). Use it, fork it, ship it in your own product. Attribution appreciated but not required.
