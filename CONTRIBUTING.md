# Contributing to ReverseShield

Thanks for wanting to help. This document covers the dev environment, running
tests, and PR conventions.

## Prerequisites

- Node.js 20 or newer
- PHP 8.1 or newer (for both middleware packages)
- Composer 2.x
- Rust stable (only for Phase 2+ work on the core engine)
- Git

If you're on Windows and don't have PHP available at the command line, see
[docs/getting-started.md](docs/getting-started.md#windows-php-setup) for a
standalone PHP install that avoids Local by Flywheel's bundled build.

## First-time setup

```bash
git clone https://github.com/IronFighter23/reverseshield.git
cd reverseshield
npm install
```

The npm install resolves all three JS workspaces (browser agent, reporting
API, dashboard). `better-sqlite3` will download a Windows/macOS/Linux prebuilt
binary — no C compiler needed on your machine.

## Running the full test suite

```bash
# JavaScript + TypeScript (browser agent + reporting API)
npm run test --workspaces --if-present

# WordPress plugin — pure PHP CLI, no WP install required
php packages/middleware-wordpress/test/plugin-test.php

# Laravel package
cd packages/middleware-laravel
composer install
vendor/bin/phpunit
```

Full suite runs in ~3 minutes locally and ~2 minutes in CI. All three CI jobs
(JS, Rust, PHP) must be green before a PR can merge.

## Development loops

Each package supports a watch-mode dev server:

```bash
# Reporting API — hot reload via tsx
npm run --workspace @reverseshield/reporting-api dev

# Dashboard — Vite HMR
npm run --workspace @reverseshield/reporting-dashboard dev

# Browser agent — vitest watch
npm run --workspace @reverseshield/agent test:watch

# Laravel package — phpunit watch (manual re-run)
cd packages/middleware-laravel && vendor/bin/phpunit
```

## Repository layout

```
packages/
├── agent-js/                 Browser SDK
├── core/                     Rust engine (Phase 2 territory, currently stubs)
├── middleware-wordpress/     WordPress plugin
└── middleware-laravel/       Laravel package
services/
└── reporting/
    ├── api/                  Express + SQLite reporting API
    └── dashboard/            React dashboard
rules/                        YAML rule files (Phase 2)
docs/                         Long-form documentation
.github/workflows/            CI configuration
```

## Code style per component

- **TypeScript** — strict mode, no `any` unless documented, prefer named
  exports over default. Formatting is inferred from the tsconfig; there's no
  Prettier config yet (add one in your PR if you'd like).
- **PHP** — PSR-4 autoload, PSR-12 style. WordPress plugin targets PHP 7.4
  syntax (no PHP 8+ features); Laravel package targets 8.1+ and uses readonly
  properties, constructor property promotion, and `str_contains`/etc freely.
- **Rust** — `cargo fmt` mandatory (CI checks), Clippy warnings treated as
  errors (CI runs `-D warnings`).

## Guardrails to preserve

If your change touches these areas, the tests will catch violations, but the
underlying principles are worth stating explicitly:

1. **Fail-open** — every code path that touches network I/O, transient state,
   or external configuration must be wrapped in `try/catch (Throwable)`. If it
   fails, the user's request continues to render normally. Blocking a
   correctly-detected attack is fine; a bug in our detection code must never
   surface as a 500.
2. **No hardcoded honeypot names** — SPEC §8. Derive from `site_id` via
   `sha256`. Dedicated tests verify diversity across sites and determinism
   within a site.
3. **Strict SPEC §3.1 event schema** — the reporting API's zod validator
   rejects unknown fields. If you add a new event field, update the schema
   AND the validator AND the migration AND the client integrations at once.
4. **CORS asymmetry** — the events endpoint accepts any origin (agents live
   everywhere); every read endpoint is locked to the dashboard origin. Don't
   loosen either without a concrete threat model discussion.
5. **Server-computed IP hash** — never trust a client-supplied `ip_hash`.
   Reporting API always recomputes from `req.ip`.

## PR workflow

1. Fork the repo, branch from `main`
2. Write your change
3. Write or update tests alongside your change — SPEC §8: "Write tests
   alongside each task, not as an afterthought pass at the end"
4. Run the full test suite locally
5. Open a PR against `IronFighter23/reverseshield:main`. Include:
   - What the change does and why
   - Which SPEC section it addresses (if applicable)
   - Anything a reviewer should look at especially carefully
6. Wait for CI to go green
7. Respond to review feedback

Small PRs review faster than big ones. If your change is bigger than ~500
lines diff, consider splitting it.

## Reporting security issues

Do not open a public issue for security bugs. Instead, email the maintainer
listed in the LICENSE file with the details. A CVE-worthy fix will be
coordinated privately before public disclosure.

## Questions

Open a GitHub discussion or issue on the repository. If you're unsure whether
your idea fits, open an issue *before* writing the code — a five-minute
conversation can save a five-hour PR that goes in the wrong direction.
