# Architecture

ReverseShield is deliberately split into small, replaceable pieces. This
document explains what each piece does, why it exists, and how they talk to
each other.

## The pieces

```
┌─────────────────────────────────────────────────────────────────┐
│  Your site                                                      │
│                                                                 │
│  Browser agent  ────────┐         Server middleware   ─────┐    │
│  (JS SDK loaded         │         (WP plugin or            │    │
│  in every page)         │         Laravel middleware)      │    │
└──────────────────────── │─────────────────────────────────  │───┘
                          │                                   │
             sendBeacon   │        Http::post                 │
             POST         │        POST                       │
                          ▼                                   ▼
                    ┌──────────────────────────────────────────────┐
                    │  Reporting API                                │
                    │  Express + SQLite + zod                       │
                    └───────────────────┬───────────────────────────┘
                                        │
                                        │  SQL (WAL mode)
                                        │
                    ┌───────────────────┴──────────────────────────┐
                    │  Dashboard                                    │
                    │  React + Vite + Tailwind                      │
                    └───────────────────────────────────────────────┘
```

Every arrow above is one-directional. The browser agent and server-side
middleware only push events. The dashboard only reads. Nothing loops back
from the reporting API to your site — this is a key design property. Even if
the reporting API is compromised, it cannot do anything to a protected site
except stop receiving events.

## Component responsibilities

### Browser agent (`packages/agent-js`)

Runs in the visitor's browser. Loaded via `<script type="module">` from either
your own CDN or the reporting API's `/agent.js` endpoint.

**What it does:**
- Generates a per-visit session ID stored in a cookie
- Watches for form interactions on inputs marked as honeypots
- Collects behavioural signals: mouse move count, mouse move distance, scroll
  event count, keyboard timing distribution
- Batches events every ~5 seconds or on `pagehide`
- Fires each batch as a `sendBeacon` (with `fetch(keepalive:true)` fallback)
  to the reporting API

**What it explicitly doesn't do:**
- Fingerprint the browser (no `navigator.plugins` enumeration, no canvas
  fingerprinting, no font enumeration)
- Track across sites (session ID is per-installation, tied to your site_id)
- Block anything on the client — detection happens on the server side. The
  agent is purely a sensor.

**Why it's separate from the middleware:** browser signals catch different
attackers than server signals. Headless Chrome will submit forms but leave a
zero-mouse-movement telemetry trail. Server-side rate limits catch API abuse
that never renders a page.

### Reporting API (`services/reporting/api`)

The one component that stores state. Express + SQLite, running as a single
Node.js process.

**What it does:**
- Accepts events from the browser agent and both middleware packages
- Validates every event against a strict zod schema (SPEC §3.1)
- Rejects unknown fields, malformed UUIDs, out-of-range timestamps, bad enums
- Computes the IP hash server-side from the request's IP (never trusts a
  client-supplied `ip_hash`)
- Stores events in SQLite with `journal_mode=WAL`, `synchronous=NORMAL`,
  `foreign_keys=ON`
- Aggregates for the dashboard: event counts by type, score bands per session
- Serves the browser agent bundle at `/agent.js` so consumers don't need their
  own CDN

**Why SQLite:** zero-config self-hosting. The whole store is one file. Backup
is `cp reporting.sqlite backup/`. No separate database server to run, secure,
or update.

**Why WAL mode:** during an active attack the write rate can spike. Without
WAL, readers block writers and the whole ingestion pipeline stalls at exactly
the moment you least want it to. WAL mode lets the dashboard read historical
events while new ones stream in.

### Dashboard (`services/reporting/dashboard`)

React SPA served by Vite. Reads from the reporting API's read endpoints.

**What it does:**
- Lists registered sites, lets you register new ones
- For a selected site, shows:
  - Total event count over the last 24 hours
  - Event counts broken down by type
  - Session score bands (likely_human / suspicious / likely_bot)
  - The 50 most recent events with details

**Design constraints:**
- No auth in v1 (see [security.md](security.md#authentication))
- No writes except site registration
- No cross-origin fetches to arbitrary origins (only its own reporting API)

### WordPress plugin (`packages/middleware-wordpress`)

A single PHP file installed as a standard WordPress plugin.

**What it does:**
- Injects the browser agent snippet into `<head>` on every page load
- Registers 5 decoy REST routes under `reverseshield-decoy/v1/*` that look
  like plausible bait for scanners
- Injects visually-hidden honeypot fields into comment and login forms
- Rate-limits failed login attempts per IP
- Fires `honeypot_triggered` / `rate_limit_exceeded` events server-side

### Laravel package (`packages/middleware-laravel`)

A Composer package installed via `composer require reverseshield/laravel`.
Provides the same functionality as the WordPress plugin, adapted to Laravel's
conventions.

**What it does:**
- Registers a service provider that pushes the middleware onto the global HTTP
  kernel stack
- Provides a `@reverseshieldHoneypot` Blade directive for form injection
- Handles snippet injection via response body rewriting
- Provides an `EventReporter` service any application code can use to fire
  custom events

## Request lifecycle

### A legitimate visitor loads a page

1. Browser requests `/some/page` from the site
2. WP plugin or Laravel middleware injects `<script type="module">` block into
   the response's `<head>`, right before `</head>`
3. Response returns to the browser
4. Browser parses HTML, encounters the ESM `<script>` block, fetches
   `agent.js` from the reporting API (typically via CDN)
5. Agent initialises: reads its per-site config, generates a session cookie
   if none present, installs event listeners on the page's form inputs
6. Agent fires a `canary_embedded` event to `POST /api/v1/events` — this
   proves the pipeline is alive
7. Visitor interacts with the page normally
8. On `pagehide` (visitor navigates away or closes tab), agent flushes any
   pending `behavioural_score` snapshot

Total added latency for the visitor: **the initial `agent.js` fetch**, which
is a 3.4 KB gzipped ES module. Runtime cost during the page's life is one
`sendBeacon` per event batch — non-blocking, doesn't affect page performance
metrics.

### A scraper hits a decoy route

1. Automated tool hits e.g. `GET /wp-json/reverseshield-decoy/v1/users`
2. WordPress routes the request to the plugin's `handle_decoy_hit` method
3. Handler fires a `honeypot_triggered` event with `kind: decoy_route,
   route: /users, method: GET`
4. Handler returns `{"data": []}` — a bland response that looks like an empty
   collection from a real endpoint
5. Scraper moves on, none the wiser

The event lands in the reporting API. The session ID for that scraper hits
`-80` on its score (SPEC §3.4), which after clamp/bucket lands in
`likely_bot`. Aggregation shows one more session in the bot band on the
dashboard.

### The reporting API is down during an attack

1. Bot submits a form with the honeypot field filled
2. WordPress plugin's `pre_comment_on_post` hook fires
3. Hook detects the filled honeypot, calls `send_event()`
4. `wp_remote_post()` to the (unreachable) reporting API times out at 200ms
5. `wp_remote_post()` returns a `WP_Error` — no exception
6. Even if it *had* thrown, the outer `try { ... } catch (Throwable $e) {}`
   would catch it
7. Plugin still calls `wp_die(...)` with a 403 — the block happens regardless
   of whether we could report it
8. When the reporting API comes back online, subsequent attempts get logged

This is the fail-open guarantee. Reporting is best-effort; detection and
blocking are not coupled to it.

## Design principles

### Fail-open everywhere

Every hook in every middleware is wrapped in `try/catch (Throwable)`. Every
callback in the browser agent's transport module is wrapped in
`try/catch (unknown)`. Any error path swallows the exception and continues.

The alternative — fail-closed — would let a bug in ReverseShield take down
the site it's protecting. That's unacceptable for a security tool.

The consequence: bugs in ReverseShield show up as *missing events* in the
dashboard, not as user-facing errors. Operators verify the pipeline is
working by watching the event stream. If events stop, investigate; the site
keeps rendering while you investigate.

### No hardcoded honeypot names

SPEC §8. Any honeypot field name (or decoy route name) that a scanner could
add to a static allowlist is worthless. So we derive names deterministically
from the per-site UUID:

```
honeypot_name = 'email_alt_' + sha256(site_id + '::honeypot')[:8]
```

Different every install. Stable within an install so the injector and the
checker see the same name. No coordination or shared state needed between
them.

The WordPress plugin and Laravel middleware use identical derivation, so a
site running both integrations exposes a consistent honeypot surface.

### Asymmetric CORS

The events ingestion endpoint accepts `Origin: *` — it has to, because the
browser agent runs on customer sites we can't enumerate ahead of time.

Every read endpoint (`GET /sites`, `GET /sites/:id/summary`, ...) is locked
to the configured dashboard origin only. That's what "prevent unauthorized
domains from reading API responses" means in practice: writes are open, reads
are private.

The events response body is deliberately trivial (`{"ok": true}` or a 202
with no body). Nothing sensitive leaks whether we send `*` or a specific
origin.

### Server-computed IP hash

Client-supplied `ip_hash` is always ignored. The reporting API recomputes it
from `req.ip` on every event, with a truncated SHA-256 mixed with an
installation-specific pepper.

If we trusted the client-supplied hash, an attacker could smuggle in a bogus
`ip_hash` to shift blame or evade per-IP aggregation. Recomputing server-side
closes that loop entirely.

We also never store the raw IP. The hash is 64 bits — enough entropy to
distinguish unique IPs within reasonable per-site traffic, not enough to
recover the IP from the hash.

## What comes next

**Phase 2** adds the Rust core engine. The idea: today, both the browser
agent (JavaScript) and both middleware packages (PHP) hardcode their own
scoring rules (`score_delta: -80` on a honeypot hit). In Phase 2, all three
delegate to a shared Rust engine that reads its rules from
`rules/core-rules.yaml`. Compiled to WASM for the browser, exposed via PHP
FFI for the middleware.

The DoD: editing the YAML changes scoring on every surface without recompiling
anything.

**Phase 3** adds response actions (block, JS challenge, drop, log-only), a
recommendations engine that runs static checks against your site config
(missing rate limits, permissive `robots.txt`, missing security headers), and
Docker Compose deployment.
