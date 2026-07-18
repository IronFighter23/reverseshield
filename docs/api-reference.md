# Reporting API reference

Complete reference for every endpoint the reporting API exposes. All URLs
below assume the API is running at `http://localhost:3001` — replace with
your actual endpoint in production.

## Table of contents

- [Base URLs](#base-urls)
- [Authentication](#authentication)
- [Content types](#content-types)
- [Event payload schema](#event-payload-schema)
- [Endpoints](#endpoints)
  - [POST /api/v1/events](#post-apiv1events)
  - [POST /api/v1/sites](#post-apiv1sites)
  - [GET /api/v1/sites](#get-apiv1sites)
  - [GET /api/v1/sites/:site_id/summary](#get-apiv1sitessite_idsummary)
  - [GET /api/v1/sites/:site_id/events](#get-apiv1sitessite_idevents)
  - [GET /api/v1/sites/:site_id/recommendations](#get-apiv1sitessite_idrecommendations)
  - [GET /agent.js](#get-agentjs)
  - [GET /healthz](#get-healthz)
- [Error responses](#error-responses)
- [CORS behaviour](#cors-behaviour)

## Base URLs

Only one base URL. There are no versioned base URLs like `/v2/`; API version
is included in each path (`/api/v1/...`) so you can add v2 endpoints
alongside v1 in a future release without breaking clients.

## Authentication

v1 is unauthenticated. This is a deliberate self-host tradeoff: the reporting
API is designed to run behind your existing infrastructure (VPN, mesh
network, reverse proxy with auth). Adding a token layer would put an auth
config surface between operators and their data at the moment they most need
to see it.

Production deployments should:
- Bind the API to `127.0.0.1` only and reverse-proxy through nginx/caddy with
  auth (basic, mTLS, or SSO) on the read endpoints
- Leave `POST /api/v1/events` accessible from any origin (agents install
  everywhere)
- Firewall reads to the dashboard host

See [deployment.md](deployment.md) for concrete configuration examples.

## Content types

- Requests: `Content-Type: application/json`
- Responses: `Content-Type: application/json` for API routes, `application/javascript`
  for `/agent.js`
- Encoding: UTF-8 for all text

## Event payload schema

Every event POSTed to `/api/v1/events` must match this shape exactly. Any
unknown field or wrong type is rejected with 400.

```json
{
  "event_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  "site_id": "5c4c0a5d-091d-4e5b-9f23-f1dada9d5ffd",
  "timestamp": "2026-07-17T20:00:00Z",
  "source": "browser",
  "session_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  "type": "honeypot_triggered",
  "score_delta": -80,
  "details": { "field": "email_alt" },
  "ip_hash": null,
  "user_agent": "Mozilla/5.0 ...",
  "asn": null
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `event_id` | UUID v4 | yes | Idempotency key. Duplicate event_id → 409 |
| `site_id` | UUID v4 | yes | Must reference an existing site (404 if unknown) |
| `timestamp` | ISO-8601 UTC | yes | Client's clock; server also records `received_at` |
| `source` | `"browser" \| "server"` | yes | Enum, no other values accepted |
| `session_id` | UUID v4 | yes | Cross-event correlation within a session |
| `type` | event type enum | yes | See below |
| `score_delta` | integer | yes | Signed integer, typically negative |
| `details` | object | yes | Type-specific fields; empty object OK |
| `ip_hash` | string \| null | yes | Server ignores this and recomputes. Send null |
| `user_agent` | string | yes | Can be empty string |
| `asn` | string \| null | yes | Optional AS number annotation |

**Event types:**

| Value | Fired by | Typical `score_delta` |
|---|---|---|
| `honeypot_triggered` | Browser agent, WP plugin, Laravel middleware | -80 |
| `canary_embedded` | Browser agent on init | 0 |
| `rate_limit_exceeded` | WP plugin, Laravel middleware | -40 to -60 |
| `behavioural_score` | Browser agent periodic snapshot | 0 |
| `attestation_failed` | Browser agent (Phase 2) | -50 |
| `request_fingerprint` | Server middleware (Phase 2) | 0 |

## Endpoints

### `POST /api/v1/events`

Fire a single event. Called by the browser agent (via `sendBeacon`) and by
the WordPress plugin / Laravel middleware (via `wp_remote_post` /
`Http::post`).

**Request body:** the event schema above.

**Response — success:**

```
HTTP/1.1 202 Accepted
Content-Type: application/json

{"ok":true}
```

**Response — validation failed:**

```
HTTP/1.1 400 Bad Request
Content-Type: application/json

{"error":"invalid_event","message":"Invalid uuid","path":"event_id"}
```

The `path` field identifies which specific field failed. Only the first
failure is returned.

**Response — unknown site:**

```
HTTP/1.1 404 Not Found
Content-Type: application/json

{"error":"unknown_site","site_id":"5c4c0a5d-091d-4e5b-9f23-f1dada9d5ffd"}
```

**Response — duplicate event_id:**

```
HTTP/1.1 409 Conflict
Content-Type: application/json

{"error":"duplicate_event"}
```

The 409 makes idempotent retry safe: clients retrying a beacon that already
landed get the same result as sending a fresh unique event.

**curl example:**

```bash
curl -X POST http://localhost:3001/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "event_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "site_id":"5c4c0a5d-091d-4e5b-9f23-f1dada9d5ffd",
    "timestamp":"2026-07-17T20:00:00Z",
    "source":"browser","session_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    "type":"honeypot_triggered","score_delta":-80,
    "details":{"field":"email_alt"},
    "ip_hash":null,"user_agent":"curl","asn":null
  }'
```

### `POST /api/v1/sites`

Register a new site. Returns the site's UUID and an install snippet you can
paste directly into your site's `<head>`.

**Request body:**

```json
{ "name": "example.com" }
```

The `name` field is 1-200 characters, otherwise 400.

**Response:**

```
HTTP/1.1 201 Created
Content-Type: application/json

{
  "site_id": "5c4c0a5d-091d-4e5b-9f23-f1dada9d5ffd",
  "name": "example.com",
  "install_snippet": "<!-- ReverseShield install snippet -->\n<script type=\"module\">\n  import { init } from \"http://localhost:3001/agent.js\";\n  init({ siteId: \"5c4c0a5d-091d-4e5b-9f23-f1dada9d5ffd\", endpoint: \"http://localhost:3001\" });\n</script>"
}
```

The endpoint URL inside `install_snippet` is taken from the reporting API's
`RS_PUBLIC_URL` env var (or defaults to `http://localhost:${port}` in dev).

### `GET /api/v1/sites`

List all registered sites, most recent first.

**Response:**

```json
{
  "sites": [
    {
      "site_id": "5c4c0a5d-091d-4e5b-9f23-f1dada9d5ffd",
      "name": "example.com",
      "created_at": "2026-07-08T15:24:01.537Z"
    }
  ]
}
```

### `GET /api/v1/sites/:site_id/summary`

Aggregated view over a time window. This is what the dashboard's "Events by
type" and "Score bands" panels are backed by.

**Query parameters:**

- `range` — time window. Format: `\d+[hdw]` (e.g. `24h`, `7d`, `4w`). Defaults
  to `24h`. Returns 400 on malformed input.

**Response:**

```json
{
  "site_id": "5c4c0a5d-091d-4e5b-9f23-f1dada9d5ffd",
  "range": "24h",
  "since": "2026-07-16T20:00:00.000Z",
  "total_events": 9,
  "by_type": {
    "honeypot_triggered": 1,
    "canary_embedded": 3,
    "rate_limit_exceeded": 0,
    "behavioural_score": 5,
    "attestation_failed": 0,
    "request_fingerprint": 0
  },
  "score_bands": {
    "likely_human": 5,
    "suspicious": 0,
    "likely_bot": 1
  }
}
```

Score bands are computed via SQL aggregation using the SPEC §3.4 formula:

```
session_score = clamp(100 + Σ score_delta_per_session, 0, 100)
band = likely_human if session_score >= 70
       suspicious   if session_score >= 40
       likely_bot   otherwise
```

**404** if the site doesn't exist.

### `GET /api/v1/sites/:site_id/events`

Raw event stream, most recent first.

**Query parameters:**

- `type` — filter by event type. Must be one of the enum values. Returns 400
  on any other value.
- `limit` — how many events to return. Default 100, max 500.

**Response:**

```json
{
  "events": [
    {
      "event_id": "...",
      "site_id": "...",
      "timestamp": "2026-07-17T20:00:00.000Z",
      "source": "browser",
      "session_id": "...",
      "type": "honeypot_triggered",
      "score_delta": -80,
      "details": { "field": "email_alt" },
      "ip_hash": "eff8e7ca506627fe",
      "user_agent": "Mozilla/5.0 ...",
      "asn": null,
      "received_at": "2026-07-17T20:00:00.234Z"
    }
  ],
  "count": 1
}
```

Note: `ip_hash` in the response is the *server-computed* value, not whatever
the client sent. It's a truncated SHA-256, 16 hex chars.

**404** if the site doesn't exist.

### `GET /api/v1/sites/:site_id/recommendations`

Configuration health checks against your site. **v1 stub — returns empty
array.** Populated in Phase 3 with static checks for missing rate limits,
permissive `robots.txt`, missing security headers.

**Response:**

```json
{
  "site_id": "5c4c0a5d-091d-4e5b-9f23-f1dada9d5ffd",
  "recommendations": [],
  "note": "Recommendations engine ships in v2 (see SPEC §4.D). This endpoint is stubbed for v1."
}
```

### `GET /agent.js`

Serves the browser agent bundle so consumers don't need their own CDN.
Returns the ESM build from `packages/agent-js/dist/index.js`. Cached 300
seconds.

**Response headers:**

```
HTTP/1.1 200 OK
Content-Type: application/javascript
Cache-Control: public, max-age=300
Access-Control-Allow-Origin: *
```

**Response — bundle not built:**

```
HTTP/1.1 503 Service Unavailable
Content-Type: application/json

{
  "error": "agent_bundle_missing",
  "message": "Build packages/agent-js first: npm run --workspace @reverseshield/agent build",
  "expected_path": "/.../packages/agent-js/dist/index.js"
}
```

If you see the 503, run `npm run --workspace @reverseshield/agent build` in
the repo root.

### `GET /healthz`

Trivial health check for load balancers. Unauthenticated, no CORS
restrictions.

**Response:**

```json
{"ok":true,"service":"reverseshield-reporting-api"}
```

## Error responses

All error responses have this shape:

```json
{ "error": "error_code", ...extra fields }
```

Error codes used across all endpoints:

| Code | HTTP | Meaning |
|---|---|---|
| `invalid_event` | 400 | Event payload failed schema validation |
| `invalid_site` | 400 | Site registration payload failed validation |
| `invalid_range` | 400 | Summary `range` param didn't match `\d+[hdw]` |
| `invalid_type` | 400 | Events `type` filter had an unknown value |
| `unknown_site` | 404 | site_id doesn't exist |
| `not_found` | 404 | Route doesn't exist |
| `duplicate_event` | 409 | event_id already ingested |
| `insert_failed` | 500 | Database write failed for reasons other than the above |
| `internal_error` | 500 | Uncaught exception in a route handler |

Server-side errors are logged to stderr with the underlying error message
before the sanitised 500 is returned to the client. Never rely on parsing
500 response bodies for diagnostics — check the API's logs.

## CORS behaviour

Split by endpoint, deliberately asymmetric:

| Endpoint | Allowed origin | Credentials |
|---|---|---|
| `POST /api/v1/events` | `*` | no |
| `OPTIONS /api/v1/events` (preflight) | `*` | no |
| `GET /agent.js` | `*` | no |
| Everything else on `/api/v1/*` | `RS_CORS_DASHBOARD_ORIGIN` | yes |

The events endpoint has to accept any origin — browser agents install on
customer sites we can't enumerate. The response body is trivial
(`{"ok":true}`), so nothing sensitive leaks.

Read endpoints are locked to the dashboard origin because they contain
attack data — session IDs, IP hashes, honeypot field names, event
timestamps. That data must not be accessible cross-origin.

The events endpoint also responds to Chrome/Edge's Private Network Access
preflight (`Access-Control-Request-Private-Network: true`) with
`Access-Control-Allow-Private-Network: true`, so browser agents on public
domains can reach reporting APIs on private addresses (like `localhost:3001`
during development, or `10.0.0.5:3001` on a corporate network).
