# Security & threat model

Honest documentation of what ReverseShield defends against, what it doesn't,
what data we collect, and what we do with it.

## Threat model

### What ReverseShield defends against (v1)

**Naive scrapers** — automated tools that request pages, follow links, and
submit forms without executing JavaScript. Caught by:
- Decoy REST routes on the server side (they don't know these are traps)
- Server-injected honeypot form fields (they fill everything)
- Login rate limits (they retry indefinitely with different credentials)

**Headless browsers doing form-fill attacks** — Puppeteer, Playwright, and
similar. Caught by:
- Client-side honeypot fields set via `display: none` + `tabindex="-1"` —
  headless browsers that auto-fill every input tab through this and fill it
- Behavioural telemetry: zero mouse movement + instant form submission is a
  strong bot signal

**Brute-force login attempts** — caught by the login rate limit on both the
WordPress plugin and Laravel middleware. Default: 5 failed attempts per 5
minutes per IP.

**Attribution-forging attempts** — an attacker who compromises a client and
tries to fire events with a spoofed `ip_hash` to shift blame. The reporting
API always recomputes the hash server-side from `req.ip`; client-supplied
values are ignored entirely.

### What ReverseShield does NOT defend against (v1)

**Sophisticated bots with real browser fingerprints, realistic mouse motion,
and coordinated distributed IPs.** These require the Rust core engine
(Phase 2) with behavioural scoring and cross-request session analysis. v1 will
catch the obvious ones and log the sophisticated ones for review; it will not
block them automatically.

**Application-level vulnerabilities in your site.** ReverseShield sees traffic
patterns; it doesn't understand your business logic. A bot that successfully
completes a purchase using stolen credit cards looks identical to a
legitimate purchase.

**Layer 3/4 DDoS.** ReverseShield sits in application layer. A SYN flood or
volumetric attack is your CDN and edge network's job.

**Attackers on your own subnet.** The IP-hash-based rate limits assume
attackers are on distinct IPs. Someone with control over a `/24` inside a
CGNAT can rotate IPs faster than we can react.

**Denial-of-service against the reporting API itself.** The events endpoint
accepts any origin by design. If someone POSTs 100 GB of fake events, the
API's SQLite store fills up. Reverse-proxy rate limits (see
[deployment.md](deployment.md#reverse-proxy-config)) mitigate this at the
edge.

**Compromised WordPress or Laravel installs.** If an attacker has RCE on the
WordPress admin, they can turn off the plugin, edit `wp-config.php`, or
delete the plugin folder. ReverseShield's `wp-config.php`-only config
prevents *some* of these ("attacker got admin credentials but not shell
access") but not all.

## Data collection

### What we collect

Per event, stored in the reporting API's SQLite:

- `event_id` — client-generated UUID v4, idempotency key
- `site_id` — which install the event came from
- `timestamp` — client's clock
- `received_at` — server's clock (helpful for detecting clock skew attacks)
- `source` — `"browser"` or `"server"`
- `session_id` — UUID v4 stored in a cookie (browser) or generated per
  request (server-side integrations without persistent sessions)
- `type` — one of six enum values
- `score_delta` — an integer, typically negative
- `details` — a JSON object with type-specific fields (e.g.,
  `{"field": "email_alt", "context": "comment_form", "post_id": 42}`)
- `ip_hash` — first 16 hex chars of SHA-256(pepper + request IP)
- `user_agent` — the value of the `User-Agent` HTTP header
- `asn` — currently always null (Phase 2 will populate from GeoIP)

### What we do NOT collect

- **The raw IP.** We compute the hash on ingestion and store only the hash.
  The raw IP appears in the reporting API's request log briefly (Node's
  default req log) but is never persisted to the events table.
- **Request bodies or query strings.** Nothing you submit in a form is
  logged, ever, with one exception: the *fact* that a honeypot field was
  filled. The value written into the honeypot IS captured in the event
  details on some code paths — see below.
- **Session cookies from your site.** The session_id ReverseShield generates
  is separate from any auth cookies your app sets.
- **Any personally identifiable information beyond what's in the User-Agent
  header** (which the user's browser sends to every site anyway).
- **Cross-site tracking data.** The session_id is per-site; there's no
  correlation across sites.

### Honeypot field values

When a bot fills a honeypot field with spam content, that content lands in
the event's `details` field for forensic value. If you're processing an
event stream and it contains a genuinely sensitive-looking value (like a
credit card number the bot pasted), that's a spam bot dumping its payload —
treat the details field like log data and consider redacting during export.

Practical impact: usually the field contains something like `viagra` or
`bit.ly/…`. Bots don't typically fill honeypots with real user data because
they don't know what real user data would look like on your site.

## IP hashing details

### The hash construction

```
ip_hash = sha256(pepper + request_ip)[0..16]
```

`pepper` is an installation-wide secret from `RS_IP_HASH_PEPPER`. `request_ip`
comes from `req.ip`, which Express resolves via the `trust proxy` setting and
the `X-Forwarded-For` header when the request goes through a reverse proxy.

Truncated to 16 hex chars (64 bits of entropy). That's:
- Enough to distinguish IPs within a single site's traffic without collisions
  for reasonable-scale sites (birthday-attack collision at ~4 billion IPs, so
  fine)
- Not enough to reverse. Given a hash and the pepper, the attacker still has
  to guess ~2^32 IP addresses (per address family), which is expensive.

Without the pepper, the hash space collapses to the IP space (~2^32 for
IPv4). A determined attacker with a hash and no pepper could brute-force it.
So: **always set the pepper in production.**

### Why we hash instead of storing raw IPs

Two reasons:

**Privacy.** Raw IPs are considered personal data under GDPR and many other
regimes. Storing hashed IPs sidesteps most retention and disclosure
obligations while preserving the analytical utility.

**Attack containment.** If the reporting API is breached and the events
table is exfiltrated, an attacker gets hashes, not addresses. Given the
pepper, hashes are unrecoverable to IPs.

### What hashing doesn't do

**It does not stop identification.** If someone hits your site from an IP
they use elsewhere, and that IP shows up in your dashboard's ip_hash column
with a consistent value across events, you can correlate those events. The
hash is stable per-IP within an installation. It just doesn't let you (or an
attacker) go the other way.

**It does not sanitise other fields.** User-Agent strings often uniquely
identify browsers. Session cookies survive across requests. If you're
subject to strict data minimisation, review the events table with your DPO.

## Authentication (or lack thereof)

The reporting API has no authentication in v1. This is intentional: for a
self-hosted tool, the API is expected to run behind your existing perimeter
(VPN, mesh, bastion, corporate VPC), and adding a token layer would put
credential management between operators and their attack data at the moment
they most need to see it.

**In production, you must:**

1. Bind the API to `127.0.0.1` (not `0.0.0.0`)
2. Reverse-proxy through nginx or caddy
3. Add basic auth, mTLS, or SSO on the dashboard route in your proxy config
4. Leave the events endpoint proxied without auth (agents install
   everywhere)
5. Consider IP-allowlisting the dashboard route to your office VPN

See [deployment.md](deployment.md#reverse-proxy-config) for examples.

**In development:**

Anyone who can reach `localhost:3001` can read your events. This is fine
because it's your local machine.

## Known limitations

### The pepper isn't rotated automatically

If you rotate the pepper, all pre-rotation ip_hashes no longer match
post-rotation events from the same IP. Cross-rotation correlation is
by-design impossible. That's the correct behaviour, but it means you should
plan pepper rotation around incidents rather than as a scheduled hygiene
task.

### The middleware trusts X-Forwarded-For without proxy validation

Both the WordPress plugin and Laravel middleware read `X-Forwarded-For` and
fall back to `REMOTE_ADDR`. Neither validates that the request actually came
through a trusted proxy. An attacker with direct access to the site (not
through your proxy) can spoof `X-Forwarded-For` to evade per-IP rate limits.

Impact: rate-limit evasion. The attacker doesn't gain any privilege — they
just aren't rate-limited on the fake IP.

Mitigation: v2 will add `REVERSESHIELD_TRUSTED_PROXIES` config with CIDR
ranges. For now, ensure your production site is only reachable through your
proxy — direct exposure of the application server allows this bypass.

### Composer's advisory ignore list

The Laravel package's `composer.json` includes a whitelist of specific
composer advisory IDs that flag historical Laravel versions we support
(10.x, 11.x). If new advisories appear against those versions and would
warrant an upgrade, composer install will silently ignore them.

Mitigation: periodically review the `config.audit.ignore` array against the
latest Laravel security advisories. Remove any IDs that have been
back-patched to the versions we support.

### v1 recommendations endpoint is a stub

`GET /api/v1/sites/:id/recommendations` returns an empty array. The actual
static-check engine (missing rate limits, permissive `robots.txt`, missing
security headers) is planned for Phase 3.

## Reporting security issues

If you find a security issue in ReverseShield:

**Do NOT** open a public issue on the repository.

**Do:** email the maintainer (in the LICENSE file) with:
- A description of the vulnerability
- Steps to reproduce
- Your assessment of impact
- Whether you've disclosed to anyone else

Please give reasonable time to respond and coordinate a fix before public
disclosure. We commit to acknowledging within 5 business days and fixing
critical issues within 30 days.

CVE-worthy fixes will be coordinated privately, then released with a public
advisory.
