# Production deployment

Running ReverseShield in production. This document covers the reporting API
and dashboard — the browser agent and middleware packages install into your
existing sites and inherit their environments.

## Deployment models

Three shapes make sense depending on your infrastructure:

**(a) Single VM.** Simplest. Reporting API + dashboard + reverse proxy on
one small VPS. Fine up to millions of events per month. This is what most
self-hosted users should pick.

**(b) Container platform.** Docker Compose or Kubernetes. Slightly more
operational overhead but easier to bin-pack with other services.

**(c) Serverless.** Not currently supported. The reporting API relies on
persistent SQLite state; adapting it to serverless would need a Postgres
migration (planned for v2 per the original SPEC).

## Configuration

Every setting is an environment variable. The API reads its config at boot
from `process.env` and has safe defaults for everything, so the minimum
config is empty and the recommended config is short.

### Reporting API

| Variable | Default | Purpose |
|---|---|---|
| `RS_PORT` | `3001` | HTTP listener port |
| `RS_DATABASE_PATH` | `<repo>/services/reporting/api/data/reporting.sqlite` | SQLite file location. Set to `/var/lib/reverseshield/reporting.sqlite` in prod |
| `RS_PUBLIC_URL` | `http://localhost:${port}` | Used to build the install snippet returned by POST /sites |
| `RS_CORS_DASHBOARD_ORIGIN` | `http://localhost:5173` | Origin allowed to read events |
| `RS_IP_HASH_PEPPER` | `` (empty) | Mixed into ip_hash. **Set to a random string in production** |
| `RS_AGENT_BUNDLE_PATH` | resolved relative to repo | Path to `dist/index.js` from the agent build |
| `NODE_ENV` | `development` | Set to `production` to disable startup logging |

**Minimum production `.env`:**

```
NODE_ENV=production
RS_PORT=3001
RS_DATABASE_PATH=/var/lib/reverseshield/reporting.sqlite
RS_PUBLIC_URL=https://reverseshield.example.com
RS_CORS_DASHBOARD_ORIGIN=https://reverseshield.example.com
RS_IP_HASH_PEPPER=<paste-a-32-char-random-string>
```

Generate a pepper with:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Dashboard

The dashboard is a Vite-built static bundle. In production, `npm run build`
in `services/reporting/dashboard/` emits `dist/` — serve those files behind
your reverse proxy at the same origin as your reporting API. That way no
CORS is involved.

There's no runtime dashboard config; the dashboard fetches from `/api/v1/*`
relative URLs. Whichever host serves the dashboard also proxies `/api/*` to
the reporting API.

## Reverse proxy config

The reporting API is a Node HTTP server. Do not expose it to the public
internet directly — front it with nginx or caddy for TLS termination, rate
limiting at the edge, and auth on the read endpoints.

### nginx

```nginx
# /etc/nginx/sites-available/reverseshield.example.com

# Dashboard + API on the same origin (recommended)
server {
    listen 443 ssl http2;
    server_name reverseshield.example.com;

    # TLS
    ssl_certificate     /etc/letsencrypt/live/reverseshield.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/reverseshield.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # Reasonable rate limit at the edge — the events endpoint is deliberately
    # open to any origin so it needs abuse protection at this layer.
    limit_req_zone $binary_remote_addr zone=events:10m rate=30r/s;

    # Static dashboard files
    root /var/www/reverseshield-dashboard;
    index index.html;

    # API — proxy to the Node process
    location /api/ {
        limit_req zone=events burst=100 nodelay;
        proxy_pass         http://127.0.0.1:3001;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }

    # Agent bundle — proxy to Node too
    location = /agent.js {
        proxy_pass http://127.0.0.1:3001/agent.js;
        expires    5m;
    }

    # Health check — proxy without auth
    location = /healthz {
        proxy_pass    http://127.0.0.1:3001/healthz;
        access_log    off;
    }

    # Dashboard SPA fallback
    location / {
        # Optional: basic auth on the dashboard
        # auth_basic           "ReverseShield";
        # auth_basic_user_file /etc/nginx/htpasswd.reverseshield;
        try_files $uri $uri/ /index.html;
    }
}

server {
    listen      80;
    server_name reverseshield.example.com;
    return      301 https://$server_name$request_uri;
}
```

### Caddy

Considerably shorter for the same behaviour:

```caddyfile
reverseshield.example.com {
    # Static dashboard
    root * /var/www/reverseshield-dashboard
    file_server

    # API + agent + healthz proxied to the Node process
    handle /api/* {
        reverse_proxy 127.0.0.1:3001
    }
    handle /agent.js {
        reverse_proxy 127.0.0.1:3001
    }
    handle /healthz {
        reverse_proxy 127.0.0.1:3001
    }

    # Optional dashboard auth
    # basicauth /* {
    #     admin JDJhJDE0...
    # }

    encode gzip
    log
}
```

Caddy handles LetsEncrypt automatically. That's the whole config.

## Process management

Run the Node process under a supervisor so it restarts on crash and after
reboot.

### systemd

```ini
# /etc/systemd/system/reverseshield-api.service
[Unit]
Description=ReverseShield reporting API
After=network.target

[Service]
Type=simple
User=reverseshield
Group=reverseshield
WorkingDirectory=/opt/reverseshield
Environment=NODE_ENV=production
EnvironmentFile=/etc/reverseshield/env
ExecStart=/usr/bin/npm run --workspace @reverseshield/reporting-api start
Restart=on-failure
RestartSec=5s

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/reverseshield
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable reverseshield-api.service
sudo systemctl start reverseshield-api.service
sudo systemctl status reverseshield-api.service
```

For the initial deployment, build both the agent bundle and the dashboard:

```bash
cd /opt/reverseshield
npm run --workspace @reverseshield/agent build
npm run --workspace @reverseshield/reporting-dashboard build
```

Then copy `services/reporting/dashboard/dist/*` to `/var/www/reverseshield-
dashboard/`.

## HTTPS

Both middleware packages default to `sslverify=false` on their outbound
event POSTs — appropriate for local development, wrong for production.

If your reporting API is behind TLS (it should be), no config change needed
on the middleware side. The default certificate store of PHP + WordPress /
Laravel validates the reporting API's cert normally.

If you're using a self-signed cert for the reporting API and don't want to
add it to the middleware host's cert store, you can set:

```
# WP
define('REVERSESHIELD_ENDPOINT', 'https://reverseshield.internal:3001');
add_filter('http_request_args', function ($args, $url) {
    if (str_contains($url, 'reverseshield.internal')) {
        $args['sslverify'] = false;
    }
    return $args;
}, 10, 2);
```

Better to use a real cert though. LetsEncrypt is free and works fine on
internal hosts if you can put a DNS TXT record.

## Backups

SQLite makes backups trivial. The database is one file. During WAL-mode
operation you also have `.sqlite-shm` and `.sqlite-wal` sidecars.

**Simple hot backup** (runs while the API is up):

```bash
sqlite3 /var/lib/reverseshield/reporting.sqlite ".backup /var/backups/reverseshield-$(date +%Y%m%d).sqlite"
```

The `.backup` command uses SQLite's online backup API — no locking, no
downtime, safe to run against a live DB. Schedule with cron:

```
0 3 * * * sqlite3 /var/lib/reverseshield/reporting.sqlite ".backup /var/backups/reverseshield-$(date +\%Y\%m\%d).sqlite" && find /var/backups -name "reverseshield-*.sqlite" -mtime +30 -delete
```

Daily backup, keep 30 days.

**Restore:** stop the API, replace the .sqlite file, restart. Any `-wal` or
`-shm` sidecars from the previous run should be deleted first — SQLite will
recreate them.

## Logging

The reporting API logs to stdout. In production, capture with your existing
log pipeline. journald if you're using systemd:

```bash
journalctl -u reverseshield-api.service -f
```

Log level is currently unconfigurable — the API prints its "listening on..."
startup lines, unhandled errors, and nothing else. If you need more detail
during an incident, restart with `DEBUG=*` (not currently wired up but
non-invasive to add).

## Monitoring

Two health signals worth watching:

**API responsive:**

```bash
curl -sf http://localhost:3001/healthz > /dev/null && echo "up" || echo "down"
```

**Event ingestion rate:**

```bash
sqlite3 /var/lib/reverseshield/reporting.sqlite \
  "SELECT COUNT(*) FROM events WHERE received_at > datetime('now', '-1 hour')"
```

Alert if that number is zero for more than an hour on a site that normally
receives events — either the API is broken, the middleware is misconfigured,
or the browser agent isn't loading.

## Scaling

SQLite scales further than most people expect. The write ceiling in WAL mode
is ~10,000 events per second on typical hardware, ~100,000 per second on
NVMe. That's ~800 million events per day. If you're pushing past that,
you're a very large site and the Postgres migration path (planned for v2) is
the right answer.

Vertical scaling before you need to think about horizontal:

- More RAM → larger SQLite page cache (default 2 MB, override with
  `PRAGMA cache_size = -65536` for 64 MB)
- NVMe disk → dramatically higher write throughput
- More CPU cores → doesn't directly help (SQLite is single-writer), but does
  let the Node event loop keep up with concurrent readers

If you need to shard, do it by `site_id` — each site's data is independent,
so each site can live in its own reporting API instance.

## Rotating the IP hash pepper

The pepper (`RS_IP_HASH_PEPPER`) prevents cross-installation IP correlation.
If you suspect it's been leaked, rotate it:

1. Generate a new pepper
2. Update `.env` / systemd EnvironmentFile
3. Restart the API

**Existing historical events keep their old hash** — there's no way to
recompute retroactively because the IP itself was never stored. Only new
events get the new hash. This is the intended behaviour: correlation between
pre- and post-rotation events is by design broken by rotation.

## Data retention

There's no built-in retention policy in v1. Events accumulate forever. For a
GDPR-compliant deployment or just for disk hygiene:

```sql
-- Delete events older than 90 days
DELETE FROM events WHERE received_at < datetime('now', '-90 days');
VACUUM;
```

Run weekly via cron. The `VACUUM` reclaims disk space; without it SQLite
just marks rows as free and reuses the pages later.
