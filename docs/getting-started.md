# Getting started

Up and running in about 10 minutes. Requires Node.js 20 or newer and PHP 8.1
or newer at the command line.

## 1. Clone and install

```bash
git clone https://github.com/IronFighter23/reverseshield.git
cd reverseshield
npm install
```

`npm install` pulls dependencies for all three JavaScript workspaces (browser
agent, reporting API, dashboard). Expect around 280 packages and no npm
audit vulnerabilities. `better-sqlite3` downloads a prebuilt Windows/macOS/
Linux binary — no C compiler needed.

## 2. Start the reporting API

In one terminal, from the repo root:

```bash
npm run --workspace @reverseshield/reporting-api dev
```

You should see:

```
[reverseshield-reporting-api] listening on http://localhost:3001
  database: .../services/reporting/api/data/reporting.sqlite
  dashboard origin allowed: http://localhost:5173
```

Sanity check from a third terminal:

```bash
curl http://localhost:3001/healthz
# {"ok":true,"service":"reverseshield-reporting-api"}
```

## 3. Start the dashboard

In a second terminal:

```bash
npm run --workspace @reverseshield/reporting-dashboard dev
```

Vite starts on port 5173. Open http://localhost:5173. Empty state:

> No sites registered yet. [Register your first site]

## 4. Register a site

Click **+ Register site**, name it `test.local`, submit. A green banner
appears with the install snippet — this is what you paste into your site:

```html
<!-- ReverseShield install snippet -->
<script type="module">
  import { init } from "http://localhost:3001/agent.js";
  init({ siteId: "<your-uuid>", endpoint: "http://localhost:3001" });
</script>
```

Copy the UUID from the `siteId:` field. That's what identifies your site
across every integration.

## 5. Send your first event

The absolute minimum test that the pipeline works, using curl:

```bash
curl -X POST http://localhost:3001/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "event_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "site_id":"<PASTE_YOUR_UUID_HERE>",
    "timestamp":"2026-07-17T20:00:00Z",
    "source":"browser",
    "session_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    "type":"honeypot_triggered",
    "score_delta":-80,
    "details":{"field":"email_alt"},
    "ip_hash":null,
    "user_agent":"curl",
    "asn":null
  }'
```

Response: `{"ok":true}`.

Hard-refresh the dashboard tab. You should see:

- Events by type: **Honeypot triggered: 1**, total: **1**
- Score bands: **Likely bot: 1** (score = 100 - 80 = 20, below the 40
  threshold per SPEC §3.4)
- Recent events table: one row with your details

You've proven the whole pipeline works. Now integrate with your real site.

## 6. Integrate with your site

Pick your platform:

### Any HTML site (browser agent)

Paste the install snippet from step 4 into your site's `<head>`. That's it.
The agent will start reporting `canary_embedded` and `behavioural_score`
events on every page load.

### WordPress

Copy the `packages/middleware-wordpress/` folder into your WP install's
`wp-content/plugins/` directory. Rename to `reverseshield`. Add two constants
to your `wp-config.php`:

```php
define('REVERSESHIELD_SITE_ID', '<your-uuid>');
define('REVERSESHIELD_ENDPOINT', 'http://localhost:3001');
```

(Replace `http://localhost:3001` with a URL your WordPress instance can
actually reach — if WP runs in Docker, use `http://host.docker.internal:3001`.)

Activate the plugin in **WP Admin → Plugins**. That's it. See
[packages/middleware-wordpress/README.md](../packages/middleware-wordpress/README.md)
for the full DoD demo.

### Laravel

```bash
composer require reverseshield/laravel
```

Laravel's auto-discovery picks up the service provider. Add to `.env`:

```
REVERSESHIELD_SITE_ID=<your-uuid>
REVERSESHIELD_ENDPOINT=http://localhost:3001
```

That's it. The middleware auto-registers globally. Add
`@reverseshieldHoneypot` to any forms you want to protect. See
[packages/middleware-laravel/README.md](../packages/middleware-laravel/README.md)
for details.

## Running the tests

Everything green means the pipeline is working end-to-end:

```bash
# Browser agent + reporting API (~91 tests)
npm run test --workspaces --if-present

# WordPress plugin (~64 tests, needs PHP CLI)
php packages/middleware-wordpress/test/plugin-test.php

# Laravel package (~34 tests)
cd packages/middleware-laravel
composer install
vendor/bin/phpunit
```

## Windows PHP setup

Windows doesn't ship with PHP. If you don't have it, `composer install` and
the WordPress smoke test won't work.

**The trap:** if you install Local by Flywheel for testing WordPress, it
bundles a PHP but that PHP is missing common extensions (openssl, curl,
mbstring) which composer needs. You'll get "The openssl extension is required
for SSL/TLS protection" if you try to use it.

**The fix:** install standalone PHP separately.

1. Download PHP 8.3 (or later) NTS x64 zip from
   https://windows.php.net/downloads/releases/
2. Extract to `C:\php`
3. `copy C:\php\php.ini-development C:\php\php.ini`
4. Open `C:\php\php.ini` and uncomment (remove the leading `;` from) these
   lines:

   ```
   ;extension=curl
   ;extension=fileinfo
   ;extension=mbstring
   ;extension=openssl
   ;extension=pdo_sqlite
   ;extension=sqlite3
   ;extension=zip
   ```

5. Add `C:\php` to your PATH. Simplest is `set PATH=C:\php;%PATH%` per cmd
   window; `setx PATH "C:\php;%PATH%"` makes it persistent.
6. Also `set PHPRC=C:\php` so PHP finds the ini file regardless of your
   working directory.

Verify:

```
php --version
# PHP 8.3.x (cli) ...

php -m | findstr openssl
# openssl
```

Then install composer:

```
curl -o composer.phar https://getcomposer.org/composer-stable.phar
php composer.phar --version
```

Now you can run `php composer.phar install` and `vendor/bin/phpunit` in
`packages/middleware-laravel/`.

## Troubleshooting

**Dashboard says "Failed to load sites":** the reporting API isn't running,
or it's running on a different port than `RS_CORS_DASHBOARD_ORIGIN` expects.
Check terminal 1 for the "listening on..." line.

**Browser DevTools shows CORS error on `/api/v1/events`:** you're loading the
site from a different origin than the reporting API's `RS_CORS_DASHBOARD_ORIGIN`
allows AND your browser has Private Network Access restrictions enabled. The
events endpoint accepts any origin by design — check that the reporting API's
`Access-Control-Allow-Private-Network` header is set (it should be by default
in v0.1.0 and later).

**WordPress page loads but events don't reach the dashboard:** the plugin's
`REVERSESHIELD_ENDPOINT` isn't reachable from PHP. Common causes:
- WordPress runs in Docker but endpoint is `http://localhost:3001` — inside
  the container that reaches the container itself, not your host. Use
  `http://host.docker.internal:3001` instead.
- Local firewall blocks the outbound request

**Laravel tests fail on `composer install` with "affected by security
advisories":** composer 2.9 and later blocks Laravel versions that have any
historical advisory. Fixed in `packages/middleware-laravel/composer.json` by
whitelisting the specific advisory IDs. If new advisories appear, add them to
the `config.audit.ignore` array.
