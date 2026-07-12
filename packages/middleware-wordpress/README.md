# ReverseShield — WordPress plugin

Injects the browser agent, serves honeypot decoy routes, and monitors rate
limits. Fail-open by design: any error in this plugin lets the WordPress
request continue to render.

## Requirements

- PHP 7.4 or newer (works on 8.0, 8.1, 8.2, 8.3)
- WordPress 5.0 or newer
- A running ReverseShield reporting API (see `services/reporting/api/`)

## Install

Copy this whole directory into `wp-content/plugins/reverseshield/` in your
WordPress install. The main file (`reverseshield.php`) contains the plugin
header, so WordPress recognises the directory as a plugin.

Then add the following to your `wp-config.php`, above the `/* That's all,
stop editing! */` line:

```php
// ReverseShield — required
define('REVERSESHIELD_SITE_ID', 'PASTE_YOUR_SITE_ID_HERE');
define('REVERSESHIELD_ENDPOINT', 'http://host.docker.internal:3001');
```

Get `SITE_ID` by registering a site in the ReverseShield dashboard
(`http://localhost:5173`). Copy the UUID from the install snippet.

Set `ENDPOINT` to wherever your reporting API is reachable **from the WordPress
process**:

- Docker WordPress on Windows/Mac → `http://host.docker.internal:3001`
- Docker WordPress on Linux → `http://172.17.0.1:3001` (or `host.docker.internal` with `extra_hosts` config)
- Local by Flywheel / XAMPP → `http://localhost:3001`
- Real server → the public URL of your reporting API

Then activate the plugin: **WP Admin → Plugins → ReverseShield → Activate**.

## Optional configuration

All of the following have safe defaults. Override in `wp-config.php` only if
needed.

| Constant                              | Default                     | Purpose                                                         |
|---------------------------------------|-----------------------------|-----------------------------------------------------------------|
| `REVERSESHIELD_ENABLE`                | `true`                      | Master switch. `false` disables all hooks.                      |
| `REVERSESHIELD_TIMEOUT_MS`            | `200`                       | Hard cap on outbound requests to the reporting API.             |
| `REVERSESHIELD_RATE_LOGIN_MAX`        | `5`                         | Failed logins per IP before 429.                                |
| `REVERSESHIELD_RATE_LOGIN_WINDOW`     | `300`                       | Window (seconds) for the login limit.                           |
| `REVERSESHIELD_RATE_REST_MAX`         | `120`                       | REST calls per IP/session before firing an event (no block).    |
| `REVERSESHIELD_RATE_REST_WINDOW`      | `60`                        | Window (seconds) for the REST rate.                             |
| `REVERSESHIELD_BLOCK_HONEYPOT`        | `true`                      | Block requests that fill a honeypot field. Set `false` to log only. |
| `REVERSESHIELD_DECOY_NAMESPACE`       | `reverseshield-decoy/v1`    | REST namespace for decoy routes.                                |

## Phase 1 Definition of Done — end-to-end demo

Full checklist. Do this after installing the plugin and setting the two required
constants.

### 1. Prove `canary_embedded` fires on page load

1. Reporting API and dashboard already running (`npm run --workspace @reverseshield/reporting-api dev`, `npm run --workspace @reverseshield/reporting-dashboard dev`).
2. Load any front-end WordPress page (e.g., the home page).
3. View source (`Ctrl+U`) — you should see the `<!-- ReverseShield agent -->` block in `<head>` with an ESM `<script>` importing from `<endpoint>/agent.js`.
4. Open the dashboard (`http://localhost:5173`). The `canary_embedded` count should tick up within a few seconds.

### 2. Prove decoy routes fire `honeypot_triggered`

In a terminal:

```
curl http://localhost:8080/wp-json/reverseshield-decoy/v1/users
```

(Replace `localhost:8080` with your WP URL.) You should get `{"data":[]}` back
— the innocuous response. Refresh the dashboard: **Honeypot triggered** count
should tick up. Details should show `kind: decoy_route, route: /users, method: GET`.

### 3. Prove the comment honeypot works

1. Find any post that allows comments.
2. Open its page, view source, and search for `email_alt_` — you'll see the
   hidden honeypot input.
3. Simulate a bot filling it. Copy the field's `name` attribute
   (e.g., `email_alt_a3b1f2e4`) and POST:

   ```
   curl -X POST http://localhost:8080/wp-comments-post.php ^
     -d "comment_post_ID=1&author=Bot&email=bot@x.com&url=&comment=hi&email_alt_a3b1f2e4=filled"
   ```

   You should get an HTTP 403 back. Dashboard shows another **Honeypot triggered**
   event with `context: comment_form`.

### 4. Prove login rate limiting fires `rate_limit_exceeded`

Hammer wp-login.php with wrong credentials 6 times:

```
for /L %i in (1,1,6) do curl -X POST http://localhost:8080/wp-login.php -d "log=admin&pwd=wrong" -o nul
```

The 6th attempt returns a WP_Error page (default message: "Too many login
attempts…"). Dashboard shows a **Rate limit exceeded** event with
`rule: login_attempts`.

### 5. Verify fail-open

Stop the reporting API (`Ctrl+C` in its terminal). Reload the WP front page
— it should still render normally (the plugin catches the connection failure
and does nothing). Restart the API and events flow again.

If all five pass, **Phase 1 DoD is closed**.

## Running the smoke test

Fast local check that the plugin file parses and behaves as expected without
requiring WordPress:

```
php test/plugin-test.php
```

Requires PHP 7.4 or newer at the command line. Tests use stubs for the ~15
WordPress functions the plugin calls, then exercise every code path including
both fail-open branches. Expected output ends with `all N tests passed`.

## Fail-open guarantees

Every hook in the plugin is wrapped in a `try { ... } catch (Throwable $e) {}`
block. If any of the following happens, the WordPress request continues to
render normally:

- Reporting API is down
- Reporting API returns 4xx/5xx
- Reporting API takes longer than `REVERSESHIELD_TIMEOUT_MS`
- A hook throws unexpectedly (plugin conflict, PHP fatal, etc.)
- The plugin itself was misconfigured

The one thing that *is* enforced is the login rate limit and (optionally) the
honeypot block. Both are documented as intentional response actions, not fail-
open failures: they fire only when a detection has *already succeeded*.
