# ReverseShield — Laravel package

Middleware, decoy routes, honeypot detection, and rate-limit monitoring for
Laravel 10 and 11. Fail-open by design.

## Requirements

- PHP 8.1 or newer
- Laravel 10 or 11
- A running ReverseShield reporting API (see `services/reporting/api/`)

## Installation

```bash
composer require reverseshield/laravel
```

Laravel's package auto-discovery picks up the service provider automatically.
No `config/app.php` edit needed.

Set the two required env vars in `.env`:

```
REVERSESHIELD_SITE_ID=paste-your-uuid-here
REVERSESHIELD_ENDPOINT=http://localhost:3001
```

Get `SITE_ID` by registering a site in the ReverseShield dashboard. That's it —
the middleware is now global and events flow to your reporting API.

## Optional configuration

Publish the config file if you need to change anything beyond the env vars:

```bash
php artisan vendor:publish --tag=reverseshield-config
```

Any setting can also be overridden via `.env`:

| .env variable                          | Default                | Purpose                                                       |
|----------------------------------------|------------------------|---------------------------------------------------------------|
| `REVERSESHIELD_ENABLED`                | `true`                 | Master switch. False = zero side effects.                     |
| `REVERSESHIELD_AUTO_REGISTER`          | `true`                 | Auto-add to global middleware. Set false to add selectively.  |
| `REVERSESHIELD_TIMEOUT_MS`             | `200`                  | Hard cap on outbound events POST.                             |
| `REVERSESHIELD_INJECT_SNIPPET`         | `true`                 | Inject browser agent snippet into HTML responses.             |
| `REVERSESHIELD_BLOCK_HONEYPOT`         | `true`                 | Return 403 on a filled honeypot. False = log-only.            |
| `REVERSESHIELD_DECOY_PREFIX`           | `reverseshield-decoy/v1` | Route prefix for the decoy honeypot endpoints.              |
| `REVERSESHIELD_RATE_LOGIN_MAX`         | `5`                    | Login POSTs per IP before 429.                                |
| `REVERSESHIELD_RATE_LOGIN_WINDOW`      | `300`                  | Window (seconds) for the login limit.                         |
| `REVERSESHIELD_RATE_API_MAX`           | `120`                  | API requests per IP before firing an event (does not block).  |
| `REVERSESHIELD_RATE_API_WINDOW`        | `60`                   | Window (seconds) for the API rate.                            |

## Usage

### The middleware runs on every request automatically

Once installed and `REVERSESHIELD_SITE_ID` + `REVERSESHIELD_ENDPOINT` are set,
the middleware injects the browser agent into every HTML response, catches
honeypot fills, monitors API rate, and enforces the login rate limit — all
without any code changes on your part.

### Blade honeypot directive

Drop one directive into any form you want to protect:

```blade
<form method="post" action="{{ route('comments.store') }}">
    @csrf
    @reverseshieldHoneypot
    <label>Your name<input type="text" name="name"></label>
    <label>Comment<textarea name="comment"></textarea></label>
    <button>Post</button>
</form>
```

The directive renders a visually hidden `<input>` that legitimate users can
neither see nor tab into. Bots that auto-fill every field will fill it, and
the middleware will catch them on the POST and return 403 (or fire an event
only, if `REVERSESHIELD_BLOCK_HONEYPOT=false`).

### Selective application

If you don't want ReverseShield on every route, set `REVERSESHIELD_AUTO_REGISTER=false`
and apply the middleware alias to specific groups:

```php
Route::middleware('reverseshield')->group(function () {
    Route::post('/comments', ...);
    Route::post('/login', ...);
});
```

## Running the test suite

```bash
composer install
vendor/bin/phpunit
```

Expected output: `Tests: 32, Assertions: 60+, Errors: 0, Failures: 0`.

Tests use Orchestra Testbench to boot a minimal Laravel application and cover:

- **Unit** — HoneypotFieldName derivation, EventReporter payload against SPEC §3.1
- **Feature** — snippet injection (positive + negative), honeypot detection, login
  rate limit, decoy routes
- **FailOpen** — API refusing connection, API returning 500, reporter throwing,
  malformed response

## Fail-open guarantees

Every phase of the middleware's `handle()` method is wrapped in a small primitive
(`safeCheck` / `safeExecute`) that logs any thrown exception via Laravel's
`report()` and continues to `$next($request)`. The specific scenarios covered:

- Reporting API is unreachable (connection refused, DNS failure, etc)
- Reporting API returns 4xx or 5xx
- Reporting API takes longer than `REVERSESHIELD_TIMEOUT_MS`
- The bound `EventReporter` singleton throws for any reason
- The response object doesn't have a string body (streamed, binary, redirect)
- HTML response has no `</head>` to inject before
- Config values are missing or malformed

The one thing that *is* enforced despite all this: detection actions. If we
successfully detect a honeypot fill, we still return 403. If we successfully
detect a login rate-limit breach, we still return 429. Detection actions are
not "fail-open failures" — they fire only after a check succeeds, and blocking
a caught attacker is the tool doing its job.
