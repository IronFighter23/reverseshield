<?php

declare(strict_types=1);

/**
 * ReverseShield Laravel package — default configuration.
 *
 * All settings are overridable via .env. Publish this file to your application
 * with:
 *
 *   php artisan vendor:publish --tag=reverseshield-config
 *
 * Only publish if you need to override something the .env constants above can't
 * express. The package works out of the box with just the two REVERSESHIELD_*
 * env vars set.
 */

return [
    // Master switch. When false, the middleware falls through to $next() with
    // zero side effects. Useful for surgically disabling in one environment.
    'enabled' => (bool) env('REVERSESHIELD_ENABLED', true),

    // The UUID you get from POST /api/v1/sites on your reporting API. Required.
    'site_id' => (string) env('REVERSESHIELD_SITE_ID', ''),

    // Reporting API endpoint (no trailing slash). Required.
    'endpoint' => rtrim((string) env('REVERSESHIELD_ENDPOINT', 'http://localhost:3001'), '/'),

    // Hard timeout on outbound events POST. Fail-open kicks in past this.
    'timeout_ms' => (int) env('REVERSESHIELD_TIMEOUT_MS', 200),

    // If true, the service provider calls $kernel->pushMiddleware() on boot so
    // this middleware runs on every HTTP request. Set false to opt out and add
    // it to your own middleware groups selectively.
    'auto_register' => (bool) env('REVERSESHIELD_AUTO_REGISTER', true),

    // Inject the browser agent snippet into HTML responses.
    'inject_snippet' => (bool) env('REVERSESHIELD_INJECT_SNIPPET', true),

    // Return 403 when a honeypot field is filled. Set false to log-only during
    // initial rollout when operators want to verify no false positives before
    // letting the middleware actually block.
    'block_honeypot' => (bool) env('REVERSESHIELD_BLOCK_HONEYPOT', true),

    // Route prefix for decoy endpoints. Same default as the WP plugin so a site
    // running both integrations exposes a consistent surface.
    'decoy_route_prefix' => (string) env('REVERSESHIELD_DECOY_PREFIX', 'reverseshield-decoy/v1'),

    // Paths that count as "login" for rate-limit purposes. Regex-matched
    // against $request->path().
    'login_paths' => [
        'login',
        'api/login',
        'auth/login',
    ],

    'rate_limits' => [
        // Login attempts per IP. When exceeded, the middleware returns 429.
        'login' => [
            'max' => (int) env('REVERSESHIELD_RATE_LOGIN_MAX', 5),
            'window_seconds' => (int) env('REVERSESHIELD_RATE_LOGIN_WINDOW', 300),
        ],
        // API requests per IP. Monitored — event fires, request continues.
        // The scoring engine (Phase 2/3) decides what to do with the events.
        'api' => [
            'max' => (int) env('REVERSESHIELD_RATE_API_MAX', 120),
            'window_seconds' => (int) env('REVERSESHIELD_RATE_API_WINDOW', 60),
        ],
    ],
];
