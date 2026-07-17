<?php

declare(strict_types=1);

namespace ReverseShield\Laravel\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use ReverseShield\Laravel\Services\EventReporter;
use ReverseShield\Laravel\Support\HoneypotFieldName;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * ReverseShield middleware for Laravel.
 *
 * Fail-open contract: every phase of handle() is wrapped in safeCheck /
 * safeExecute. Any exception thrown during pre-request checks or post-response
 * modification is caught, reported to Laravel's log, and swallowed — the request
 * always continues via $next($request). A security failure must never cause an
 * HTTP 500 for a valid user.
 *
 * Detection *actions* (returning 429 for a confirmed rate-limit breach, 403 for
 * a confirmed honeypot fill) are not "failures" in the fail-open sense — they
 * fire only after a successful detection. Fail-open covers the case where our
 * own code broke, not the case where an attacker was correctly identified.
 */
final class ReverseShieldMiddleware
{
    public function __construct(
        private readonly EventReporter $reporter,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        // Master switch. Zero side effects when disabled.
        if (!(bool) config('reverseshield.enabled', true)) {
            return $next($request);
        }

        // Phase 1 — pre-request checks. Each can return a Response to short-
        // circuit the pipeline; each is wrapped in safeCheck() so an internal
        // exception falls through to $next() instead of surfacing as a 500.
        if ($response = $this->safeCheck(fn () => $this->checkLoginRateLimit($request))) {
            return $response;
        }
        if ($response = $this->safeCheck(fn () => $this->checkHoneypot($request))) {
            return $response;
        }
        $this->safeExecute(fn () => $this->monitorApiRate($request));

        // Phase 2 — the actual request. Never guarded by fail-open; the app
        // itself decides what to do.
        $response = $next($request);

        // Phase 3 — post-response modification. Snippet injection is the only
        // mutation we make. Fail-open guards against a mangled response object
        // in edge cases (e.g. StreamedResponse, BinaryFileResponse) where
        // getContent() doesn't return a string.
        $this->safeExecute(fn () => $this->injectSnippet($response));

        return $response;
    }

    // -----------------------------------------------------------------------
    // Detection paths
    // -----------------------------------------------------------------------

    /**
     * Login brute-force rate limiting, per IP.
     *
     * Only checked on POST requests to configured login paths. When exceeded,
     * fires a rate_limit_exceeded event and returns 429 with Retry-After.
     * v1 counts *all* login POSTs, not just failures; a legitimate user hits
     * login at most a couple of times per session so 5 attempts per 5 minutes
     * is very generous. v2 will integrate with Auth\Events\Failed for
     * failure-only counting.
     */
    private function checkLoginRateLimit(Request $request): ?Response
    {
        if (!$request->isMethod('POST') || !$this->isLoginPath($request)) {
            return null;
        }

        $ip = (string) ($request->ip() ?? '');
        if ($ip === '') {
            return null;
        }

        /** @var array{max: int, window_seconds: int} $cfg */
        $cfg = (array) config('reverseshield.rate_limits.login', ['max' => 5, 'window_seconds' => 300]);
        $key = 'rs_login_' . sha1($ip);

        if (RateLimiter::tooManyAttempts($key, $cfg['max'])) {
            $this->reporter->send('rate_limit_exceeded', -60, [
                'rule' => 'login_attempts',
                'window_seconds' => $cfg['window_seconds'],
                'max' => $cfg['max'],
                'path' => $request->path(),
            ]);

            $retryAfter = RateLimiter::availableIn($key);

            return response('Too many login attempts. Please try again later.', 429)
                ->header('Retry-After', (string) $retryAfter);
        }

        RateLimiter::hit($key, $cfg['window_seconds']);

        return null;
    }

    /**
     * Server-side honeypot detection. If the derived honeypot field is present
     * and non-empty in the POST body, the submitter is almost certainly a bot.
     * Fires the event; optionally returns 403.
     */
    private function checkHoneypot(Request $request): ?Response
    {
        if (!$request->isMethod('POST')) {
            return null;
        }

        $fieldName = HoneypotFieldName::fromConfig();
        if ($fieldName === '') {
            return null;
        }

        $value = $request->input($fieldName);
        if (!is_string($value) || trim($value) === '') {
            return null;
        }

        $this->reporter->send('honeypot_triggered', -80, [
            'field' => $fieldName,
            'context' => 'form_submit',
            'path' => $request->path(),
        ]);

        if ((bool) config('reverseshield.block_honeypot', true)) {
            return response('Submission flagged as automated.', 403);
        }

        return null;
    }

    /**
     * REST/API rate monitoring. Detect only; does not block.
     *
     * Only counts requests to /api/* paths. When the per-IP threshold is
     * crossed, fires an event. The response engine (v2/3) decides what to do
     * with it; blocking legitimate integrations because of a rate check is too
     * high a false-positive cost for v1.
     */
    private function monitorApiRate(Request $request): void
    {
        if (!str_starts_with($request->path(), 'api/')) {
            return;
        }

        $ip = (string) ($request->ip() ?? '');
        if ($ip === '') {
            return;
        }

        /** @var array{max: int, window_seconds: int} $cfg */
        $cfg = (array) config('reverseshield.rate_limits.api', ['max' => 120, 'window_seconds' => 60]);
        $key = 'rs_api_' . sha1($ip);

        RateLimiter::hit($key, $cfg['window_seconds']);
        $attempts = RateLimiter::attempts($key);

        if ($attempts > $cfg['max']) {
            $this->reporter->send('rate_limit_exceeded', -40, [
                'rule' => 'api',
                'window_seconds' => $cfg['window_seconds'],
                'max' => $cfg['max'],
                'attempts' => $attempts,
            ]);
        }
    }

    // -----------------------------------------------------------------------
    // Response modification
    // -----------------------------------------------------------------------

    /**
     * Inject the agent snippet before </head> if the response is HTML.
     *
     * Only touches text/html responses. Streamed responses, JSON, binary files,
     * redirects — all pass through unchanged. If the HTML has no </head> at
     * all (weird but possible), we leave it alone rather than guessing.
     */
    private function injectSnippet(Response $response): void
    {
        if (!(bool) config('reverseshield.inject_snippet', true)) {
            return;
        }

        $contentType = (string) $response->headers->get('Content-Type', '');
        if (!str_contains(strtolower($contentType), 'text/html')) {
            return;
        }

        // getContent() returns false on some Response subtypes (streamed, binary).
        // Only proceed when we have a real string to modify.
        $content = $response->getContent();
        if (!is_string($content) || $content === '') {
            return;
        }

        if (stripos($content, '</head>') === false) {
            return;
        }

        $endpoint = (string) config('reverseshield.endpoint', '');
        $siteId = (string) config('reverseshield.site_id', '');
        if ($endpoint === '' || $siteId === '') {
            return;
        }

        // json_encode gives us safe JS-string escaping for both URL and UUID.
        $agentUrl = json_encode($endpoint . '/agent.js', JSON_UNESCAPED_SLASHES);
        $siteIdJs = json_encode($siteId);
        $endpointJs = json_encode($endpoint, JSON_UNESCAPED_SLASHES);
        if ($agentUrl === false || $siteIdJs === false || $endpointJs === false) {
            return;
        }

        $snippet = "<!-- ReverseShield agent -->\n"
            . '<script type="module">' . "\n"
            . '  import { init } from ' . $agentUrl . ';' . "\n"
            . '  init({ siteId: ' . $siteIdJs . ', endpoint: ' . $endpointJs . ' });' . "\n"
            . '</script>' . "\n";

        // Case-insensitive replace at the first </head> only. Preserves the rest
        // of the document byte-for-byte.
        $newContent = preg_replace('#</head>#i', $snippet . '</head>', $content, 1);
        if (is_string($newContent) && $newContent !== $content) {
            $response->setContent($newContent);
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private function isLoginPath(Request $request): bool
    {
        $path = $request->path();
        /** @var array<int, string> $loginPaths */
        $loginPaths = (array) config('reverseshield.login_paths', ['login']);

        foreach ($loginPaths as $candidate) {
            if ($path === (string) $candidate) {
                return true;
            }
        }

        return false;
    }

    /**
     * Run a callable that may throw and may return a short-circuit Response.
     * If it throws, log and return null (fail-open). If it returns a Response,
     * hand it back to the caller.
     *
     * @param callable(): (?Response) $check
     */
    private function safeCheck(callable $check): ?Response
    {
        try {
            $result = $check();
            return $result instanceof Response ? $result : null;
        } catch (Throwable $e) {
            $this->safeReport($e);
            return null;
        }
    }

    /**
     * Run a callable that may throw but doesn't return a decision. If it
     * throws, log and continue (fail-open).
     *
     * @param callable(): void $fn
     */
    private function safeExecute(callable $fn): void
    {
        try {
            $fn();
        } catch (Throwable $e) {
            $this->safeReport($e);
        }
    }

    private function safeReport(Throwable $e): void
    {
        try {
            if (function_exists('report')) {
                report($e);
            }
        } catch (Throwable) {
            // absolute last resort
        }
    }
}
