<?php

declare(strict_types=1);

namespace ReverseShield\Laravel\Services;

use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * Calls POST /api/v1/score on the reporting API to compute the canonical trust
 * score for a set of signals detected by the middleware. This is the mechanism
 * that keeps `rules/core-rules.yaml` as the single source of truth for weights
 * — the middleware ships the signal names, the API returns the score, and
 * nothing in this codebase duplicates the numeric weights that used to be
 * hardcoded in Phase 1.
 *
 * Fail-open contract (mirrors EventReporter):
 *   * Endpoint or site_id not configured  → returns null, no HTTP call
 *   * Network exception (connect refused) → returns null (swallowed)
 *   * Timeout (default 200ms hard cap)    → returns null (swallowed)
 *   * Non-2xx response                    → returns null
 *   * Response body is not valid JSON     → returns null
 *   * Response missing expected fields    → returns null
 *
 * The 200ms budget is deliberate: middleware sits in the hot path of every
 * request. A slow scoring API must never delay a page. The number is a
 * *hard* cap — Http::timeout + Http::connectTimeout both fire at or below it.
 *
 * Not marked final so tests can subclass to inject throwing implementations
 * for fail-open verification, exactly like EventReporter.
 */
class ScoringClient
{
    public function __construct(
        private readonly string $endpoint,
        private readonly string $siteId,
        private readonly int $timeoutMs,
    ) {}

    /**
     * Compute the trust score for a set of signals. Returns null if scoring is
     * unavailable for any reason — caller treats null as "no score" and continues.
     *
     * The returned array mirrors the Rust ScoreResult struct one-for-one:
     *
     *   [
     *     'score' => int (0..100),
     *     'band' => 'likely_human'|'suspicious'|'likely_bot',
     *     'triggered_rule_ids' => string[],
     *     'total_weight' => int,
     *   ]
     *
     * @param string[] $signals SPEC §3.1 event type names.
     * @return array{score:int, band:string, triggered_rule_ids:array<int,string>, total_weight:int}|null
     */
    public function score(array $signals): ?array
    {
        try {
            if ($this->siteId === '' || $this->endpoint === '') {
                return null;
            }

            // Convert ms to seconds with a floor of 50ms — Guzzle rejects timeouts
            // below that in some transports, and a lower value would compress the
            // TLS+TCP handshake into an impossibly short window even on localhost.
            $timeoutSeconds = max(0.05, $this->timeoutMs / 1000);

            $response = Http::timeout($timeoutSeconds)
                ->connectTimeout($timeoutSeconds)
                ->withHeaders(['Content-Type' => 'application/json'])
                ->acceptJson()
                ->post($this->endpoint . '/api/v1/score', [
                    'site_id' => $this->siteId,
                    'signals' => array_values($signals),
                ]);

            if (!$response->successful()) {
                return null;
            }

            /** @var array<string, mixed>|null $body */
            $body = $response->json();
            if (!is_array($body)) {
                return null;
            }

            // Defensive field-shape check. The scoring API returns the exact shape
            // our Rust engine produces, but a proxy or misconfigured deployment
            // could return anything under a 2xx status — verify before trusting.
            if (
                !isset($body['score'], $body['band'], $body['triggered_rule_ids'], $body['total_weight'])
                || !is_int($body['score'])
                || !is_string($body['band'])
                || !is_array($body['triggered_rule_ids'])
                || !is_int($body['total_weight'])
            ) {
                return null;
            }

            return [
                'score' => $body['score'],
                'band' => $body['band'],
                'triggered_rule_ids' => array_values(array_filter(
                    $body['triggered_rule_ids'],
                    'is_string',
                )),
                'total_weight' => $body['total_weight'],
            ];
        } catch (Throwable $e) {
            $this->safeReport($e);
            return null;
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
