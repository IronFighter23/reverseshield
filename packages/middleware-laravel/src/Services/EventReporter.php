<?php

declare(strict_types=1);

namespace ReverseShield\Laravel\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Throwable;

/**
 * Sends events to the ReverseShield reporting API. Every call is fail-open:
 * if the API is unreachable, times out, returns an error, or the HTTP client
 * throws for any reason, we swallow silently and continue. The middleware never
 * blocks a valid request because we couldn't talk to the reporting service.
 *
 * Not marked final so tests can subclass to inject throwing implementations
 * for fail-open verification.
 */
class EventReporter
{
    public function __construct(
        private readonly string $endpoint,
        private readonly string $siteId,
        private readonly int $timeoutMs,
    ) {}

    /**
     * Fire an event to POST /api/v1/events.
     *
     * @param string $type One of the SPEC §3.1 event types.
     * @param int $scoreDelta Integer, negative reduces trust.
     * @param array<string, mixed> $details Type-specific fields.
     */
    public function send(string $type, int $scoreDelta, array $details = []): void
    {
        try {
            if ($this->siteId === '' || $this->endpoint === '') {
                return;
            }

            $timeoutSeconds = max(0.05, $this->timeoutMs / 1000);

            $payload = [
                'event_id' => (string) Str::uuid(),
                'site_id' => $this->siteId,
                'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
                'source' => 'server',
                'session_id' => $this->getSessionId(),
                'type' => $type,
                'score_delta' => $scoreDelta,
                'details' => $details,
                'ip_hash' => null,
                'user_agent' => (string) (request()?->userAgent() ?? ''),
                'asn' => null,
            ];

            Http::timeout($timeoutSeconds)
                ->connectTimeout($timeoutSeconds)
                ->withHeaders(['Content-Type' => 'application/json'])
                ->acceptJson()
                ->post($this->endpoint . '/api/v1/events', $payload);
        } catch (Throwable $e) {
            $this->safeReport($e);
        }
    }

    private function getSessionId(): string
    {
        try {
            if (function_exists('session')) {
                $session = session();
                if ($session !== null && $session->isStarted()) {
                    $sid = $session->get('reverseshield.session_id');
                    if (is_string($sid) && preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $sid)) {
                        return $sid;
                    }
                    $sid = (string) Str::uuid();
                    $session->put('reverseshield.session_id', $sid);
                    return $sid;
                }
            }
        } catch (Throwable) {
            // fall through
        }

        return (string) Str::uuid();
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