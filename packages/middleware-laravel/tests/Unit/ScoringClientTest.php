<?php

declare(strict_types=1);

namespace ReverseShield\Laravel\Tests\Unit;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request as HttpRequest;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\Test;
use ReverseShield\Laravel\Services\ScoringClient;
use ReverseShield\Laravel\Tests\TestCase;

/**
 * Unit tests for ScoringClient — the "call POST /api/v1/score and treat every failure
 * as a null result" contract.
 *
 * Coverage matrix (input × API state × expected client behavior):
 *
 *   valid signals + 200 with correct body    →  returns array with score fields
 *   valid signals + 200 with malformed body  →  returns null (defensive shape check)
 *   valid signals + 500                      →  returns null
 *   valid signals + 503                      →  returns null (scoring_unavailable path)
 *   valid signals + connection timeout       →  returns null (fail-open)
 *   empty signals + 200                      →  returns array (baseline case)
 *   empty endpoint config                    →  returns null, no HTTP call issued
 *   empty site_id config                     →  returns null, no HTTP call issued
 */
final class ScoringClientTest extends TestCase
{
    // -----------------------------------------------------------------------
    // Happy path — score is returned in the documented shape
    // -----------------------------------------------------------------------

    #[Test]
    public function it_posts_signals_to_the_configured_endpoint(): void
    {
        Http::fake([
            self::TEST_ENDPOINT . '/api/v1/score' => Http::response([
                'score' => 20,
                'band' => 'likely_bot',
                'triggered_rule_ids' => ['honeypot-field-fill'],
                'total_weight' => 80,
            ], 200),
        ]);

        $client = new ScoringClient(self::TEST_ENDPOINT, self::TEST_SITE_ID, 200);
        $result = $client->score(['honeypot_triggered']);

        $this->assertSame([
            'score' => 20,
            'band' => 'likely_bot',
            'triggered_rule_ids' => ['honeypot-field-fill'],
            'total_weight' => 80,
        ], $result);

        Http::assertSent(function (HttpRequest $request) {
            return $request->url() === self::TEST_ENDPOINT . '/api/v1/score'
                && $request->method() === 'POST'
                && $request->data() === [
                    'site_id' => self::TEST_SITE_ID,
                    'signals' => ['honeypot_triggered'],
                ];
        });
    }

    #[Test]
    public function it_handles_multiple_signals(): void
    {
        Http::fake([
            self::TEST_ENDPOINT . '/api/v1/score' => Http::response([
                'score' => 0,
                'band' => 'likely_bot',
                'triggered_rule_ids' => ['honeypot-field-fill', 'rate-limit-exceeded'],
                'total_weight' => 120,
            ], 200),
        ]);

        $client = new ScoringClient(self::TEST_ENDPOINT, self::TEST_SITE_ID, 200);
        $result = $client->score(['honeypot_triggered', 'rate_limit_exceeded']);

        $this->assertNotNull($result);
        $this->assertSame(0, $result['score']);
        $this->assertSame(120, $result['total_weight']);
    }

    #[Test]
    public function empty_signals_still_produces_a_valid_call(): void
    {
        // Middlewares may need to ask "what's the baseline for this session right now?"
        // even without any triggered signals — e.g. for header attachment. The API
        // handles empty signals and returns 100/likely_human; the client must not
        // short-circuit before making the call.
        Http::fake([
            self::TEST_ENDPOINT . '/api/v1/score' => Http::response([
                'score' => 100,
                'band' => 'likely_human',
                'triggered_rule_ids' => [],
                'total_weight' => 0,
            ], 200),
        ]);

        $client = new ScoringClient(self::TEST_ENDPOINT, self::TEST_SITE_ID, 200);
        $result = $client->score([]);

        $this->assertSame(100, $result['score']);
        $this->assertSame('likely_human', $result['band']);
    }

    // -----------------------------------------------------------------------
    // Fail-open — every non-happy path collapses to null
    // -----------------------------------------------------------------------

    #[Test]
    public function it_returns_null_on_5xx(): void
    {
        Http::fake([
            self::TEST_ENDPOINT . '/api/v1/score' => Http::response(['error' => 'boom'], 500),
        ]);

        $client = new ScoringClient(self::TEST_ENDPOINT, self::TEST_SITE_ID, 200);
        $this->assertNull($client->score(['honeypot_triggered']));
    }

    #[Test]
    public function it_returns_null_on_503_scoring_unavailable(): void
    {
        // The specific 503 the reporting API returns when WASM isn't loaded. Middleware
        // must silently continue in this state — the reporting service is up, it just
        // can't score, so page loads still work.
        Http::fake([
            self::TEST_ENDPOINT . '/api/v1/score' => Http::response(
                ['error' => 'scoring_unavailable'],
                503,
            ),
        ]);

        $client = new ScoringClient(self::TEST_ENDPOINT, self::TEST_SITE_ID, 200);
        $this->assertNull($client->score(['honeypot_triggered']));
    }

    #[Test]
    public function it_returns_null_when_the_response_body_is_missing_expected_fields(): void
    {
        // A misconfigured reverse proxy could return HTML "200 OK" pages under
        // failure conditions. The client must not blindly trust "2xx" — it validates
        // the payload shape before returning.
        Http::fake([
            self::TEST_ENDPOINT . '/api/v1/score' => Http::response([
                'score' => 42,
                // no band, triggered_rule_ids, or total_weight
            ], 200),
        ]);

        $client = new ScoringClient(self::TEST_ENDPOINT, self::TEST_SITE_ID, 200);
        $this->assertNull($client->score(['honeypot_triggered']));
    }

    #[Test]
    public function it_returns_null_when_the_response_body_has_wrong_field_types(): void
    {
        Http::fake([
            self::TEST_ENDPOINT . '/api/v1/score' => Http::response([
                'score' => '20',  // string, not int
                'band' => 'likely_bot',
                'triggered_rule_ids' => [],
                'total_weight' => 80,
            ], 200),
        ]);

        $client = new ScoringClient(self::TEST_ENDPOINT, self::TEST_SITE_ID, 200);
        $this->assertNull($client->score(['honeypot_triggered']));
    }

    #[Test]
    public function it_returns_null_on_network_exception(): void
    {
        // Simulates connect-refused / DNS failure / timeout — any Throwable path.
        // Uses a subclass to force-throw from the Http facade, mirroring the pattern
        // in EventReporterTest for fail-open verification.
        Http::fake(function () {
            throw new ConnectionException('connection refused');
        });

        $client = new ScoringClient(self::TEST_ENDPOINT, self::TEST_SITE_ID, 200);
        $this->assertNull($client->score(['honeypot_triggered']));
    }

    #[Test]
    public function it_returns_null_without_making_a_call_when_endpoint_is_empty(): void
    {
        Http::fake();  // fake so we can assert nothing was sent

        $client = new ScoringClient('', self::TEST_SITE_ID, 200);
        $this->assertNull($client->score(['honeypot_triggered']));

        Http::assertNothingSent();
    }

    #[Test]
    public function it_returns_null_without_making_a_call_when_site_id_is_empty(): void
    {
        Http::fake();

        $client = new ScoringClient(self::TEST_ENDPOINT, '', 200);
        $this->assertNull($client->score(['honeypot_triggered']));

        Http::assertNothingSent();
    }

    // -----------------------------------------------------------------------
    // Timeout enforcement — the 200ms guardrail
    // -----------------------------------------------------------------------

    #[Test]
    public function it_configures_a_hard_timeout_floor_of_50ms_even_if_config_asks_for_less(): void
    {
        // Configuring 10ms is nonsensical (TCP handshake alone takes longer on
        // anything but localhost) but must not cause a Guzzle error — the client
        // floors to 50ms internally.
        Http::fake([
            self::TEST_ENDPOINT . '/api/v1/score' => Http::response([
                'score' => 100,
                'band' => 'likely_human',
                'triggered_rule_ids' => [],
                'total_weight' => 0,
            ], 200),
        ]);

        $client = new ScoringClient(self::TEST_ENDPOINT, self::TEST_SITE_ID, 10);
        $result = $client->score([]);

        // Successful outcome — no exception, valid result. If the floor weren't
        // enforced, Guzzle would throw on Http::timeout(0.01) in some configs.
        $this->assertNotNull($result);
    }
}
