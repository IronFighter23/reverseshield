<?php

declare(strict_types=1);

namespace ReverseShield\Laravel\Tests\Feature;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\Test;
use ReverseShield\Laravel\Http\Middleware\ReverseShieldMiddleware;
use ReverseShield\Laravel\Services\ScoringClient;
use ReverseShield\Laravel\Support\HoneypotFieldName;
use ReverseShield\Laravel\Tests\TestCase;

final class MiddlewareTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Http::fake();

        Route::middleware(ReverseShieldMiddleware::class)->group(function () {
            Route::get('/html', function () {
                return response(
                    '<!doctype html><html><head><title>x</title></head><body>hi</body></html>',
                    200,
                    ['Content-Type' => 'text/html']
                );
            });
            Route::get('/html-no-head', function () {
                return response('<html><body>hi</body></html>', 200, ['Content-Type' => 'text/html']);
            });
            Route::get('/json', function () {
                return response()->json(['ok' => true]);
            });
            Route::post('/submit', fn () => response('ok', 200));
            Route::post('/login', fn () => response('ok', 200));
            Route::get('/api/things', fn () => response()->json(['things' => []]));
        });
    }

    // -------------------------------------------------------------------
    // Snippet injection
    // -------------------------------------------------------------------

    #[Test]
    public function it_injects_the_agent_snippet_before_closing_head(): void
    {
        $response = $this->get('/html');
        $response->assertOk();

        $body = (string) $response->getContent();
        $this->assertStringContainsString('<!-- ReverseShield agent -->', $body);
        $this->assertStringContainsString('import { init } from "http://api.test/agent.js"', $body);
        $this->assertStringContainsString('siteId: "' . self::TEST_SITE_ID . '"', $body);

        $snippetPos = strpos($body, '<!-- ReverseShield agent -->');
        $headClosePos = strpos($body, '</head>');
        $this->assertNotFalse($snippetPos);
        $this->assertNotFalse($headClosePos);
        $this->assertLessThan($headClosePos, $snippetPos);
    }

    #[Test]
    public function it_does_not_inject_into_non_html_responses(): void
    {
        $response = $this->get('/json');
        $response->assertOk();
        $body = (string) $response->getContent();
        $this->assertStringNotContainsString('ReverseShield agent', $body);
    }

    #[Test]
    public function it_does_not_inject_when_response_has_no_closing_head(): void
    {
        $response = $this->get('/html-no-head');
        $response->assertOk();
        $body = (string) $response->getContent();
        $this->assertStringNotContainsString('ReverseShield agent', $body);
    }

    #[Test]
    public function it_does_not_inject_when_disabled_via_config(): void
    {
        config()->set('reverseshield.inject_snippet', false);
        $response = $this->get('/html');
        $body = (string) $response->getContent();
        $this->assertStringNotContainsString('ReverseShield agent', $body);
    }

    #[Test]
    public function it_does_nothing_when_master_switch_is_off(): void
    {
        config()->set('reverseshield.enabled', false);
        $response = $this->get('/html');
        $body = (string) $response->getContent();
        $this->assertStringNotContainsString('ReverseShield agent', $body);
    }

    // -------------------------------------------------------------------
    // Honeypot detection
    // -------------------------------------------------------------------

    #[Test]
    public function it_blocks_submissions_with_a_filled_honeypot_field(): void
    {
        $fieldName = HoneypotFieldName::forSite(self::TEST_SITE_ID);
        $response = $this->post('/submit', [$fieldName => 'spam-content']);
        $response->assertStatus(403);
    }

    #[Test]
    public function honeypot_events_are_enriched_with_score_when_scoring_api_is_available(): void
    {
        // The whole payoff of Phase 2 step 4 in one test: when the ScoringClient
        // returns a real score, the emitted honeypot_triggered event carries `score`
        // and `band` in its details.
        //
        // We inject a subclass of ScoringClient rather than mocking the underlying
        // Http calls, for two reasons: (1) the setUp() blanket Http::fake() overrides
        // per-URL fakes in unpredictable ways between Testbench versions; (2) what
        // this test cares about is "the middleware correctly consumes the client's
        // return value" — the HTTP wire is already exercised by ScoringClientTest.
        $this->app->instance(ScoringClient::class, new class (self::TEST_ENDPOINT, self::TEST_SITE_ID, 200) extends ScoringClient {
            public function score(array $signals): ?array
            {
                return [
                    'score' => 20,
                    'band' => 'likely_bot',
                    'triggered_rule_ids' => ['honeypot-field-fill'],
                    'total_weight' => 80,
                ];
            }
        });

        $fieldName = HoneypotFieldName::forSite(self::TEST_SITE_ID);
        $response = $this->post('/submit', [$fieldName => 'spam-content']);
        $response->assertStatus(403);

        Http::assertSent(function ($request) {
            if ($request->url() !== self::TEST_ENDPOINT . '/api/v1/events') {
                return false;
            }
            /** @var array<string, mixed> $body */
            $body = $request->data();
            if ($body['type'] !== 'honeypot_triggered') {
                return false;
            }
            /** @var array<string, mixed> $details */
            $details = $body['details'];
            return isset($details['score'], $details['band'])
                && $details['score'] === 20
                && $details['band'] === 'likely_bot';
        });
    }

    #[Test]
    public function honeypot_events_are_shipped_without_enrichment_when_scoring_returns_null(): void
    {
        // Fail-open: if the scorer returns null (any reason — 5xx, 503, timeout, bad
        // shape), the event still fires and the request still gets blocked. No
        // `score` or `band` in details — downstream event schema is unchanged from
        // Phase 1. This is the guarantee that lets us swap scoring on and off
        // without ever coordinating with the events consumer.
        $this->app->instance(ScoringClient::class, new class (self::TEST_ENDPOINT, self::TEST_SITE_ID, 200) extends ScoringClient {
            public function score(array $signals): ?array
            {
                return null;
            }
        });

        $fieldName = HoneypotFieldName::forSite(self::TEST_SITE_ID);
        $response = $this->post('/submit', [$fieldName => 'spam-content']);
        $response->assertStatus(403);

        Http::assertSent(function ($request) {
            if ($request->url() !== self::TEST_ENDPOINT . '/api/v1/events') {
                return false;
            }
            /** @var array<string, mixed> $body */
            $body = $request->data();
            if ($body['type'] !== 'honeypot_triggered') {
                return false;
            }
            /** @var array<string, mixed> $details */
            $details = $body['details'];
            return !isset($details['score']) && !isset($details['band']);
        });
    }

    #[Test]
    public function it_lets_through_submissions_with_an_empty_honeypot_field(): void
    {
        $fieldName = HoneypotFieldName::forSite(self::TEST_SITE_ID);
        $response = $this->post('/submit', [$fieldName => '', 'name' => 'alice']);
        $response->assertOk();
    }

    #[Test]
    public function it_lets_through_submissions_without_any_honeypot_field(): void
    {
        $response = $this->post('/submit', ['name' => 'alice']);
        $response->assertOk();
    }

    #[Test]
    public function it_does_not_block_when_block_honeypot_is_false(): void
    {
        config()->set('reverseshield.block_honeypot', false);
        $fieldName = HoneypotFieldName::forSite(self::TEST_SITE_ID);
        $response = $this->post('/submit', [$fieldName => 'spam-content']);
        $response->assertOk();
    }

    // -------------------------------------------------------------------
    // Login rate limiting
    // -------------------------------------------------------------------

    #[Test]
    public function it_permits_login_attempts_below_the_threshold(): void
    {
        $this->flushRateLimits();
        config()->set('reverseshield.rate_limits.login.max', 5);

        for ($i = 0; $i < 5; $i++) {
            $response = $this->post('/login', ['user' => 'x', 'pass' => 'y']);
            $response->assertOk();
        }
    }

    #[Test]
    public function it_returns_429_after_the_login_threshold(): void
    {
        $this->flushRateLimits();
        config()->set('reverseshield.rate_limits.login.max', 3);

        for ($i = 0; $i < 3; $i++) {
            $this->post('/login', ['user' => 'x', 'pass' => 'y']);
        }

        $blocked = $this->post('/login', ['user' => 'x', 'pass' => 'y']);
        $blocked->assertStatus(429);
        $blocked->assertHeader('Retry-After');
    }

    // -------------------------------------------------------------------
    // Decoy routes
    // -------------------------------------------------------------------

    #[Test]
    public function decoy_users_route_returns_200_with_empty_data(): void
    {
        $response = $this->get('/reverseshield-decoy/v1/users');
        $response->assertOk();
        $response->assertJson(['data' => []]);
    }

    #[Test]
    public function decoy_backup_route_returns_200_with_empty_data(): void
    {
        $response = $this->get('/reverseshield-decoy/v1/backup');
        $response->assertOk();
        $response->assertJson(['data' => []]);
    }

    #[Test]
    public function decoy_routes_accept_post_as_well_as_get(): void
    {
        $response = $this->post('/reverseshield-decoy/v1/tokens', ['x' => 'y']);
        $response->assertOk();
    }
}