<?php

declare(strict_types=1);

namespace ReverseShield\Laravel\Tests\Unit;

use Illuminate\Http\Client\Request as HttpRequest;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\Test;
use ReverseShield\Laravel\Services\EventReporter;
use ReverseShield\Laravel\Tests\TestCase;

final class EventReporterTest extends TestCase
{
    #[Test]
    public function it_posts_events_to_the_configured_endpoint(): void
    {
        Http::fake();

        $reporter = new EventReporter(self::TEST_ENDPOINT, self::TEST_SITE_ID, 200);
        $reporter->send('honeypot_triggered', -80, ['field' => 'email_alt_xxx']);

        Http::assertSent(function (HttpRequest $request) {
            return $request->url() === self::TEST_ENDPOINT . '/api/v1/events'
                && $request->method() === 'POST';
        });
    }

    #[Test]
    public function the_payload_matches_spec_31(): void
    {
        Http::fake();

        $reporter = new EventReporter(self::TEST_ENDPOINT, self::TEST_SITE_ID, 200);
        $reporter->send('honeypot_triggered', -80, ['field' => 'email_alt_xxx']);

        Http::assertSent(function (HttpRequest $request) {
            /** @var array<string, mixed> $body */
            $body = $request->data();

            // Field presence
            $this->assertArrayHasKey('event_id', $body);
            $this->assertArrayHasKey('site_id', $body);
            $this->assertArrayHasKey('timestamp', $body);
            $this->assertArrayHasKey('source', $body);
            $this->assertArrayHasKey('session_id', $body);
            $this->assertArrayHasKey('type', $body);
            $this->assertArrayHasKey('score_delta', $body);
            $this->assertArrayHasKey('details', $body);
            $this->assertArrayHasKey('ip_hash', $body);
            $this->assertArrayHasKey('user_agent', $body);
            $this->assertArrayHasKey('asn', $body);

            // Values
            $this->assertSame(self::TEST_SITE_ID, $body['site_id']);
            $this->assertSame('server', $body['source']);
            $this->assertSame('honeypot_triggered', $body['type']);
            $this->assertSame(-80, $body['score_delta']);
            $this->assertSame(['field' => 'email_alt_xxx'], $body['details']);
            $this->assertNull($body['ip_hash']);
            $this->assertNull($body['asn']);

            // Format
            $uuidRe = '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';
            $this->assertMatchesRegularExpression($uuidRe, $body['event_id']);
            $this->assertMatchesRegularExpression($uuidRe, $body['session_id']);
            $this->assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/', $body['timestamp']);

            return true;
        });
    }

    #[Test]
    public function it_is_silent_when_site_id_is_empty(): void
    {
        Http::fake();

        $reporter = new EventReporter(self::TEST_ENDPOINT, '', 200);
        $reporter->send('canary_embedded', 0, []);

        Http::assertNothingSent();
    }

    #[Test]
    public function it_is_silent_when_endpoint_is_empty(): void
    {
        Http::fake();

        $reporter = new EventReporter('', self::TEST_SITE_ID, 200);
        $reporter->send('canary_embedded', 0, []);

        Http::assertNothingSent();
    }
}
