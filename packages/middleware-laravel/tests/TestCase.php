<?php

declare(strict_types=1);

namespace ReverseShield\Laravel\Tests;

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\RateLimiter;
use Orchestra\Testbench\TestCase as BaseTestCase;
use ReverseShield\Laravel\ReverseShieldServiceProvider;

/**
 * Common Testbench setup. All feature and unit tests extend this so they get:
 *   * The ReverseShield service provider registered
 *   * Array cache driver (fast, per-test-isolated)
 *   * Known site_id and endpoint so events have consistent shape assertions
 *   * auto_register OFF — tests apply the middleware via Route::middleware()
 *     explicitly. In production auto_register defaults to true; in tests we
 *     want to control middleware placement so we don't run it twice.
 *   * RateLimiter counters flushed between tests
 */
abstract class TestCase extends BaseTestCase
{
    protected const TEST_SITE_ID = '5c4c0a5d-091d-4e5b-9f23-f1dada9d5ffd';
    protected const TEST_ENDPOINT = 'http://api.test';

    /**
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [ReverseShieldServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        /** @var Application $app */
        $app['config']->set('cache.default', 'array');
        $app['config']->set('reverseshield.enabled', true);
        $app['config']->set('reverseshield.site_id', self::TEST_SITE_ID);
        $app['config']->set('reverseshield.endpoint', self::TEST_ENDPOINT);
        $app['config']->set('reverseshield.timeout_ms', 200);
        $app['config']->set('reverseshield.inject_snippet', true);
        $app['config']->set('reverseshield.block_honeypot', true);
        // Disabled in tests so we don't run the middleware twice (once
        // globally, once via Route::middleware() in the feature tests).
        $app['config']->set('reverseshield.auto_register', false);
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->flushRateLimits();
    }

    protected function flushRateLimits(): void
    {
        $ipHash = sha1('127.0.0.1');
        foreach (['rs_login_' . $ipHash, 'rs_api_' . $ipHash] as $key) {
            RateLimiter::clear($key);
        }
    }
}