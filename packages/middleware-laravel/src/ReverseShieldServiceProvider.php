<?php

declare(strict_types=1);

namespace ReverseShield\Laravel;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use ReverseShield\Laravel\Http\Controllers\DecoyController;
use ReverseShield\Laravel\Http\Middleware\ReverseShieldMiddleware;
use ReverseShield\Laravel\Services\EventReporter;
use ReverseShield\Laravel\Services\ScoringClient;
use ReverseShield\Laravel\Support\HoneypotFieldName;
use Throwable;

/**
 * Wires ReverseShield into a Laravel application.
 *
 * On register(): merges the default config so users don't have to publish
 * before the package works, and binds EventReporter as a singleton.
 *
 * On boot(): publishes config for override, registers the decoy routes,
 * registers the middleware alias and (unless opted out) auto-adds it to the
 * global HTTP middleware stack, and registers the @reverseshieldHoneypot
 * Blade directive.
 */
final class ReverseShieldServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/Config/reverseshield.php',
            'reverseshield'
        );

        $this->app->singleton(EventReporter::class, function ($app) {
            /** @var \Illuminate\Contracts\Config\Repository $config */
            $config = $app['config'];

            return new EventReporter(
                endpoint: (string) $config->get('reverseshield.endpoint', ''),
                siteId: (string) $config->get('reverseshield.site_id', ''),
                timeoutMs: (int) $config->get('reverseshield.timeout_ms', 200),
            );
        });

        $this->app->singleton(ScoringClient::class, function ($app) {
            /** @var \Illuminate\Contracts\Config\Repository $config */
            $config = $app['config'];

            // Scoring shares the events endpoint by default but uses its own timeout
            // so the two can be tuned independently. In practice both live at 200ms
            // — the point of the separate config key is to let operators reduce
            // scoring to, say, 100ms without also making event reporting flakier.
            return new ScoringClient(
                endpoint: (string) $config->get('reverseshield.endpoint', ''),
                siteId: (string) $config->get('reverseshield.site_id', ''),
                timeoutMs: (int) $config->get(
                    'reverseshield.scoring_timeout_ms',
                    (int) $config->get('reverseshield.timeout_ms', 200),
                ),
            );
        });
    }

    public function boot(Router $router, Kernel $kernel): void
    {
        try {
            // Allow users to override any config value by publishing.
            $this->publishes([
                __DIR__ . '/Config/reverseshield.php' => config_path('reverseshield.php'),
            ], 'reverseshield-config');

            // Route middleware alias — always registered so users can also add
            // it selectively to specific route groups if they turned off auto-
            // register.
            $router->aliasMiddleware('reverseshield', ReverseShieldMiddleware::class);

            $this->registerDecoyRoutes();
            $this->registerBladeDirective();
            $this->maybeAutoRegisterGlobally($kernel);
        } catch (Throwable $e) {
            // Fail-open at boot too — a package that breaks the app on
            // installation fails its own guardrail.
            if (function_exists('report')) {
                try {
                    report($e);
                } catch (Throwable) {
                    // last resort
                }
            }
        }
    }

    /**
     * Register the fake bait routes that scanners often probe for. Names
     * mirror the WP plugin exactly.
     */
    private function registerDecoyRoutes(): void
    {
        if (!(bool) config('reverseshield.enabled', true)) {
            return;
        }

        $prefix = (string) config('reverseshield.decoy_route_prefix', 'reverseshield-decoy/v1');
        $prefix = trim($prefix, '/');
        if ($prefix === '') {
            return;
        }

        $names = ['users', 'config', 'backup', 'tokens', 'export'];
        foreach ($names as $name) {
            Route::match(['get', 'post'], $prefix . '/' . $name, DecoyController::class);
        }
    }

    /**
     * @reverseshieldHoneypot — one-tag drop into any Blade form.
     */
    private function registerBladeDirective(): void
    {
        Blade::directive('reverseshieldHoneypot', function () {
            return '<?php echo \\' . HoneypotFieldName::class . '::htmlField(); ?>';
        });
    }

    /**
     * Push our middleware onto the global HTTP kernel stack unless the user
     * opted out via config. Works for both Laravel 10 and 11 — both expose
     * pushMiddleware() on the HTTP Kernel contract.
     */
    private function maybeAutoRegisterGlobally(Kernel $kernel): void
    {
        if (!(bool) config('reverseshield.enabled', true)) {
            return;
        }
        if (!(bool) config('reverseshield.auto_register', true)) {
            return;
        }
        if (method_exists($kernel, 'pushMiddleware')) {
            $kernel->pushMiddleware(ReverseShieldMiddleware::class);
        }
    }
}
