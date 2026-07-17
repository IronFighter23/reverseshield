<?php

declare(strict_types=1);

namespace ReverseShield\Laravel\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use ReverseShield\Laravel\Services\EventReporter;
use Throwable;

/**
 * Single-action controller for the decoy honeypot routes.
 *
 * Any hit fires a `honeypot_triggered` event server-side and returns a bland
 * empty response so the scraper doesn't get a signal that it just tripped a
 * tripwire. The response looks like an empty collection from a real endpoint.
 */
final class DecoyController
{
    public function __construct(
        private readonly EventReporter $reporter,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        try {
            $this->reporter->send('honeypot_triggered', -80, [
                'kind' => 'decoy_route',
                'route' => '/' . ltrim($request->path(), '/'),
                'method' => $request->method(),
            ]);
        } catch (Throwable $e) {
            // fail-open — even the reporter failing must not change the response
            if (function_exists('report')) {
                try {
                    report($e);
                } catch (Throwable) {
                    // last resort
                }
            }
        }

        return response()->json(['data' => []]);
    }
}
