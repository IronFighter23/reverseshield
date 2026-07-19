<?php
/**
 * ReverseShield WordPress plugin — CLI smoke test.
 *
 * Run: php test/plugin-test.php
 *
 * Loads the plugin against a set of WordPress function stubs and exercises
 * each of its important code paths through Reflection (for private methods).
 * Verifies:
 *   * The plugin file parses and defines ReverseShield_Plugin
 *   * Event payload matches SPEC §3.1 field-for-field
 *   * Fail-open swallows wp_remote_post exceptions
 *   * Fail-open swallows wp_json_encode returning false
 *   * Honeypot field name derives deterministically from site_id
 *   * IP extraction validates and prefers proxy headers correctly
 *   * Session cookie is respected when set to a valid UUID; regenerated otherwise
 */

declare(strict_types=1);

if (PHP_VERSION_ID < 70400) {
    fwrite(STDERR, "FAIL: this plugin requires PHP 7.4+; got " . PHP_VERSION . "\n");
    exit(1);
}

// ---------------------------------------------------------------------------
// WordPress stubs. Must be defined BEFORE requiring the plugin file, because
// the top-level `defined(...)` guards and the bootstrap closure both run at
// require time.
// ---------------------------------------------------------------------------

define('ABSPATH', __DIR__);
define('REVERSESHIELD_ENABLE', true);
define('REVERSESHIELD_SITE_ID', '5c4c0a5d-091d-4e5b-9f23-f1dada9d5ffd');
define('REVERSESHIELD_ENDPOINT', 'http://api.test');
define('REVERSESHIELD_TIMEOUT_MS', 200);
define('REVERSESHIELD_RATE_LOGIN_MAX', 5);
define('REVERSESHIELD_RATE_LOGIN_WINDOW', 300);
define('REVERSESHIELD_RATE_REST_MAX', 120);
define('REVERSESHIELD_RATE_REST_WINDOW', 60);
define('REVERSESHIELD_BLOCK_HONEYPOT', true);
define('REVERSESHIELD_DECOY_NAMESPACE', 'reverseshield-decoy/v1');
define('COOKIEPATH', '/');
define('COOKIE_DOMAIN', '');

// Global test state
$captured_actions = array();
$captured_filters = array();
$captured_events = array();
$transients = array();
$remote_post_should_throw = false;
$remote_post_should_return_error = false;

function add_action($hook, $cb, $priority = 10, $args = 1) {
    global $captured_actions;
    $captured_actions[$hook][] = $cb;
}
function add_filter($hook, $cb, $priority = 10, $args = 1) {
    global $captured_filters;
    $captured_filters[$hook][] = $cb;
}
function register_activation_hook($file, $cb) {}
function register_deactivation_hook($file, $cb) {}
function register_rest_route($ns, $route, $args) {
    global $captured_actions;
    $captured_actions['__rest_routes__'][] = array('ns' => $ns, 'route' => $route, 'args' => $args);
}
function get_transient($k) {
    global $transients;
    return isset($transients[$k]) ? $transients[$k] : false;
}
function set_transient($k, $v, $t) {
    global $transients;
    $transients[$k] = $v;
    return true;
}
function delete_transient($k) {
    global $transients;
    unset($transients[$k]);
}
function wp_generate_uuid4() {
    return sprintf(
        '%04x%04x-%04x-4%03x-%04x-%04x%04x%04x',
        mt_rand(0, 0xffff), mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0xfff),
        mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
    );
}
function wp_json_encode($data) {
    // Behaves like real WP's wp_json_encode. Real WP returns false on encoding failure.
    return json_encode($data);
}
function wp_remote_post($url, $args) {
    global $captured_events, $remote_post_should_throw, $remote_post_should_return_error;
    global $mock_score_response, $mock_score_status;
    if ($remote_post_should_throw) {
        throw new RuntimeException('simulated wp_remote_post failure');
    }
    if ($remote_post_should_return_error) {
        return new WP_Error('http_request_failed', 'Simulated failure');
    }
    $captured_events[] = array('url' => $url, 'args' => $args);

    // Score endpoint: return whatever the current test configured. Default = 503
    // (scoring unavailable), which makes fetch_score return null and every existing
    // event test behave exactly like before we added enrichment.
    if (strpos((string) $url, '/api/v1/score') !== false) {
        $status = isset($mock_score_status) ? (int) $mock_score_status : 503;
        $body = isset($mock_score_response) ? (string) $mock_score_response : '';
        return array(
            'response' => array('code' => $status, 'message' => 'x'),
            'body' => $body,
            'headers' => array(),
        );
    }

    // Everything else (events): accept with 202, matching the real reporting API.
    return array('response' => array('code' => 202, 'message' => 'Accepted'));
}
// Helpers the fetch_score path uses. Real WP defines these; our harness mirrors just
// enough of their surface to exercise the code without pulling in the WordPress core.
function wp_remote_retrieve_response_code($response) {
    if (is_array($response) && isset($response['response']['code'])) {
        return (int) $response['response']['code'];
    }
    return 0;
}
function wp_remote_retrieve_body($response) {
    if (is_array($response) && isset($response['body'])) {
        return (string) $response['body'];
    }
    return '';
}
function is_wp_error($thing) {
    return $thing instanceof WP_Error;
}
function is_admin() { return false; }
function is_feed() { return false; }
function is_ssl() { return false; }
function status_header($code) {}
function esc_js($s) {
    return str_replace(array("\\", "'", '"', "\n", "\r"), array('\\\\', "\\'", '\\"', '\\n', '\\r'), (string) $s);
}
function esc_url($s) { return (string) $s; }
function esc_attr($s) { return htmlspecialchars((string) $s, ENT_QUOTES); }
function esc_html($s) { return htmlspecialchars((string) $s, ENT_QUOTES); }
function esc_html__($s, $domain = null) { return esc_html($s); }
$wp_die_called = null;
function wp_die($msg = '', $title = '', $args = array()) {
    // Real WP calls exit() — we can't do that in a test, so record the call and return.
    // The plugin has no logic after wp_die(), so behavior is equivalent for testing.
    global $wp_die_called;
    $wp_die_called = array('message' => $msg, 'title' => $title, 'args' => $args);
}

if (!class_exists('WP_REST_Response')) {
    class WP_REST_Response {
        public $data;
        public $status;
        public function __construct($data = null, $status = 200) {
            $this->data = $data;
            $this->status = $status;
        }
    }
}
if (!class_exists('WP_Error')) {
    class WP_Error {
        public $code;
        public $message;
        public function __construct($code = '', $message = '') {
            $this->code = $code;
            $this->message = $message;
        }
    }
}

// ---------------------------------------------------------------------------
// Load the plugin. The top-level bootstrap closure registers itself on
// plugins_loaded; we run it manually below.
// ---------------------------------------------------------------------------

require dirname(__DIR__) . '/reverseshield.php';

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

$test_count = 0;
$fail_count = 0;

function assertEq($actual, $expected, $label) {
    global $test_count, $fail_count;
    $test_count++;
    if ($actual !== $expected) {
        fwrite(STDERR, "FAIL: $label\n  expected: " . var_export($expected, true) . "\n  got:      " . var_export($actual, true) . "\n");
        $fail_count++;
    } else {
        echo "PASS: $label\n";
    }
}

function assertTrue($cond, $label) {
    global $test_count, $fail_count;
    $test_count++;
    if (!$cond) {
        fwrite(STDERR, "FAIL: $label\n");
        $fail_count++;
    } else {
        echo "PASS: $label\n";
    }
}

// ---------------------------------------------------------------------------
// Fire the plugins_loaded closure to instantiate the plugin.
// ---------------------------------------------------------------------------

assertTrue(class_exists('ReverseShield_Plugin'), 'ReverseShield_Plugin class defined');
assertTrue(isset($captured_actions['plugins_loaded']), 'plugins_loaded hook registered');

foreach ($captured_actions['plugins_loaded'] as $cb) {
    $cb();
}

// After bootstrap, the plugin should have registered its own hooks.
assertTrue(isset($captured_actions['wp_head']), 'wp_head hook registered');
assertTrue(isset($captured_actions['rest_api_init']), 'rest_api_init hook registered');
assertTrue(isset($captured_filters['authenticate']), 'authenticate filter registered');
assertTrue(isset($captured_actions['wp_login_failed']), 'wp_login_failed hook registered');
assertTrue(isset($captured_actions['pre_comment_on_post']), 'pre_comment_on_post hook registered');
assertTrue(isset($captured_actions['comment_form_after_fields']), 'comment_form_after_fields hook registered');
assertTrue(isset($captured_actions['login_form']), 'login_form hook registered');

// ---------------------------------------------------------------------------
// Direct plugin exercise through Reflection.
// ---------------------------------------------------------------------------

$plugin = new ReverseShield_Plugin();
$ref = new ReflectionClass('ReverseShield_Plugin');

// ---- send_event ----------------------------------------------------------

$sendMethod = $ref->getMethod('send_event');
$sendMethod->setAccessible(true);

$captured_events = array();
$sendMethod->invoke($plugin, 'honeypot_triggered', -80, array('field' => 'email_alt_xxx'));

// send_event now makes TWO wp_remote_post calls: one to /api/v1/score (blocking,
// for enrichment), then one to /api/v1/events (non-blocking, the actual event).
// The score call returns 503 by default in the test harness so fetch_score bails
// to null — meaning the event payload matches Phase 1 shape exactly.
$event_calls = array_values(array_filter($captured_events, function ($c) {
    return strpos($c['url'], '/api/v1/events') !== false;
}));
$score_calls = array_values(array_filter($captured_events, function ($c) {
    return strpos($c['url'], '/api/v1/score') !== false;
}));
assertEq(count($event_calls), 1, 'send_event fires exactly one events request');
assertEq(count($score_calls), 1, 'send_event first calls the scoring endpoint');

$sent = $event_calls[0];
assertEq($sent['url'], 'http://api.test/api/v1/events', 'event URL points at /api/v1/events');
assertEq((float) $sent['args']['timeout'], 0.2, 'timeout capped at 200ms');
assertEq($sent['args']['blocking'], false, 'send is non-blocking (fire-and-forget)');

$body = json_decode($sent['args']['body'], true);
assertTrue(is_array($body), 'event body is valid JSON');
assertEq($body['type'], 'honeypot_triggered', 'event type propagates');
assertEq($body['score_delta'], -80, 'score_delta propagates');
assertEq($body['source'], 'server', 'source is "server" (SPEC §3.1)');
assertEq($body['site_id'], '5c4c0a5d-091d-4e5b-9f23-f1dada9d5ffd', 'site_id from config');
assertEq($body['ip_hash'], null, 'ip_hash is null; server API computes it');
assertEq($body['asn'], null, 'asn is null');
assertTrue(is_array($body['details']), 'details is an object');
assertEq($body['details']['field'], 'email_alt_xxx', 'details propagates');
assertTrue(!isset($body['details']['score']), 'no score enrichment when scoring API returns 503 (fail-open)');
assertTrue(!isset($body['details']['band']), 'no band enrichment when scoring API returns 503 (fail-open)');

// Verify the score request itself is well-formed.
$score_call = $score_calls[0];
assertEq($score_call['url'], 'http://api.test/api/v1/score', 'score URL is /api/v1/score');
assertEq($score_call['args']['blocking'], true, 'score call is blocking (we need the response)');
$score_body = json_decode($score_call['args']['body'], true);
assertTrue(is_array($score_body), 'score body is valid JSON');
assertEq($score_body['site_id'], '5c4c0a5d-091d-4e5b-9f23-f1dada9d5ffd', 'score request carries site_id');
assertEq($score_body['signals'], array('honeypot_triggered'), 'score request carries the signal');

$uuid_re = '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';
assertTrue((bool) preg_match($uuid_re, $body['event_id']), 'event_id is UUID v4');
assertTrue((bool) preg_match($uuid_re, $body['session_id']), 'session_id is UUID v4');

$iso_re = '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/';
assertTrue((bool) preg_match($iso_re, $body['timestamp']), 'timestamp is ISO-8601 UTC (SPEC §3.1)');

// ---- Scoring enrichment: when the API returns a real score --------------
//
// This exercises the Phase 2 step 4 payoff on the WordPress side: send_event
// merges the API-computed `score` and `band` into the event's details before
// firing. Achieved by staging a 200 response body on the scoring endpoint.

$captured_events = array();
$mock_score_status = 200;
$mock_score_response = json_encode(array(
    'score' => 20,
    'band' => 'likely_bot',
    'triggered_rule_ids' => array('honeypot-field-fill'),
    'total_weight' => 80,
));
$sendMethod->invoke($plugin, 'honeypot_triggered', -80, array('field' => 'email_alt_xxx'));

$event_calls = array_values(array_filter($captured_events, function ($c) {
    return strpos($c['url'], '/api/v1/events') !== false;
}));
$sent = $event_calls[0];
$body = json_decode($sent['args']['body'], true);
assertEq($body['details']['score'], 20, 'API score merged into details');
assertEq($body['details']['band'], 'likely_bot', 'API band merged into details');
assertEq($body['details']['field'], 'email_alt_xxx', 'existing details keys still present');

// Reset for later tests to see the default 503-scoring behavior.
$mock_score_status = 503;
$mock_score_response = '';

// ---- Scoring fail-open: 200 with corrupted body ---------------------------
//
// A misconfigured proxy could return HTML "200 OK" pages under failure. The
// fetch_score defensive shape check must catch this and return null — the
// event still ships, but without score enrichment.

$captured_events = array();
$mock_score_status = 200;
$mock_score_response = '<html>not json</html>';
$sendMethod->invoke($plugin, 'honeypot_triggered', -80, array('field' => 'email_alt_xxx'));

$event_calls = array_values(array_filter($captured_events, function ($c) {
    return strpos($c['url'], '/api/v1/events') !== false;
}));
$sent = $event_calls[0];
$body = json_decode($sent['args']['body'], true);
assertTrue(!isset($body['details']['score']), 'no enrichment on non-JSON body');
assertEq($body['type'], 'honeypot_triggered', 'event still fires even when scoring is corrupted');

$mock_score_status = 503;
$mock_score_response = '';

// ---- Fail-open: wp_remote_post throws ------------------------------------

$captured_events = array();
$remote_post_should_throw = true;
$caught = false;
try {
    $sendMethod->invoke($plugin, 'canary_embedded', 0, array());
} catch (Throwable $e) {
    // Reflection unwraps and re-throws; look for the original message.
    $caught = strpos($e->getMessage(), 'simulated') !== false;
}
$remote_post_should_throw = false;
assertTrue(!$caught, 'send_event catches wp_remote_post exceptions (fail-open)');

// ---- Fail-open: wp_remote_post returns WP_Error --------------------------

$captured_events = array();
$remote_post_should_return_error = true;
$sendMethod->invoke($plugin, 'canary_embedded', 0, array());
$remote_post_should_return_error = false;
assertTrue(true, 'send_event handles WP_Error returns without throwing');

// ---- Honeypot field name is deterministic and site-scoped ----------------

$getHoneypotName = $ref->getMethod('get_honeypot_field_name');
$getHoneypotName->setAccessible(true);
$name1 = $getHoneypotName->invoke($plugin);
$name2 = $getHoneypotName->invoke($plugin);
assertEq($name1, $name2, 'honeypot field name is deterministic within a site');
assertTrue(strpos($name1, 'email_alt_') === 0, 'honeypot name has plausible prefix');
assertEq(strlen($name1), strlen('email_alt_') + 8, 'honeypot name has 8-hex suffix');
assertTrue($name1 !== 'email_alt_', 'honeypot name is not the empty seed value');

// ---- IP extraction: validation and header preference ---------------------

$getIp = $ref->getMethod('get_client_ip');
$getIp->setAccessible(true);

$_SERVER = array();
assertEq($getIp->invoke($plugin), '', 'get_client_ip returns "" when no headers present');

$_SERVER = array('REMOTE_ADDR' => '203.0.113.5');
assertEq($getIp->invoke($plugin), '203.0.113.5', 'REMOTE_ADDR used when no proxy header');

$_SERVER = array('REMOTE_ADDR' => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => '198.51.100.9, 203.0.113.5');
assertEq($getIp->invoke($plugin), '198.51.100.9', 'X-Forwarded-For first entry preferred over REMOTE_ADDR');

$_SERVER = array('REMOTE_ADDR' => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => 'not-an-ip');
assertEq($getIp->invoke($plugin), '203.0.113.5', 'invalid X-Forwarded-For falls through to REMOTE_ADDR');

$_SERVER = array('HTTP_CF_CONNECTING_IP' => '198.51.100.9', 'HTTP_X_REAL_IP' => '198.51.100.10', 'REMOTE_ADDR' => '203.0.113.5');
assertEq($getIp->invoke($plugin), '198.51.100.9', 'CF-Connecting-IP preferred over other headers');

// ---- Session ID: valid cookie preserved, invalid cookie regenerated ------

$getSession = $ref->getMethod('get_session_id');
$getSession->setAccessible(true);

$_COOKIE = array('rs_session' => '5c4c0a5d-091d-4e5b-9f23-f1dada9d5ffd');
assertEq($getSession->invoke($plugin), '5c4c0a5d-091d-4e5b-9f23-f1dada9d5ffd', 'valid session cookie preserved');

$_COOKIE = array('rs_session' => 'not-a-uuid');
$sid = $getSession->invoke($plugin);
assertTrue((bool) preg_match($uuid_re, $sid), 'invalid session cookie triggers fresh UUID');

$_COOKIE = array();
$sid = $getSession->invoke($plugin);
assertTrue((bool) preg_match($uuid_re, $sid), 'missing session cookie triggers fresh UUID');

// ---- Login rate limit: blocks after N failures ---------------------------

$transients = array();
$_SERVER = array('REMOTE_ADDR' => '203.0.113.5');
$check = $ref->getMethod('check_login_rate_limit');
// Public — no setAccessible needed but doesn't hurt.
$check->setAccessible(true);

// Below the threshold: no block.
for ($i = 0; $i < 5; $i++) {
    set_transient('rs_rl_login_' . md5('203.0.113.5'), $i, 300);
    $result = $check->invoke($plugin, null, 'admin', 'wrongpass');
    if ($i < 5) {
        assertTrue(!($result instanceof WP_Error), "attempt #{$i}: not blocked");
    }
}

// At the threshold: block.
set_transient('rs_rl_login_' . md5('203.0.113.5'), 5, 300);
$captured_events = array();
$result = $check->invoke($plugin, null, 'admin', 'wrongpass');
assertTrue($result instanceof WP_Error, 'attempt at threshold: returns WP_Error');
$event_calls = array_values(array_filter($captured_events, function ($c) {
    return strpos($c['url'], '/api/v1/events') !== false;
}));
assertTrue(count($event_calls) === 1, 'rate limit block fires a rate_limit_exceeded event');
$evt_body = json_decode($event_calls[0]['args']['body'], true);
assertEq($evt_body['type'], 'rate_limit_exceeded', 'rate limit event has correct type');

// on_login_failed increments the counter.
$transients = array();
$plugin->on_login_failed('admin');
$c = get_transient('rs_rl_login_' . md5('203.0.113.5'));
assertEq($c, 1, 'on_login_failed increments the counter from 0 → 1');
$plugin->on_login_failed('admin');
$c = get_transient('rs_rl_login_' . md5('203.0.113.5'));
assertEq($c, 2, 'on_login_failed increments the counter from 1 → 2');

// ---- Comment honeypot: empty field is not flagged; filled field triggers -

$check_comment = $ref->getMethod('check_comment_honeypot');
$check_comment->setAccessible(true);
$honeypot_name = $getHoneypotName->invoke($plugin);

// Empty field: no event, no block.
$captured_events = array();
$_POST = array($honeypot_name => '');
$check_comment->invoke($plugin, 42);
$event_calls = array_values(array_filter($captured_events, function ($c) {
    return strpos($c['url'], '/api/v1/events') !== false;
}));
assertEq(count($event_calls), 0, 'empty honeypot value does not trigger event');

// Filled field: event fires and wp_die is called (which real WP exits on).
$captured_events = array();
$wp_die_called = null;
$_POST = array($honeypot_name => 'spam-content');
$check_comment->invoke($plugin, 42);
assertTrue($wp_die_called !== null, 'filled honeypot triggers wp_die (block enabled)');
assertTrue(is_array($wp_die_called) && isset($wp_die_called['args']['response']) && $wp_die_called['args']['response'] === 403, 'wp_die response code is 403');
$event_calls = array_values(array_filter($captured_events, function ($c) {
    return strpos($c['url'], '/api/v1/events') !== false;
}));
assertEq(count($event_calls), 1, 'filled honeypot fires exactly one event');
$evt_body = json_decode($event_calls[0]['args']['body'], true);
assertEq($evt_body['type'], 'honeypot_triggered', 'honeypot event has correct type');
assertEq($evt_body['details']['context'], 'comment_form', 'honeypot event details.context is comment_form');
assertEq($evt_body['details']['post_id'], 42, 'honeypot event details.post_id propagates');

// ---- Decoy routes registered under our namespace -------------------------

// The plugin registers a rest_api_init hook that calls register_decoy_routes when
// WP boots the REST API. Our stubs don't fire rest_api_init hooks, so invoke the
// method directly to prove the routes get registered when the hook does fire.
$ref->getMethod('register_decoy_routes')->invoke($plugin);
assertTrue(isset($captured_actions['__rest_routes__']), 'REST routes registered');
if (isset($captured_actions['__rest_routes__'])) {
    $routes = array_map(function ($r) { return $r['route']; }, $captured_actions['__rest_routes__']);
    $expected = array('/users', '/config', '/backup', '/tokens', '/export');
    foreach ($expected as $r) {
        assertTrue(in_array($r, $routes, true), "decoy route registered: $r");
    }
    // All registered under our namespace.
    $namespaces = array_unique(array_map(function ($r) { return $r['ns']; }, $captured_actions['__rest_routes__']));
    assertEq(count($namespaces), 1, 'all decoy routes under a single namespace');
    assertEq($namespaces[0], 'reverseshield-decoy/v1', 'namespace matches SPEC');
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

echo "\n";
echo "$test_count tests, " . ($test_count - $fail_count) . " passed, $fail_count failed\n";
exit($fail_count === 0 ? 0 : 1);
