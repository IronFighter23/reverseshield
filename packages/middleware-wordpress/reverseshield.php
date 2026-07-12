<?php
/**
 * Plugin Name:       ReverseShield
 * Plugin URI:        https://github.com/IronFighter23/reverseshield
 * Description:       Bot & scraper defense — injects the ReverseShield browser agent, serves honeypot decoy routes, and monitors rate limits. Fail-open by design.
 * Version:           0.1.0
 * Requires at least: 5.0
 * Requires PHP:      7.4
 * Author:            ReverseShield
 * License:           see LICENSE at the ReverseShield repo root
 * Text Domain:       reverseshield
 *
 * ---------------------------------------------------------------------------
 * DESIGN NOTES FOR MAINTAINERS
 * ---------------------------------------------------------------------------
 *
 * FAIL-OPEN is the top-line design constraint. Every hook is wrapped in
 * try { ... } catch (Throwable $e) {}. If any code path fails for any reason
 * — network timeout, DB unavailable, plugin conflict, an operator typo in
 * wp-config.php — the WordPress request continues to render as if this plugin
 * were not installed. A security tool must never take down the site it protects.
 *
 * Configuration lives in wp-config.php constants only. There is no admin UI.
 * That eliminates a whole class of attack surface (option-table poisoning,
 * settings-page XSS/CSRF) and means an attacker who compromises WP admin still
 * cannot disable or reconfigure this plugin without filesystem access.
 *
 * Rate limiting is intentionally asymmetric:
 *   * Login is ENFORCED (429 after N failed attempts). Brute-force login is
 *     the single highest-value target on a WP site; the default threshold is
 *     conservative enough that no legitimate user ever hits it.
 *   * REST API is MONITORED (event fires, request continues). The false-
 *     positive cost of blocking a legitimate integration is too high for v1;
 *     the scoring engine (Phase 2/3) decides what to do with those events.
 *
 * Honeypot field names are DERIVED from the per-site UUID (SPEC §8 guardrail),
 * never hardcoded. Different every install; no static allowlist for scrapers.
 * ---------------------------------------------------------------------------
 */

if (!defined('ABSPATH')) {
    exit;
}

// ---------------------------------------------------------------------------
// Configuration constants. Every one may be overridden in wp-config.php.
// The plugin does nothing (silently) if SITE_ID or ENDPOINT are not set.
// ---------------------------------------------------------------------------

if (!defined('REVERSESHIELD_ENABLE')) {
    define('REVERSESHIELD_ENABLE', true);
}
if (!defined('REVERSESHIELD_SITE_ID')) {
    define('REVERSESHIELD_SITE_ID', '');
}
if (!defined('REVERSESHIELD_ENDPOINT')) {
    define('REVERSESHIELD_ENDPOINT', '');
}
if (!defined('REVERSESHIELD_TIMEOUT_MS')) {
    define('REVERSESHIELD_TIMEOUT_MS', 200);
}
if (!defined('REVERSESHIELD_RATE_LOGIN_MAX')) {
    define('REVERSESHIELD_RATE_LOGIN_MAX', 5);
}
if (!defined('REVERSESHIELD_RATE_LOGIN_WINDOW')) {
    define('REVERSESHIELD_RATE_LOGIN_WINDOW', 300);
}
if (!defined('REVERSESHIELD_RATE_REST_MAX')) {
    define('REVERSESHIELD_RATE_REST_MAX', 120);
}
if (!defined('REVERSESHIELD_RATE_REST_WINDOW')) {
    define('REVERSESHIELD_RATE_REST_WINDOW', 60);
}
if (!defined('REVERSESHIELD_BLOCK_HONEYPOT')) {
    define('REVERSESHIELD_BLOCK_HONEYPOT', true);
}
if (!defined('REVERSESHIELD_DECOY_NAMESPACE')) {
    define('REVERSESHIELD_DECOY_NAMESPACE', 'reverseshield-decoy/v1');
}

/**
 * Main plugin class. Instantiated once on plugins_loaded.
 */
final class ReverseShield_Plugin {

    /** @var string */
    private $site_id;

    /** @var string */
    private $endpoint;

    /** @var float seconds */
    private $timeout_seconds;

    /** @var bool */
    private $enabled;

    public function __construct() {
        try {
            $this->enabled = (bool) REVERSESHIELD_ENABLE;
            $this->site_id = (string) REVERSESHIELD_SITE_ID;
            $this->endpoint = rtrim((string) REVERSESHIELD_ENDPOINT, '/');
            $this->timeout_seconds = max(0.05, ((int) REVERSESHIELD_TIMEOUT_MS) / 1000.0);

            if (!$this->enabled) {
                return;
            }
            if ($this->site_id === '' || $this->endpoint === '') {
                // Log once via error_log so operators know why we're a no-op.
                error_log('[ReverseShield] plugin loaded but REVERSESHIELD_SITE_ID or REVERSESHIELD_ENDPOINT not set in wp-config.php; the plugin will do nothing.');
                return;
            }

            // Frontend injection: agent snippet + honeypot form fields.
            add_action('wp_head', array($this, 'inject_snippet'), 5);
            add_action('comment_form_after_fields', array($this, 'inject_comment_honeypot'));
            add_action('comment_form_logged_in_after', array($this, 'inject_comment_honeypot'));
            add_action('login_form', array($this, 'inject_login_honeypot'));

            // Server-side honeypot detection: check submitted forms.
            add_action('pre_comment_on_post', array($this, 'check_comment_honeypot'), 5);

            // Decoy REST routes.
            add_action('rest_api_init', array($this, 'register_decoy_routes'));

            // Rate limiting. authenticate filter runs BEFORE credentials are checked;
            // wp_login_failed action increments the counter after a failed attempt.
            add_filter('authenticate', array($this, 'check_login_rate_limit'), 5, 3);
            add_action('wp_login_failed', array($this, 'on_login_failed'), 10, 1);

            // REST API monitoring — detect only, do not block. Priority 5 to run early.
            add_action('rest_api_init', array($this, 'monitor_rest_rate'), 5);
        } catch (Throwable $e) {
            // Absolute last resort — even the constructor is fail-open.
            error_log('[ReverseShield] init error: ' . $e->getMessage());
        }
    }

    // ---------------------------------------------------------------------
    // Snippet injection
    // ---------------------------------------------------------------------

    /**
     * Emit the ESM agent snippet into the frontend <head>. Skipped on admin,
     * REST, AJAX, and feed contexts — none of those render user-facing HTML
     * where the browser agent should run.
     */
    public function inject_snippet() {
        try {
            if (is_admin()) {
                return;
            }
            if (defined('REST_REQUEST') && REST_REQUEST) {
                return;
            }
            if (defined('DOING_AJAX') && DOING_AJAX) {
                return;
            }
            if (function_exists('is_feed') && is_feed()) {
                return;
            }

            $endpoint = esc_url($this->endpoint);
            $site_id = esc_js($this->site_id);
            $endpoint_js = esc_js($this->endpoint);

            echo "<!-- ReverseShield agent -->\n";
            echo '<script type="module">' . "\n";
            echo '  import { init } from "' . $endpoint . '/agent.js";' . "\n";
            echo '  init({ siteId: "' . $site_id . '", endpoint: "' . $endpoint_js . '" });' . "\n";
            echo "</script>\n";
        } catch (Throwable $e) {
            // fail-open
        }
    }

    // ---------------------------------------------------------------------
    // Honeypot form fields (server-injected)
    // ---------------------------------------------------------------------

    /**
     * Derive a per-site honeypot field name so scrapers can't build a static
     * allowlist (SPEC §8 guardrail). Different per install; stable within an
     * install so submitted forms can be checked against the same name.
     *
     * @return string
     */
    private function get_honeypot_field_name() {
        $seed = substr(hash('sha256', $this->site_id . '::honeypot'), 0, 8);
        return 'email_alt_' . $seed;
    }

    /**
     * Render a visually-hidden text input inside comment forms. Real users
     * never see or fill this; bots that autofill every field do.
     */
    public function inject_comment_honeypot() {
        $this->render_honeypot_field();
    }

    public function inject_login_honeypot() {
        $this->render_honeypot_field();
    }

    private function render_honeypot_field() {
        try {
            $name = $this->get_honeypot_field_name();
            // display:none + tabindex=-1 + aria-hidden + autocomplete=off. A real
            // user cannot focus this or have their browser autofill it.
            echo '<p style="position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden;" aria-hidden="true">';
            echo '<label>' . esc_html__('Leave this field empty', 'reverseshield') . '</label>';
            echo '<input type="text" name="' . esc_attr($name) . '" value="" tabindex="-1" autocomplete="off">';
            echo '</p>';
        } catch (Throwable $e) {
            // fail-open
        }
    }

    /**
     * On comment submission, check the honeypot field. If filled, fire the
     * event and (optionally) block with a 403.
     *
     * @param int $post_id
     */
    public function check_comment_honeypot($post_id) {
        try {
            $name = $this->get_honeypot_field_name();
            if (!isset($_POST[$name])) {
                return;
            }
            $value = trim((string) $_POST[$name]);
            if ($value === '') {
                return;
            }
            $this->send_event('honeypot_triggered', -80, array(
                'field' => $name,
                'context' => 'comment_form',
                'post_id' => (int) $post_id,
            ));
            if ((bool) REVERSESHIELD_BLOCK_HONEYPOT) {
                // Aligned with fail-open: we blocked a *successfully detected* bad
                // actor, not a legitimate flow that our code broke.
                wp_die(
                    esc_html__('Your submission was flagged as automated.', 'reverseshield'),
                    esc_html__('Submission blocked', 'reverseshield'),
                    array('response' => 403)
                );
            }
        } catch (Throwable $e) {
            // fail-open
        }
    }

    // ---------------------------------------------------------------------
    // Decoy REST routes
    // ---------------------------------------------------------------------

    /**
     * Register a set of routes under our namespace that mimic bait scanners
     * look for. Any hit fires a honeypot_triggered event and returns an
     * innocuous 200 so the scraper doesn't get a signal it just tripped a
     * tripwire.
     */
    public function register_decoy_routes() {
        try {
            $routes = array('users', 'config', 'backup', 'tokens', 'export');
            foreach ($routes as $route) {
                register_rest_route(
                    REVERSESHIELD_DECOY_NAMESPACE,
                    '/' . $route,
                    array(
                        'methods'             => 'GET, POST',
                        'callback'            => array($this, 'handle_decoy_hit'),
                        'permission_callback' => '__return_true',
                    )
                );
            }
        } catch (Throwable $e) {
            // fail-open
        }
    }

    /**
     * Called when a decoy route is hit.
     *
     * @param mixed $request WP_REST_Request in real WP; kept generic for stubs.
     * @return mixed WP_REST_Response
     */
    public function handle_decoy_hit($request) {
        try {
            $route = '';
            $method = '';
            if (is_object($request)) {
                if (method_exists($request, 'get_route')) {
                    $route = (string) $request->get_route();
                }
                if (method_exists($request, 'get_method')) {
                    $method = (string) $request->get_method();
                }
            }
            $this->send_event('honeypot_triggered', -80, array(
                'kind' => 'decoy_route',
                'route' => $route,
                'method' => $method,
            ));
        } catch (Throwable $e) {
            // fail-open — even the event send failing must not change the response.
        }
        // Bland empty payload. Looks like a legitimate empty resource.
        return new WP_REST_Response(array('data' => array()), 200);
    }

    // ---------------------------------------------------------------------
    // Rate limiting: login enforce, REST monitor
    // ---------------------------------------------------------------------

    /**
     * authenticate filter. Runs BEFORE credentials are checked. Returns a
     * WP_Error to short-circuit the login flow.
     *
     * @param mixed  $user
     * @param string $username
     * @param string $password
     * @return mixed
     */
    public function check_login_rate_limit($user, $username, $password) {
        try {
            // Skip when this is a form render, not a submission.
            if ($username === '' && $password === '') {
                return $user;
            }
            $ip = $this->get_client_ip();
            if ($ip === '') {
                return $user;
            }
            $key = 'rs_rl_login_' . md5($ip);
            $count = get_transient($key);
            $count = ($count === false) ? 0 : (int) $count;

            if ($count >= (int) REVERSESHIELD_RATE_LOGIN_MAX) {
                $this->send_event('rate_limit_exceeded', -60, array(
                    'rule' => 'login_attempts',
                    'window_seconds' => (int) REVERSESHIELD_RATE_LOGIN_WINDOW,
                    'max' => (int) REVERSESHIELD_RATE_LOGIN_MAX,
                    'count' => $count,
                ));
                return new WP_Error(
                    'rs_rate_limit',
                    sprintf(
                        /* translators: %d: seconds */
                        esc_html__('Too many login attempts. Please try again in %d seconds.', 'reverseshield'),
                        (int) REVERSESHIELD_RATE_LOGIN_WINDOW
                    )
                );
            }
        } catch (Throwable $e) {
            // fail-open
        }
        return $user;
    }

    /**
     * Called on any failed login attempt (bad credentials, blocked user, etc).
     * Increments the per-IP counter used by check_login_rate_limit above.
     *
     * @param string $username
     */
    public function on_login_failed($username) {
        try {
            $ip = $this->get_client_ip();
            if ($ip === '') {
                return;
            }
            $key = 'rs_rl_login_' . md5($ip);
            $count = get_transient($key);
            $count = ($count === false) ? 0 : (int) $count;
            set_transient($key, $count + 1, (int) REVERSESHIELD_RATE_LOGIN_WINDOW);
        } catch (Throwable $e) {
            // fail-open
        }
    }

    /**
     * REST API rate monitoring. Fires an event when the threshold is exceeded
     * but does NOT block the request. The scoring/response engine (v2) decides
     * what to do.
     */
    public function monitor_rest_rate() {
        try {
            $ip = $this->get_client_ip();
            $session = $this->get_session_id();
            if ($ip === '' && $session === '') {
                return;
            }
            $window = (int) REVERSESHIELD_RATE_REST_WINDOW;
            $max = (int) REVERSESHIELD_RATE_REST_MAX;

            $ip_key = 'rs_rl_rest_ip_' . md5($ip);
            $ses_key = 'rs_rl_rest_ses_' . md5($session);

            $ip_count = get_transient($ip_key);
            $ip_count = ($ip_count === false) ? 0 : (int) $ip_count;
            $ses_count = get_transient($ses_key);
            $ses_count = ($ses_count === false) ? 0 : (int) $ses_count;

            set_transient($ip_key, $ip_count + 1, $window);
            set_transient($ses_key, $ses_count + 1, $window);

            if (($ip_count + 1) > $max || ($ses_count + 1) > $max) {
                $this->send_event('rate_limit_exceeded', -40, array(
                    'rule' => 'rest_api',
                    'window_seconds' => $window,
                    'max' => $max,
                    'ip_count' => $ip_count + 1,
                    'session_count' => $ses_count + 1,
                ));
            }
        } catch (Throwable $e) {
            // fail-open
        }
    }

    // ---------------------------------------------------------------------
    // Reporting API client
    // ---------------------------------------------------------------------

    /**
     * Send an event to the reporting API. Fire-and-forget with a hard timeout.
     * Silent on failure. Payload matches SPEC §3.1.
     *
     * @param string $type         one of the SPEC §3.1 event types
     * @param int    $score_delta  negative integer (reduces trust)
     * @param array  $details      arbitrary JSON-encodable object
     */
    private function send_event($type, $score_delta, $details) {
        try {
            $payload = array(
                'event_id' => wp_generate_uuid4(),
                'site_id' => $this->site_id,
                'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
                'source' => 'server',
                'session_id' => $this->get_session_id(),
                'type' => (string) $type,
                'score_delta' => (int) $score_delta,
                'details' => is_array($details) ? $details : array(),
                // Server API computes the real ip_hash from REMOTE_ADDR and refuses to
                // trust any value we send here anyway. Sending null is the honest thing.
                'ip_hash' => null,
                'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '',
                'asn' => null,
            );

            $body = wp_json_encode($payload);
            if ($body === false || $body === null) {
                return;
            }

            wp_remote_post(
                $this->endpoint . '/api/v1/events',
                array(
                    'timeout' => $this->timeout_seconds,
                    'blocking' => false, // fire-and-forget
                    'headers' => array('Content-Type' => 'application/json'),
                    'body' => $body,
                    // Dev/local reporting endpoints are typically http:// with no cert;
                    // production installs behind TLS should override via the
                    // 'http_request_args' filter or by pointing at an HTTPS endpoint.
                    'sslverify' => false,
                    'user-agent' => 'ReverseShield-WP/0.1',
                )
            );
        } catch (Throwable $e) {
            // fail-open — the entire purpose of the outer try/catch
        }
    }

    // ---------------------------------------------------------------------
    // Session and IP helpers
    // ---------------------------------------------------------------------

    /**
     * Return the ReverseShield session ID, setting a cookie if we don't have
     * one yet. Falls back to a fresh (non-persisted) UUID if headers are
     * already sent — the event still validates in that case.
     *
     * @return string UUID v4
     */
    private function get_session_id() {
        try {
            if (
                isset($_COOKIE['rs_session'])
                && is_string($_COOKIE['rs_session'])
                && preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $_COOKIE['rs_session'])
            ) {
                return $_COOKIE['rs_session'];
            }
            $sid = wp_generate_uuid4();
            if (!headers_sent()) {
                $path = defined('COOKIEPATH') && COOKIEPATH !== '' ? COOKIEPATH : '/';
                $domain = defined('COOKIE_DOMAIN') && COOKIE_DOMAIN !== '' ? COOKIE_DOMAIN : '';
                @setcookie('rs_session', $sid, time() + 3600, $path, $domain, is_ssl(), true);
            }
            return $sid;
        } catch (Throwable $e) {
            // Return a fresh UUID even on failure so the event still validates.
            return wp_generate_uuid4();
        }
    }

    /**
     * Extract the client IP. Prefers common proxy headers; falls back to
     * REMOTE_ADDR. Validated via filter_var so garbage in headers can't
     * poison the rate-limit key.
     *
     * Note: trusting X-Forwarded-For without a proxy allowlist is spoofable.
     * The only impact here is that a determined attacker can evade our per-IP
     * rate limit by cycling forged headers — they gain no privilege. Acceptable
     * v1 trade-off; v2 will read a wp-config.php constant with trusted proxy
     * CIDRs.
     *
     * @return string IP or ''
     */
    private function get_client_ip() {
        try {
            $candidates = array(
                'HTTP_CF_CONNECTING_IP',
                'HTTP_X_REAL_IP',
                'HTTP_X_FORWARDED_FOR',
                'REMOTE_ADDR',
            );
            foreach ($candidates as $key) {
                if (empty($_SERVER[$key])) {
                    continue;
                }
                $value = (string) $_SERVER[$key];
                if (strpos($value, ',') !== false) {
                    $parts = explode(',', $value);
                    $value = trim($parts[0]);
                }
                if (filter_var($value, FILTER_VALIDATE_IP)) {
                    return $value;
                }
            }
        } catch (Throwable $e) {
            // fall through
        }
        return '';
    }
}

// -------------------------------------------------------------------------
// Bootstrap
// -------------------------------------------------------------------------

add_action('plugins_loaded', function () {
    try {
        new ReverseShield_Plugin();
    } catch (Throwable $e) {
        error_log('[ReverseShield] fatal during bootstrap: ' . $e->getMessage());
    }
});
