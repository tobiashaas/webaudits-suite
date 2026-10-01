<?php
/**
 * Plugin Name: WebAudits Suite
 * Plugin URI: https://github.com/tobiashaas/webaudits-suite
 * Description: Security and tracking baseline for any WordPress site: security
 *              headers + nonce-based CSP (report-only → enforce), version-leak
 *              fixes, XML-RPC block, security.txt, consent-gated GTM or GA4,
 *              admin cleanup, account allowlist + security log, forced core
 *              security updates. Self-updating. Tools → WebAudits Suite.
 * Version: 4.0.0
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Author: Tobias Haas
 * Author URI: https://github.com/tobiashaas
 * License: MIT
 * License URI: https://opensource.org/licenses/MIT
 * Update URI: https://github.com/tobiashaas/webaudits-suite
 *
 * 4.0: Usable on any site, not only ours. Runs as mu-plugin or regular plugin
 *      (the updater writes to the running file, the config is looked up in
 *      mu-plugins/, wp-content/ and next to the plugin). Safe first run without
 *      a config: site_url/brand_name fall back to the WordPress settings, no
 *      security.txt without a real contact, comments stay ON by default
 *      (disable_comments is now opt-in). consent_provider 'custom' with
 *      consent_script_attrs for any consent manager. CSP is skipped for logged-in
 *      editors in the editing views of Etch, Bricks, Elementor, Oxygen,
 *      Breakdance, Beaver Builder, Divi and Brizy. 'self_update' => false pins the
 *      version, 'update_repo' points the updater to a fork. Code comments in
 *      English; new security-log details use English keys.
 * 3.6.1: Admin overview, 301-redirects row: PHP parsed "$k→$v" as the variable $k→
 *      (bytes > 0x7F are part of an identifier) → warning, source path missing.
 * 3.6: Etch Security merged in (section 15) — User Guard (domain allowlist,
 *      foreign accounts are neutralised, not deleted), security log with CSV
 *      and forced core security updates. Same options and table as
 *      Etch Security 1.1.1, existing data is kept. As long as the old
 *      etch-security.php is still loaded, the module stays off (admin notice).
 *
 * 3.1: frame_ancestors — foreign origins may embed this site (optionally only
 *      on specific paths). X-Frame-Options cannot express a foreign origin
 *      (ALLOW-FROM is dead), so XFO is omitted on exactly these responses
 *      and a SEPARATE, always-enforced
 *      `Content-Security-Policy: frame-ancestors …` header is sent instead —
 *      even in Report-Only mode, which would enforce nothing.
 *
 * 2.1: Admin/backend module — dashboard cleanup (widgets/welcome panel/
 *      plugin widgets), sortable last-login column, DISALLOW_FILE_EDIT,
 *      generic login error message. Each switchable via config.
 * 2.2: disable_comments switch — comments fully off (frontend, existing ones,
 *      admin menu/admin bar, REST endpoints).
 * 2.6: Settings UI (Tools → WebAudits Suite): operational values (GTM/GA4 ID,
 *      CSP mode, switches) are editable in the admin; the DB option wins over the
 *      file default. New GA4-direct module (gtag) as an alternative to GTM —
 *      mutually exclusive (GTM wins, an admin notice warns about double tracking).
 * 2.7: Bilingual (de/en) — admin UI follows the user language, frontend strings
 *      follow the site locale (webaudits_txt). The overview shows only configured
 *      modules (inactive ones without details are hidden).
 * 3.0: Code/config split — site values live in webaudits-config.php next to it
 *      (define('WEBAUDITS_CONFIG_SITE', array(...))); this file is generic
 *      and kept current by the self-updater from GitHub releases
 *      (github.com/tobiashaas/webaudits-suite — change it THERE + tag a release).
 * 2.4: privacy_cpt — CPT selectable in WP Settings → Privacy (wp_dropdown_pages filter).
 * 2.3: CSP + output buffer are NOT sent in the Etch builder view (?etch=magic)
 *      — otherwise CSP blocks eval + the bridge WebSocket and the builder
 *      won't load. Anonymous visitors are unaffected.
 *
 * INSTALL: adjust the config per site, copy the file to wp-content/mu-plugins/
 * (auto-active). REPLACES the standalone files mu-plugin-security-headers,
 * mu-plugin-csp and separate performance/schema/GTM files — delete the old
 * files, otherwise headers/buffers are doubled!
 * The static layer (compression, asset cache, readme/license/xmlrpc block for
 * Apache) stays in .htaccess (htaccess-hardening.txt).
 */
if (!defined('ABSPATH')) exit;

// ============================================================ CONFIG
// Generic defaults. SITE values do NOT belong here but in the file
// webaudits-config.php in the same folder (template: webaudits-config-sample.php):
//   define('WEBAUDITS_CONFIG_SITE', array('site_url' => ..., ...));
// They override the defaults key by key and survive every
// self-update (which replaces only THIS file).
function webaudits_file_config() {
    static $cfg = null;
    if ($cfg !== null) return $cfg;
    $defaults = array(
        // --- Site ---
        'site_url'          => '',                          // no trailing slash; '' = home_url()
        'brand_name'        => '',                          // schema/display; '' = site title

        // --- Security headers ---
        'hsts_preload'      => false,                       // only after a subdomain audit + www check!
        'csp_mode'          => 'report-only',               // 'report-only' | 'enforce' | 'off'
        // Mode for logged-in administrators (manage_options). 'same' = like csp_mode.
        // 'off' e.g. when an admin tool needs eval on the frontend (ACSS dashboard).
        // Visitors are unaffected; frame-ancestors always stays enforced.
        'csp_admins'        => 'same',                      // 'same' | 'report-only' | 'off'
        // Inline event handlers allowed by hash ('unsafe-hashes' + sha256).
        // Exact handler texts only, no patterns. Default: deferred CSS loading
        // (<link media="print" onload="…">) as used by Borlabs Cookie, Perfmatters and others.
        'csp_handler_hashes' => array("this.media='all';this.onload=null", "this.media='all'", "this.onload=null;this.media='all'"),
        'security_contact'  => '',                          // e.g. 'mailto:security@example.com'; '' = no security.txt route
        'security_expires'  => '2027-01-01T00:00:00.000Z',  // RFC 9116: <= 1 year, renew before then
        'block_xmlrpc'      => true,

        // --- Framing: who may put this site in an iframe? ---
        // Default = nobody except the own origin (X-Frame-Options:
        // SAMEORIGIN + frame-ancestors 'self').
        // 'origins' = additionally allowed foreign origins (scheme + host, no
        // path, no trailing slash). 'paths' = which paths the exception is
        // limited to (no trailing slash, empty array = site-wide).
        // On matching responses X-Frame-Options is DROPPED — the header
        // cannot allow a foreign origin (ALLOW-FROM has no effect in any current
        // browser) and would otherwise block the embedding.
        'frame_ancestors'   => array(
            'origins' => array(),   // e.g. array('https://lms.example.com')
            'paths'   => array(),   // e.g. array('/datenschutz', '/impressum')
        ),

        // --- Foundations ---
        'theme_color'       => '',                          // e.g. '#E30613'; '' = off
        'color_scheme'      => 'light',

        // --- Performance ---
        // img classes that must NEVER load eager/fetchpriority=high (WP's
        // LCP heuristic misfires when the real hero is a canvas).
        'force_lazy_classes' => array(),                    // e.g. array('bignum__media')

        // --- Schema: LocalBusiness from a locations CPT (on one page) ---
        'localbusiness'     => array(
            'enabled'   => false,
            'page'      => 'kontakt',                       // is_page(slug)
            'post_type' => 'standorte',
            'fields'    => array(                            // CPT meta keys
                'street' => 'strasse_nr',
                'zip'    => 'postleitzahl',
                'city'   => 'ort',
                'phone'  => 'telefon',
            ),
            'image'     => '',                              // e.g. og-default.png URL
            // Legal entity, if the site is a brand/sub-brand (Google then maps the
            // addresses to the company profile). Empty = brand_name + site_url.
            'parent'    => array('name' => '', 'url' => ''),
        ),

        // --- Tracking: GTM consent-gated (Pressidium, page_scripts must be ON) ---
        'gtm_id'            => '',                          // 'GTM-XXXXXXX'; '' = off
        // GA4 DIRECTLY via gtag (without GTM). Exclusive with gtm_id — if BOTH are set,
        // GTM wins and GA4-direct stays off (double-tracking lock + notice).
        'ga4_id'            => '',                          // 'G-XXXXXXXXXX'; '' = off
        'consent_category'  => 'analytics',                 // Pressidium category (consent_provider=pressidium only)
        // Consent manager that activates the text/plain scripts after consent:
        //   'pressidium' (default) | 'iubenda' | 'custom' (attributes below)
        //   | 'none' (GTM loads cookieless via Consent Mode)
        // Consent managers that load GTM themselves (Borlabs Cookie, Complianz,
        // Real Cookie Banner, …): leave gtm_id empty instead.
        'consent_provider'  => 'pressidium',
        'iubenda_purposes'  => '4',                         // iubenda purpose ID(s) for measurement (consent_provider=iubenda only)
        // consent_provider=custom: attributes of the inert GTM <script>, e.g. Cookiebot:
        //   array('type' => 'text/plain', 'data-cookieconsent' => 'statistics')
        'consent_script_attrs' => array(),
        // WS Form bridge: pushes an event on wsf-submit-success. 'generate_lead' if
        // every form is a lead; 'wsf_submit' if the container decides by form_id
        // (multi-form sites). '' = bridge off.
        'wsf_bridge_event'  => 'generate_lead',

        // --- Admin/Backend ---
        'admin_cleanup'        => true,   // remove dashboard widgets + welcome panel
        // Additionally remove plugin widgets (remove_meta_box on non-existent
        // IDs is a no-op — the list may be generous):
        'dashboard_remove_extra' => array(
            'seopress-dashboard-widget',           // SEOPress
            'wordfence_activity_report_widget',    // Wordfence
            'woocommerce_dashboard_status',        // WooCommerce
            'woocommerce_dashboard_recent_reviews',
            'wc_admin_dashboard_setup',
            'yoast_db_widget',                     // Yoast (third-party setups)
            'rg_forms_dashboard',                  // Gravity Forms
            'bbp-dashboard-right-now',             // bbPress
        ),
        'last_login_column'    => true,   // user list: "Last login" column (sortable)
        'disable_file_editor'  => true,   // theme/plugin editor in the admin off (DISALLOW_FILE_EDIT)
        'generic_login_errors' => true,   // login does not reveal whether the username exists
        // Comments COMPLETELY off (frontend closed, existing ones hidden, admin menu/
        // admin bar gone, REST endpoints removed). Opt-in since 4.0 — only enable if
        // the site really uses no comments.
        'disable_comments'     => false,

        // --- Privacy policy from a CPT (WP Settings → Privacy natively only allows
        //     `page`). Makes this CPT's posts selectable in the privacy dropdown. ---
        'privacy_cpt'          => '',   // e.g. 'compliance'; '' = module off

        // --- Explicit 301 redirects (old path => new path, each with a slash).
        //     WP's "old slug" redirect doesn't apply to root-based CPTs. ---
        'redirects'            => array(),   // e.g. array('/old/' => '/new/')

        // --- Accounts & security (section 15, "Etch Security" up to 3.5) ---
        // User Guard, security log, forced core security updates. Domains and
        // switches are managed under Tools → WebAudits Suite → Accounts & security.
        'security_module'      => true,

        // --- Self-update ---
        'self_update'          => true,                         // false = pin the version (manual button still works)
        'update_repo'          => 'tobiashaas/webaudits-suite', // GitHub owner/repo; point it to a fork if you maintain one
    );
    webaudits_load_site_config();
    $site = defined('WEBAUDITS_CONFIG_SITE') ? WEBAUDITS_CONFIG_SITE : array();
    $cfg = array_merge($defaults, (array) $site);
    // Fallbacks for a first run without (complete) config: the WordPress settings.
    // Placeholders copied unchanged from the sample count as "not set".
    if (!$cfg['site_url'] || stripos($cfg['site_url'], 'example.com') !== false) $cfg['site_url'] = untrailingslashit(home_url());
    if (!$cfg['brand_name'] || strcasecmp($cfg['brand_name'], 'example') === 0) $cfg['brand_name'] = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);
    if (stripos((string) $cfg['security_contact'], 'example.com') !== false) $cfg['security_contact'] = '';
    return $cfg;
}

/**
 * Loads webaudits-config.php if no config is defined yet. As a must-use plugin
 * WordPress loads the file itself (it sits in mu-plugins/ and sorts before the
 * suite); as a regular plugin the suite looks in wp-content/ and next to itself.
 */
function webaudits_load_site_config() {
    if (defined('WEBAUDITS_CONFIG_SITE')) return;
    foreach (array(WPMU_PLUGIN_DIR, WP_CONTENT_DIR, __DIR__) as $dir) {
        $file = $dir . '/webaudits-config.php';
        if (is_readable($file)) { require_once $file; return; }
    }
}

// These keys are editable in the admin (Tools → WebAudits Suite).
// The DB option `webaudits_suite_options` WINS over the file default;
// everything else deliberately stays file config (versioned in the repo).
const WEBAUDITS_UI_KEYS = array(
    'gtm_id'               => 'text',
    'ga4_id'               => 'text',
    'csp_mode'             => 'select',
    'csp_admins'           => 'select',
    'theme_color'          => 'text',
    'hsts_preload'         => 'bool',
    'block_xmlrpc'         => 'bool',
    'admin_cleanup'        => 'bool',
    'last_login_column'    => 'bool',
    'disable_file_editor'  => 'bool',
    'generic_login_errors' => 'bool',
    'disable_comments'     => 'bool',
);

function webaudits_cfg($key, $default = null) {
    $config = webaudits_file_config();
    $file = array_key_exists($key, $config) ? $config[$key] : $default;
    if (!array_key_exists($key, WEBAUDITS_UI_KEYS)) return $file;
    $opts = get_option('webaudits_suite_options', null);
    if (!is_array($opts) || !array_key_exists($key, $opts)) return $file;
    return WEBAUDITS_UI_KEYS[$key] === 'bool' ? (bool) $opts[$key] : $opts[$key];
}

// Bilingual without the .po machinery: German if the relevant locale is de_*,
// English otherwise. Admin pages follow the USER language, frontend strings
// (e.g. login errors) follow the site locale.
function webaudits_txt($de, $en) {
    $locale = (is_admin() && function_exists('get_user_locale')) ? get_user_locale() : determine_locale();
    return (strpos($locale, 'de') === 0) ? $de : $en;
}

// Page-builder editing views: CSP + output buffer would lock the builder out
// (builders need 'unsafe-eval', e.g. via new Function(), and their own preview
// channels — Etch additionally its bridge WebSocket ws://127.0.0.1:7331/7332).
// For logged-in editors in these views we send NO CSP and skip the buffer.
// Visitors — and anyone adding the query string without being logged in —
// always get the full policy. Query key => required value ('' = any value).
function webaudits_is_builder_view() {
    static $is = null;
    if ($is !== null) return $is;
    $views = apply_filters('webaudits_builder_query_vars', array(
        'etch'              => 'magic',    // Etch
        'bricks'            => 'run',      // Bricks (builder + preview iframe)
        'elementor-preview' => '',         // Elementor preview iframe
        'ct_builder'        => '',         // Oxygen
        'breakdance'        => 'builder',  // Breakdance
        'breakdance_iframe' => '',         // Breakdance preview iframe
        'fl_builder'        => '',         // Beaver Builder
        'et_fb'             => '',         // Divi visual builder
        'brizy-edit'        => '',         // Brizy
        'brizy-edit-iframe' => '',         // Brizy preview iframe
    ));
    $hit = false;
    foreach ((array) $views as $key => $value) {
        if (isset($_GET[$key]) && ($value === '' || $_GET[$key] === $value)) { $hit = true; break; }
    }
    $is = $hit && function_exists('current_user_can') && is_user_logged_in() && current_user_can('edit_posts');
    return $is;
}

// ---------------------------------------------------------------- Framing
/**
 * Foreign origins allowed to embed EXACTLY THIS response.
 * Empty array = nobody (X-Frame-Options: SAMEORIGIN then stays).
 */
function webaudits_frame_ancestor_origins() {
    static $cache = null;
    if ($cache !== null) return $cache;
    $cache = array();
    $fa = webaudits_cfg('frame_ancestors', array());
    if (!is_array($fa)) return $cache;
    $origins = array();
    foreach ((array) (isset($fa['origins']) ? $fa['origins'] : array()) as $o) {
        $o = trim((string) $o);
        // Real origins only: scheme + host, no path, no wildcard.
        if (!preg_match('~^https?://[A-Za-z0-9.\-]+(:\d+)?$~', $o)) continue;
        $origins[] = $o;
    }
    if (!$origins) return $cache;
    $paths = array_filter(array_map(function ($p) {
        return rtrim((string) $p, '/');
    }, (array) (isset($fa['paths']) ? $fa['paths'] : array())), 'strlen');
    if (!$paths) { $cache = $origins; return $cache; }   // site-wide
    $path = rtrim((string) parse_url(isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/', PHP_URL_PATH), '/');
    if (in_array($path, $paths, true)) $cache = $origins;
    return $cache;
}

/** Value of the frame-ancestors directive for this response. */
function webaudits_frame_ancestors_value() {
    $extra = webaudits_frame_ancestor_origins();
    return $extra ? "'self' " . implode(' ', $extra) : "'self'";
}

// ==================================================== 1) XML-RPC fully closed
// xmlrpc.php defines XMLRPC_REQUEST before wp-load.php -> the mu-plugin sees it early.
if (webaudits_cfg('block_xmlrpc') && defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    exit('XML-RPC ist deaktiviert.');
}
if (webaudits_cfg('block_xmlrpc')) {
    add_filter('xmlrpc_enabled', '__return_false');
    add_filter('wp_headers', function ($headers) { unset($headers['X-Pingback']); return $headers; });
    remove_action('wp_head', 'rsd_link');
}

// ==================================================== 2) Response security headers
add_action('send_headers', function () {
    if (headers_sent()) return;
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains' . (webaudits_cfg('hsts_preload') ? '; preload' : ''));
    header('X-Content-Type-Options: nosniff');
    // XFO cannot allow a foreign origin — on responses with allowed foreign
    // ancestors it must be omitted, otherwise it blocks the embedding
    // despite frame-ancestors. Protection there comes from the separate,
    // enforced CSP header further down (priority 1001).
    if (!webaudits_frame_ancestor_origins()) header('X-Frame-Options: SAMEORIGIN');
    // same-origin: full referrer internally (WP partly needs it), none
    // cross-origin — stricter than strict-origin-when-cross-origin, safe
    // as long as no external service needs a referrer from us.
    header('Referrer-Policy: same-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), browsing-topics=()');
    // COEP deliberately NOT set: require-corp would break external embeds (only
    // needed for cross-origin isolation/SharedArrayBuffer).
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    header('X-Permitted-Cross-Domain-Policies: none');
    @header_remove('X-Powered-By');
}, 999);

// ==================================================== 3) Version leaks
remove_action('wp_head', 'wp_generator');
add_filter('the_generator', '__return_empty_string');

// ==================================================== 4) theme-color / color-scheme
add_action('wp_head', function () {
    if (webaudits_cfg('theme_color')) {
        echo '<meta name="theme-color" content="' . esc_attr(webaudits_cfg('theme_color')) . '">' . "\n";
    }
    if (webaudits_cfg('color_scheme')) {
        echo '<meta name="color-scheme" content="' . esc_attr(webaudits_cfg('color_scheme')) . '">' . "\n";
    }
}, 1);

// ==================================================== 5) /.well-known/security.txt
add_action('init', function () {
    if (!webaudits_cfg('security_contact')) return;
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
    if ($path !== '/.well-known/security.txt' && $path !== '/security.txt') return;
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: max-age=86400');
    echo 'Contact: ' . webaudits_cfg('security_contact') . "\n";
    echo 'Expires: ' . webaudits_cfg('security_expires') . "\n";
    echo "Preferred-Languages: de, en\n";
    echo 'Canonical: ' . webaudits_cfg('site_url') . "/.well-known/security.txt\n";
    exit;
});

// ==================================================== 6) CSP (nonce-based, dynamic)
/** Nonce per request (computed once, then constant). */
function webaudits_csp_nonce() {
    static $n = null;
    if ($n === null) $n = base64_encode(random_bytes(16));
    return $n;
}

/** Attach the nonce to enqueued <script src="…">. */
add_filter('script_loader_tag', function ($tag, $handle) {
    if (webaudits_cfg('csp_mode') === 'off' || is_admin()) return $tag;
    if (strpos($tag, ' nonce=') !== false || strpos($tag, '<script') === false) return $tag;
    return preg_replace('/<script\s/', '<script nonce="' . esc_attr(webaudits_csp_nonce()) . '" ', $tag, 1);
}, 11, 2);

/** Nonce on wp_add_inline_script/wp_script output (WP >= 6.3). */
add_filter('wp_inline_script_attributes', function ($attr) {
    if (webaudits_cfg('csp_mode') !== 'off' && !is_admin()) $attr['nonce'] = webaudits_csp_nonce();
    return $attr;
}, 10, 1);
add_filter('wp_script_attributes', function ($attr) {
    if (webaudits_cfg('csp_mode') !== 'off' && !is_admin() && empty($attr['nonce'])) $attr['nonce'] = webaudits_csp_nonce();
    return $attr;
}, 10, 1);

/**
 * Effective CSP mode for this request. For logged-in administrators it can be
 * relaxed via `csp_admins` (never tightened); visitors always get csp_mode.
 */
function webaudits_csp_effective_mode() {
    $mode = webaudits_cfg('csp_mode');
    if ($mode === 'off' || !is_user_logged_in() || !current_user_can('manage_options')) return $mode;
    $admins = webaudits_cfg('csp_admins', 'same');
    if ($admins === 'off') return 'off';
    if ($admins === 'report-only') return 'report-only';
    return $mode;
}

/** Send the CSP header (name depends on the mode). */
add_action('send_headers', function () {
    if (webaudits_csp_effective_mode() === 'off' || is_admin() || headers_sent()) return;
    if (webaudits_is_builder_view()) return;   // builder needs eval + ws bridge
    $n = webaudits_csp_nonce();
    $enforce = webaudits_csp_effective_mode() === 'enforce';
    // Allowed inline handlers as hashes (exactly these texts only; all other on*= stay forbidden).
    $hashes = '';
    foreach ((array) webaudits_cfg('csp_handler_hashes', array()) as $src) {
        if (is_string($src) && $src !== '') $hashes .= " 'sha256-" . base64_encode(hash('sha256', $src, true)) . "'";
    }
    $directives = array(
        "default-src 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        'frame-ancestors ' . webaudits_frame_ancestors_value(),
        "form-action 'self'",
        // Nonce + strict-dynamic is the actual policy (CSP3 browsers then
        // ignore 'unsafe-inline' and https: — pure legacy-browser
        // fallbacks, Google pattern). Every script tag gets the nonce in the
        // output buffer -> external scripts run without maintaining an allowlist.
        "script-src 'self' 'nonce-$n' 'strict-dynamic'" . ($hashes ? " 'unsafe-hashes'$hashes" : '') . " 'unsafe-inline' https:",
        "style-src 'self' 'unsafe-inline'",   // builder inline style="" attributes
        "img-src 'self' data: https:",
        "font-src 'self' data:",
        "connect-src 'self' https:",
        "frame-src 'self' https:",
        "worker-src 'self' blob:",
    );
    // upgrade-insecure-requests only works when enforced; in the Report-Only header
    // Chrome logs a console error for it on every page.
    if ($enforce) $directives[] = 'upgrade-insecure-requests';
    $csp = implode('; ', $directives);
    $name = $enforce ? 'Content-Security-Policy' : 'Content-Security-Policy-Report-Only';
    header("$name: $csp");
}, 1000);

/**
 * frame-ancestors ALWAYS enforced — as a separate header, independent of
 * csp_mode. Reasons: (a) Report-Only enforces nothing, (b) with csp_mode=off
 * there would otherwise be no framing protection at all once XFO is dropped.
 * The second header is intentional: multiple CSP headers are AND-combined.
 * Runs AFTER the main CSP header (1000) so that its replace=true does not
 * overwrite the value set here.
 */
add_action('send_headers', function () {
    if (is_admin() || headers_sent()) return;
    if (webaudits_is_builder_view()) return;
    if (webaudits_csp_effective_mode() === 'enforce') return;   // already included there
    header('Content-Security-Policy: frame-ancestors ' . webaudits_frame_ancestors_value(), false);
}, 1001);

// ==================================================== 7) ONE output buffer:
// (a) image-loading fixes, (b) CSP nonce on ALL script tags (inline + src).
add_action('template_redirect', function () {
    if (is_admin() || webaudits_is_builder_view()) return;
    if (webaudits_cfg('csp_mode') === 'off' && !webaudits_cfg('force_lazy_classes')) return;
    ob_start('webaudits_filter_output');
}, 1);

function webaudits_filter_output($html) {
    // (a) force images wrongly loaded eagerly (WP LCP heuristic) to lazy.
    $lazy = webaudits_cfg('force_lazy_classes', array());
    if ($lazy && stripos($html, '<img') !== false) {
        $html = preg_replace_callback('#<img\b[^>]*>#i', function ($m) use ($lazy) {
            $tag = $m[0];
            $hit = false;
            foreach ($lazy as $cls) {
                if (strpos($tag, $cls) !== false) { $hit = true; break; }
            }
            if (!$hit) return $tag;
            $tag = preg_replace('#\sfetchpriority="[^"]*"#i', '', $tag);
            if (stripos($tag, 'loading=') === false) {
                $tag = preg_replace('#<img\b#i', '<img loading="lazy"', $tag, 1);
            }
            return $tag;
        }, $html);
    }
    // (b) nonce on every script tag (including src/external — the "dynamic" part
    // of the CSP; skip data/template types).
    if (webaudits_cfg('csp_mode') !== 'off' && stripos($html, '<script') !== false) {
        $n = webaudits_csp_nonce();
        $html = preg_replace_callback('#<script\b([^>]*)>#i', function ($m) use ($n) {
            $a = $m[1];
            if (stripos($a, 'nonce=') !== false) return $m[0];
            if (preg_match('#type\s*=\s*["\']?(application/(ld\+)?json|text/(template|html))#i', $a)) return $m[0];
            return '<script nonce="' . $n . '"' . $a . '>';
        }, $html);
        // (c) script preloading (<link rel="preload|modulepreload" as="script">)
        // is also checked against script-src and needs the nonce (e.g. the Borlabs config).
        $html = preg_replace_callback('#<link\b([^>]*)>#i', function ($m) use ($n) {
            $a = $m[1];
            if (stripos($a, 'nonce=') !== false) return $m[0];
            if (!preg_match('#\brel\s*=\s*["\']?(modulepreload|preload)\b#i', $a)) return $m[0];
            if (stripos($a, 'modulepreload') === false && !preg_match('#\bas\s*=\s*["\']?script\b#i', $a)) return $m[0];
            return '<link nonce="' . $n . '"' . $a . '>';
        }, $html);
    }
    return $html;
}

// ==================================================== 8) LocalBusiness schema (CPT-driven)
add_action('wp_head', function () {
    $lb = webaudits_cfg('localbusiness', array());
    if (empty($lb['enabled']) || !is_page($lb['page'])) return;
    $q = new WP_Query(array('post_type' => $lb['post_type'], 'posts_per_page' => -1, 'post_status' => 'publish'));
    if (!$q->posts) return;
    $f = $lb['fields'];
    $site = webaudits_cfg('site_url');
    $brand = webaudits_cfg('brand_name');
    $parent = array('@type' => 'Organization', 'name' => $brand, 'url' => $site);
    if (!empty($lb['parent']['name'])) {
        $parent['name'] = (string) $lb['parent']['name'];
        $parent['url'] = !empty($lb['parent']['url']) ? esc_url_raw($lb['parent']['url']) : '';
        if (!$parent['url']) unset($parent['url']);
    }
    $nodes = array();
    foreach ($q->posts as $p) {
        $street = get_post_meta($p->ID, $f['street'], true);
        $zip    = get_post_meta($p->ID, $f['zip'], true);
        $city   = get_post_meta($p->ID, $f['city'], true);
        $tel    = get_post_meta($p->ID, $f['phone'], true);
        if (!$street || !$zip || !$city) continue;
        $node = array(
            '@type' => 'LocalBusiness',
            '@id' => $site . '/' . $lb['page'] . '/#standort-' . $p->post_name,
            'name' => $brand . ' — Standort ' . $p->post_title,
            'url' => $site . '/' . $lb['page'] . '/',
            'address' => array(
                '@type' => 'PostalAddress',
                'streetAddress' => $street,
                'postalCode' => $zip,
                'addressLocality' => $city,
                'addressCountry' => 'DE',
            ),
            'parentOrganization' => $parent,
        );
        if (!empty($lb['image'])) $node['image'] = $lb['image'];
        if ($tel) $node['telephone'] = '+49' . preg_replace('/\D+/', '', preg_replace('/^0/', '', $tel));
        $nodes[] = $node;
    }
    if (!$nodes) return;
    echo '<script type="application/ld+json">' . wp_json_encode(array('@context' => 'https://schema.org', '@graph' => $nodes), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . '</script>' . "\n";
}, 20);

// ==================================================== 9) GTM consent-gated + WS Form bridge

/** Is Pressidium Cookie Consent active? Relevant for consent_provider=pressidium.
 *  Slug verified against real site data; is_plugin_active is the reliable check. */
function webaudits_pressidium_active() {
    if (!function_exists('is_plugin_active')) require_once ABSPATH . 'wp-admin/includes/plugin.php';
    return is_plugin_active('pressidium-cookie-consent/pressidium-cookie-consent.php');
}

/**
 * Returns the attributes for the consent-gated GTM <script> depending on consent_provider.
 * Returns: array($attrs, $grant).
 *   $attrs === null  -> do not emit (provider not ready, e.g. Pressidium inactive)
 *   $attrs === ''    -> plain <script> (provider=none): loads, but stays cookieless
 *   otherwise        -> '<script '.$attrs.'>' (text/plain, activated by the consent manager)
 */
function webaudits_consent_gate($category) {
    $provider = webaudits_cfg('consent_provider', 'pressidium');
    if ($provider === 'iubenda') {
        $purposes = trim((string) webaudits_cfg('iubenda_purposes', '4'));
        $p = $purposes !== '' ? ' data-iub-purposes="' . esc_attr($purposes) . '"' : '';
        return array('type="text/plain" class="_iub_cs_activate"' . $p, true);
    }
    if ($provider === 'none') {
        return array('', false);
    }
    if ($provider === 'custom') {
        // Attributes from the config. The script must stay inert until consent,
        // so a non-JavaScript type is mandatory — otherwise nothing is emitted.
        $attrs = (array) webaudits_cfg('consent_script_attrs', array());
        $type = isset($attrs['type']) ? strtolower(trim((string) $attrs['type'])) : '';
        if ($type === '' || in_array($type, array('text/javascript', 'application/javascript', 'module'), true)) return array(null, false);
        $out = array();
        foreach ($attrs as $name => $value) {
            if (!preg_match('/^[a-z][a-z0-9_:.-]*$/i', (string) $name)) continue;
            $out[] = $value === true || $value === '' ? $name : $name . '="' . esc_attr((string) $value) . '"';
        }
        return array(implode(' ', $out), true);
    }
    if ($provider !== 'pressidium') return array(null, false);   // unknown value: never load ungated
    // pressidium (default): only if active, otherwise inert
    if (!webaudits_pressidium_active()) return array(null, false);
    return array('type="text/plain" data-cookiecategory="' . esc_attr($category) . '"', true);
}

// Admin warning: a GTM ID is set, but the chosen consent provider is not ready -> GTM is not loaded.
add_action('admin_notices', function () {
    if (!current_user_can('manage_options')) return;
    if (!webaudits_cfg('gtm_id')) return;
    list($attrs) = webaudits_consent_gate(webaudits_cfg('consent_category', 'analytics'));
    if ($attrs !== null) return;
    $provider = (string) webaudits_cfg('consent_provider', 'pressidium');
    if ($provider === 'pressidium') {
        $msg = webaudits_txt(
            'consent_provider = pressidium, aber das Pressidium-Cookie-Consent-Plugin ist nicht aktiv — GTM wird deshalb nicht geladen. Pressidium aktivieren oder einen anderen consent_provider wählen (iubenda, custom, none). Lädt euer Consent-Manager GTM selbst (z. B. Borlabs Cookie), gtm_id leer lassen.',
            'consent_provider = pressidium, but the Pressidium Cookie Consent plugin is not active — GTM is therefore not loaded. Activate Pressidium or choose another consent_provider (iubenda, custom, none). If your consent manager loads GTM itself (e.g. Borlabs Cookie), leave gtm_id empty.'
        );
    } elseif ($provider === 'custom') {
        $msg = webaudits_txt(
            'consent_provider = custom, aber consent_script_attrs enthält keinen inaktiven Typ (z. B. \'type\' => \'text/plain\') — GTM wird deshalb nicht geladen.',
            'consent_provider = custom, but consent_script_attrs has no inert type (e.g. \'type\' => \'text/plain\') — GTM is therefore not loaded.'
        );
    } else {
        $msg = sprintf(webaudits_txt(
            'consent_provider = „%s“ ist unbekannt — GTM wird deshalb nicht geladen. Erlaubt: pressidium, iubenda, custom, none.',
            'consent_provider = "%s" is unknown — GTM is therefore not loaded. Allowed: pressidium, iubenda, custom, none.'
        ), $provider);
    }
    echo '<div class="notice notice-warning"><p><strong>WebAudits Suite:</strong> ' . esc_html($msg) . '</p></div>';
});

// Consent Mode v2 defaults — always, BEFORE GTM (stores nothing, GDPR-safe).
add_action('wp_head', function () {
    if (!webaudits_cfg('gtm_id') && !webaudits_cfg('ga4_id')) return;
    ?>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}
gtag('consent','default',{ad_storage:'denied',ad_user_data:'denied',ad_personalization:'denied',analytics_storage:'denied',wait_for_update:500});</script>
    <?php
}, 4);

// GTM loader — consent-gated depending on consent_provider:
//  - pressidium: <script type="text/plain" data-cookiecategory> (Pressidium flips it after consent).
//    Only if Pressidium is active, otherwise inert (no dead script) + admin warning.
//  - iubenda:    <script type="text/plain" class="_iub_cs_activate"> (iubenda activates it after consent).
//  - none:       plain <script> without a consent grant -> GTM loads but stays cookieless (Consent Mode denied).
// No noscript iframe (it would fire before consent).
add_action('wp_head', function () {
    if (!webaudits_cfg('gtm_id')) return;
    $id  = esc_js(webaudits_cfg('gtm_id'));
    $cat = webaudits_cfg('consent_category', 'analytics');
    list($attrs, $grant) = webaudits_consent_gate($cat);
    if ($attrs === null) return; // provider selected but not ready (e.g. Pressidium inactive)
    $loader = "(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src='https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);})(window,document,'script','dataLayer','" . $id . "');";
    if ($attrs === '') {
        echo "<script>\n" . $loader . "\n</script>\n";
    } else {
        echo '<script ' . $attrs . ">\ngtag('consent','update',{analytics_storage:'granted'});\n" . $loader . "\n</script>\n";
    }
}, 5);

// ==================================================== 9b) GA4 direct (gtag) — alternative to GTM
// Runs ONLY without a GTM container (otherwise every page counts twice — GTM wins).
// Consent Mode v2: the defaults above (priority 4) come BEFORE this loader; GA4
// runs cookieless until the consent manager reports analytics_storage granted.
add_action('wp_head', function () {
    if (!webaudits_cfg('ga4_id') || webaudits_cfg('gtm_id') || is_admin() || is_user_logged_in()) return;
    $id = webaudits_cfg('ga4_id');
    if (!preg_match('/^G-[A-Z0-9]+$/', $id)) return;
    echo '<script async src="https://www.googletagmanager.com/gtag/js?id=' . esc_attr($id) . '"></script>' . "
";
    echo "<script>gtag('js',new Date());gtag('config','" . esc_js($id) . "');</script>
";
}, 6);

// Make the double-tracking lock visible: both IDs set -> warning in the admin.
add_action('admin_notices', function () {
    if (!current_user_can('manage_options')) return;
    if (webaudits_cfg('gtm_id') && webaudits_cfg('ga4_id')) {
        echo '<div class="notice notice-warning"><p><strong>WebAudits Suite:</strong> ' . esc_html(webaudits_txt(
            'GTM-Container UND GA4-Mess-ID sind konfiguriert — GA4-direkt ist deshalb deaktiviert (Doppel-Tracking-Sperre). GA4 im GTM-Container konfigurieren oder eine der IDs leeren (Werkzeuge → WebAudits Suite).',
            'Both a GTM container AND a GA4 measurement ID are configured — direct GA4 is therefore disabled (double-tracking guard). Configure GA4 inside the GTM container or clear one of the IDs (Tools → WebAudits Suite).'
        )) . '</p></div>';
    }
});

// WS Form bridge: official document event `wsf-submit-success` (WS Form docs).
add_action('wp_footer', function () {
    if (!webaudits_cfg('gtm_id') || !webaudits_cfg('wsf_bridge_event')) return;
    $event = esc_js(webaudits_cfg('wsf_bridge_event'));
    ?>
<script>document.addEventListener('wsf-submit-success',function(e){var d=(e&&e.detail)||{};window.dataLayer=window.dataLayer||[];window.dataLayer.push({event:'<?php echo $event; ?>',form_id:String(d.form_id||d.id||''),page_location:location.href});});</script>
    <?php
}, 20);

// ==================================================== 10) Admin/backend cleanup
// File editor off (security: no code editing via a compromised admin session).
if (webaudits_cfg('disable_file_editor') && !defined('DISALLOW_FILE_EDIT')) {
    define('DISALLOW_FILE_EDIT', true);
}

// Obscure login errors (no username-enumeration hint).
if (webaudits_cfg('generic_login_errors')) {
    add_filter('login_errors', function () {
        return webaudits_txt(
            'Anmeldung fehlgeschlagen: Benutzername oder Passwort ist nicht korrekt.',
            'Login failed: username or password is incorrect.'
        );
    });
}

// Clean up the dashboard: default widgets, welcome panel, plugin widgets.
add_action('wp_dashboard_setup', function () {
    if (!webaudits_cfg('admin_cleanup')) return;
    $widgets = array(
        'normal' => array(
            'dashboard_activity', 'dashboard_right_now', 'dashboard_recent_comments',
            'dashboard_incoming_links', 'dashboard_plugins',
            'dashboard_site_health', 'health_check_status', 'network_dashboard_right_now',
        ),
        'side' => array(
            'dashboard_primary', 'dashboard_quick_press',
            'dashboard_recent_drafts', 'dashboard_secondary',
        ),
        'high' => array('dashboard_browser_nag', 'dashboard_php_nag'),
    );
    foreach ($widgets as $context => $ids) {
        foreach ($ids as $id) remove_meta_box($id, 'dashboard', $context);
    }
    foreach (webaudits_cfg('dashboard_remove_extra', array()) as $id) {
        remove_meta_box($id, 'dashboard', 'normal');
        remove_meta_box($id, 'dashboard', 'side');
    }
    remove_action('welcome_panel', 'wp_welcome_panel');
}, 999);

// Visual leftovers (empty containers, community events footer).
add_action('admin_head', function () {
    if (!webaudits_cfg('admin_cleanup')) return;
    echo '<style>#dashboard-widgets .empty-container,.dashboard-post-browser,.community-events-footer{display:none !important;}</style>';
}, 100);

// User list: sortable "Last login" column.
if (webaudits_cfg('last_login_column')) {
    add_action('wp_login', function ($user_login, $user) {
        update_user_meta($user->ID, 'last_login', time());
    }, 10, 2);
    add_filter('manage_users_columns', function ($columns) {
        $columns['last_login'] = webaudits_txt('Letzter Login', 'Last login');
        return $columns;
    });
    add_filter('manage_users_custom_column', function ($value, $column, $user_id) {
        if ($column !== 'last_login') return $value;
        $ts = (int) get_user_meta($user_id, 'last_login', true);
        // wp_date = site timezone (date() would be UTC).
        return $ts ? wp_date('d.m.Y H:i', $ts) : '—';
    }, 10, 3);
    add_filter('manage_users_sortable_columns', function ($columns) {
        $columns['last_login'] = 'last_login';
        return $columns;
    });
    add_action('pre_get_users', function ($query) {
        if (!is_admin() || ($_GET['orderby'] ?? '') !== 'last_login') return;
        // OR meta_query so users WITHOUT last_login don't drop out of the
        // list when sorting (the classic meta_key approach filters them out).
        $query->set('meta_query', array(
            'relation' => 'OR',
            'last_login_clause' => array('key' => 'last_login', 'compare' => 'EXISTS', 'type' => 'NUMERIC'),
            array('key' => 'last_login', 'compare' => 'NOT EXISTS'),
        ));
        $query->set('orderby', array('last_login_clause' => strtoupper($_GET['order'] ?? 'DESC') === 'ASC' ? 'ASC' : 'DESC'));
    });
}

// ==================================================== 11) Comments completely off
if (webaudits_cfg('disable_comments')) {
    // Remove support from all post types + close everywhere.
    add_action('init', function () {
        foreach (get_post_types() as $pt) {
            if (post_type_supports($pt, 'comments')) {
                remove_post_type_support($pt, 'comments');
                remove_post_type_support($pt, 'trackbacks');
            }
        }
    }, 100);
    add_filter('comments_open', '__return_false', 20);
    add_filter('pings_open', '__return_false', 20);
    // Never output existing comments anywhere.
    add_filter('comments_array', '__return_empty_array', 20);
    // Comment feed links out of the <head> (feed_links + feed_links_extra).
    add_filter('feed_links_show_comments_feed', '__return_false');
    add_filter('feed_links_extra_show_post_comments_feed', '__return_false');
    // Admin: menu item gone, comments page redirected, admin bar bubble gone.
    add_action('admin_menu', function () { remove_menu_page('edit-comments.php'); });
    add_action('admin_init', function () {
        global $pagenow;
        if ($pagenow === 'edit-comments.php') { wp_safe_redirect(admin_url()); exit; }
    });
    add_action('admin_bar_menu', function ($bar) { $bar->remove_node('comments'); }, 999);
    // Remove REST endpoints (otherwise comments stay readable via the API).
    add_filter('rest_endpoints', function ($endpoints) {
        unset($endpoints['/wp/v2/comments'], $endpoints['/wp/v2/comments/(?P<id>[\d]+)']);
        return $endpoints;
    });
}

// ==================================================== 11b) Explicit 301 redirects
add_action('template_redirect', function () {
    $map = webaudits_cfg('redirects', array());
    if (!$map) return;
    $path = untrailingslashit(parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH));
    foreach ($map as $from => $to) {
        if (untrailingslashit($from) === $path) {
            wp_safe_redirect(home_url($to), 301);
            exit;
        }
    }
}, 0);

// ==================================================== 12) Privacy policy from a CPT
// WP Settings → Privacy builds the page dropdown with wp_dropdown_pages()
// and lists only `page`. We append the CPT posts as <option>s — on save
// WP stores `wp_page_for_privacy_policy` = selected ID (without a
// post_type check), and get_privacy_policy_url() works for any post type.
add_filter('wp_dropdown_pages', function ($html, $args) {
    $cpt = webaudits_cfg('privacy_cpt');
    if (!$cpt || !is_admin()) return $html;
    if (($args['name'] ?? '') !== 'page_for_privacy_policy') return $html;
    $selected = (int) get_option('wp_page_for_privacy_policy');
    $posts = get_posts(array('post_type' => $cpt, 'numberposts' => -1, 'post_status' => 'publish', 'orderby' => 'title', 'order' => 'ASC'));
    if (!$posts) return $html;
    $opts = '';
    foreach ($posts as $p) {
        $opts .= '<option value="' . (int) $p->ID . '" ' . selected($selected, $p->ID, false) . '>'
              . esc_html($p->post_title) . ' — ' . esc_html($cpt) . '</option>';
    }
    return preg_replace('#</select>#', $opts . '</select>', $html, 1);
}, 10, 2);

// ==================================================== 14) Self-update (GitHub releases)
// Canonical repo (public, no token needed). One release = one tag vX.Y.Z;
// the cron compares twice daily and replaces ONLY webaudits-suite.php — the
// site config (webaudits-config.php) and the DB option stay untouched.
const WEBAUDITS_SUITE_VERSION = '4.0.0';
const WEBAUDITS_SUITE_REPO = 'tobiashaas/webaudits-suite';

/** Update source: 'update_repo' from the config (owner/repo), otherwise the canonical repo. */
function webaudits_update_repo() {
    $repo = trim((string) webaudits_cfg('update_repo', WEBAUDITS_SUITE_REPO), " /");
    return preg_match('#^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$#', $repo) ? $repo : WEBAUDITS_SUITE_REPO;
}

add_action('init', function () {
    $scheduled = wp_next_scheduled('webaudits_update_check');
    if (!webaudits_cfg('self_update', true)) {
        if ($scheduled) wp_clear_scheduled_hook('webaudits_update_check');   // pinned: no automatic checks
        return;
    }
    if (!$scheduled) wp_schedule_event(time() + HOUR_IN_SECONDS, 'twicedaily', 'webaudits_update_check');
});
add_action('webaudits_update_check', function () {
    if (webaudits_cfg('self_update', true)) webaudits_run_update_check();
});

function webaudits_run_update_check() {
    $status = array('checked_at' => time(), 'current' => WEBAUDITS_SUITE_VERSION, 'error' => '');
    // Version AND code in ONE request from raw.githubusercontent.com.
    //
    // Why not api.github.com/releases/latest: the API is limited to 60
    // requests/hour per IP. On shared hosting all customers share one
    // egress IP, so the quota is practically always used up there —
    // measured on Strato (81.169.144.135) on 2026-07-22: HTTP 403,
    // "remaining: 0". The updater therefore NEVER ran. raw.githubusercontent.com
    // sits on a CDN without this limit (same measurement: HTTP 200).
    //
    // CONTRACT: the main branch is always the latest release version —
    // the version is bumped only at release time, not during work.
    $raw = wp_remote_get('https://raw.githubusercontent.com/' . webaudits_update_repo() . '/main/webaudits-suite.php', array(
        'timeout' => 30,
        'headers' => array('User-Agent' => 'webaudits-suite-updater'),
    ));
    if (is_wp_error($raw) || wp_remote_retrieve_response_code($raw) !== 200) {
        $status['error'] = 'release_check_failed';
        update_option('webaudits_suite_update_status', $status, false);
        return $status;
    }
    $code = wp_remote_retrieve_body($raw);
    $latest = preg_match("/WEBAUDITS_SUITE_VERSION\s*=\s*'([0-9][0-9.]*)'/", $code, $m) ? $m[1] : '';
    $status['latest'] = $latest;
    if (!$latest || version_compare($latest, WEBAUDITS_SUITE_VERSION, '<=')) {
        update_option('webaudits_suite_update_status', $status, false);
        return $status;
    }
    // Validate HARD before replacing anything — a broken
    // mu-plugin file takes down the whole site.
    $valid = $code !== ''
        && strpos($code, '<?php') === 0
        && strlen($code) > 20000
        && strpos($code, "WEBAUDITS_SUITE_VERSION = '" . $latest . "'") !== false
        && substr_count($code, '{') === substr_count($code, '}');
    if ($valid && function_exists('token_get_all')) {
        try { token_get_all($code, TOKEN_PARSE); } catch (\ParseError $e) { $valid = false; }
    }
    if (!$valid) {
        $status['error'] = 'download_invalid';
        update_option('webaudits_suite_update_status', $status, false);
        return $status;
    }
    // Replace the file that is actually running — mu-plugins/ or plugins/webaudits-suite/.
    // (Until 3.6 this was hard-wired to mu-plugins/, which would have dropped a second
    // copy there on regular-plugin installs.)
    $file = __FILE__;
    if (@file_put_contents($file . '.new', $code) === false || !@copy($file, $file . '.bak') || !@rename($file . '.new', $file)) {
        $status['error'] = 'write_failed';
        update_option('webaudits_suite_update_status', $status, false);
        return $status;
    }
    if (function_exists('opcache_invalidate')) @opcache_invalidate($file, true);
    $status['updated_to'] = $latest;
    $status['updated_at'] = time();
    update_option('webaudits_suite_update_status', $status, false);
    return $status;
}

// ==================================================== 13) Admin overview (Tools)
add_action('admin_menu', function () {
    add_management_page('WebAudits Suite', 'WebAudits Suite', 'manage_options', 'webaudits-suite', 'webaudits_admin_page');
});

function webaudits_admin_page() {
    $T = 'webaudits_txt';
    // Tabs of the security module (section 15): own views, own saving via admin-post.
    $tab = isset($_GET['tab']) ? sanitize_key($_GET['tab']) : 'suite';
    if ($tab === 'konten') $tab = 'accounts';   // slug up to 3.6
    if (in_array($tab, array('accounts', 'log'), true) && WebAudits_Sec::$active) {
        echo '<div class="wrap"><h1>WebAudits Suite</h1>';
        webaudits_admin_tabs($tab);
        if ($tab === 'log') WebAudits_Sec_Admin::render_log(); else WebAudits_Sec_Admin::render_status();
        echo '</div>';
        return;
    }
    // Save (settings UI): only the UI keys, checkboxes explicitly 0/1.
    if (isset($_POST['webaudits_save']) && current_user_can('manage_options') && check_admin_referer('webaudits_suite_save')) {
        $in = array();
        foreach (WEBAUDITS_UI_KEYS as $key => $type) {
            if ($type === 'bool') {
                $in[$key] = empty($_POST[$key]) ? 0 : 1;
            } else {
                $in[$key] = sanitize_text_field(wp_unslash($_POST[$key] ?? ''));
            }
        }
        if ($in['gtm_id'] !== '' && !preg_match('/^GTM-[A-Z0-9]+$/', $in['gtm_id'])) $in['gtm_id'] = '';
        if ($in['ga4_id'] !== '' && !preg_match('/^G-[A-Z0-9]+$/', $in['ga4_id'])) $in['ga4_id'] = '';
        if (!in_array($in['csp_mode'], array('off', 'report-only', 'enforce'), true)) $in['csp_mode'] = 'report-only';
        if (!in_array($in['csp_admins'], array('same', 'report-only', 'off'), true)) $in['csp_admins'] = 'same';
        if ($in['theme_color'] !== '' && !preg_match('/^#[0-9a-fA-F]{3,8}$/', $in['theme_color'])) $in['theme_color'] = '';
        update_option('webaudits_suite_options', $in, false);
        echo '<div class="notice notice-success"><p>' . esc_html($T(
            'Gespeichert — die Werte greifen sofort (DB-Option gewinnt über den Datei-Default).',
            'Saved — the values take effect immediately (DB option overrides the file default).'
        )) . '</p></div>';
    }
    if (isset($_POST['webaudits_check_update']) && current_user_can('manage_options') && check_admin_referer('webaudits_suite_save')) {
        $st = webaudits_run_update_check();
        echo '<div class="notice notice-info"><p>' . esc_html(!empty($st['updated_to'])
            ? $T('Update eingespielt: Version ', 'Update installed: version ') . $st['updated_to'] . $T(' — Seite neu laden.', ' — reload the page.')
            : (!empty($st['error'])
                ? $T('Update-Prüfung fehlgeschlagen: ', 'Update check failed: ') . $st['error']
                : $T('Aktuell — neueste Version ist ', 'Up to date — latest version is ') . (isset($st['latest']) ? $st['latest'] : WEBAUDITS_SUITE_VERSION))) . '</p></div>';
    }
    // The overview shows the EFFECTIVE value (file default + UI override merged).
    $c = webaudits_file_config();
    foreach (WEBAUDITS_UI_KEYS as $key => $type) { $c[$key] = webaudits_cfg($key); }
    $lb = $c['localbusiness'];
    $lb_count = 0;
    if (!empty($lb['enabled'])) {
        $q = new WP_Query(array('post_type' => $lb['post_type'], 'posts_per_page' => -1, 'post_status' => 'publish', 'fields' => 'ids'));
        $lb_count = count($q->posts);
    }
    $on  = '<span style="color:#00a32a;font-weight:600">' . esc_html($T('aktiv', 'active')) . '</span>';
    $off = '<span style="color:#999">' . esc_html($T('aus', 'off')) . '</span>';
    $na  = '—';
    $upd = get_option('webaudits_suite_update_status', array());
    $upd_txt = 'v' . WEBAUDITS_SUITE_VERSION;
    if (!empty($upd['checked_at'])) {
        $upd_txt .= ' · ' . $T('geprüft', 'checked') . ': ' . wp_date('d.m.Y H:i', $upd['checked_at']);
        if (!empty($upd['latest'])) {
            $upd_txt .= ' · ' . (version_compare($upd['latest'], WEBAUDITS_SUITE_VERSION, '>')
                ? '<strong>' . $T('Update verfügbar', 'update available') . ': v' . esc_html($upd['latest']) . '</strong>'
                : $T('aktuell', 'up to date'));
        }
        if (!empty($upd['error'])) $upd_txt .= ' · <span style="color:#d63638">' . esc_html($upd['error']) . '</span>';
    }
    $rows = array(
        array($T('Version / Self-Update', 'Version / self-update'), webaudits_cfg('self_update', true) ? $on : $off,
            $upd_txt . ' — ' . (webaudits_cfg('self_update', true) ? $T('2×/Tag automatisch aus', 'auto twice a day from') : $T('automatisch aus (self_update = false), manuell aus', 'automatic updates off (self_update = false), manual check from'))
            . ' <a href="https://github.com/' . esc_attr(webaudits_update_repo()) . '" target="_blank">github.com/' . esc_html(webaudits_update_repo()) . '</a>'),
        array($T('Security-Header', 'Security headers'), $on,
            'HSTS' . ($c['hsts_preload'] ? ' <strong>+ preload</strong>' : '') . ', nosniff, X-Frame-Options, Referrer-Policy <code>same-origin</code>, Permissions-Policy, COOP/CORP, X-Permitted-Cross-Domain-Policies; '
            . $T('X-Powered-By entfernt. <em>COEP bewusst nicht (bräche externe Embeds).</em>', 'X-Powered-By stripped. <em>Deliberately no COEP (would break external embeds).</em>')),
        array($T('Einbettung (frame-ancestors)', 'Framing (frame-ancestors)'),
            (!empty($c['frame_ancestors']['origins']) ? $on : $off),
            (empty($c['frame_ancestors']['origins'])
                ? $T('Nur eigene Origin — X-Frame-Options: SAMEORIGIN + frame-ancestors <code>\'self\'</code>.',
                     'Own origin only — X-Frame-Options: SAMEORIGIN + frame-ancestors <code>\'self\'</code>.')
                : $T('Zusaetzlich erlaubt: ', 'Additionally allowed: ')
                  . '<code>' . esc_html(implode(' ', (array) $c['frame_ancestors']['origins'])) . '</code>'
                  . (empty($c['frame_ancestors']['paths'])
                      ? ' — ' . $T('site-weit', 'site-wide')
                      : ' — ' . $T('nur auf', 'only on') . ' <code>' . esc_html(implode(', ', (array) $c['frame_ancestors']['paths'])) . '</code>')
                  . '. ' . $T('Auf diesen Antworten entfaellt X-Frame-Options (kennt keine fremde Origin); der Schutz kommt aus einem erzwungenen frame-ancestors-Header.',
                              'X-Frame-Options is omitted on those responses (it cannot express a foreign origin); protection comes from an enforced frame-ancestors header.'))),
        array('Content-Security-Policy', $c['csp_mode'] === 'off' ? $off : $on,
            $T('Modus', 'Mode') . ': <code>' . esc_html($c['csp_mode']) . '</code> — '
            . $T('nonce-basiert + strict-dynamic; jedes script-Tag bekommt die Nonce (Output-Buffer), externe Skripte laufen ohne Allowlist-Pflege.',
                 'nonce-based + strict-dynamic; every script tag receives the nonce (output buffer), external scripts work without allowlist maintenance.')),
        array($T('Versions-Leaks', 'Version leaks'), $on,
            $T('generator-Meta entfernt, X-Powered-By gestrippt. readme.html/license.txt/xmlrpc.php-Block für statische Requests: .htaccess-Ebene.',
               'generator meta removed, X-Powered-By stripped. readme.html/license.txt/xmlrpc.php blocking for static requests: .htaccess layer.')),
        array('XML-RPC', $c['block_xmlrpc'] ? $on : $off, $c['block_xmlrpc']
            ? $T('POST auf xmlrpc.php → 403; Pingback-Header + RSD-Link entfernt.', 'POST to xmlrpc.php → 403; pingback header + RSD link removed.') : $na),
        array('security.txt', $c['security_contact'] ? $on : $off, $c['security_contact']
            ? '<a href="' . esc_url($c['site_url']) . '/.well-known/security.txt" target="_blank">/.well-known/security.txt</a> · Expires: <code>' . esc_html($c['security_expires']) . '</code> ' . $T('(≤ 1 Jahr, rechtzeitig erneuern!)', '(≤ 1 year, renew in time!)') : $na),
        array('theme-color / color-scheme', $c['theme_color'] ? $on : $off, $c['theme_color']
            ? '<code>' . esc_html($c['theme_color']) . '</code> / <code>' . esc_html($c['color_scheme']) . '</code>' : $na),
        array($T('Bild-Loading-Fix', 'Image loading fix'), $c['force_lazy_classes'] ? $on : $off, $c['force_lazy_classes']
            ? $T('Erzwingt <code>loading="lazy"</code> (und entfernt <code>fetchpriority</code>) für: ', 'Forces <code>loading="lazy"</code> (and removes <code>fetchpriority</code>) for: ') . '<code>' . esc_html(implode(', ', $c['force_lazy_classes'])) . '</code>' : $na),
        array($T('LocalBusiness-Schema', 'LocalBusiness schema'), !empty($lb['enabled']) ? $on : $off, !empty($lb['enabled'])
            ? '<strong>' . (int) $lb_count . '</strong> ' . $T('Standort(e) aus CPT', 'location(s) from CPT') . ' <code>' . esc_html($lb['post_type']) . '</code> ' . $T('auf Seite', 'on page') . ' <code>/' . esc_html($lb['page']) . '/</code>' : $na),
        array('Google Tag Manager', $c['gtm_id'] ? $on : $off, $c['gtm_id']
            ? '<code>' . esc_html($c['gtm_id']) . '</code> — ' . $T('consent-gated via', 'consent-gated via') . ' <code>' . esc_html(webaudits_cfg('consent_provider', 'pressidium')) . '</code>'
              . ('pressidium' === webaudits_cfg('consent_provider', 'pressidium')
                    ? ' (' . $T('Kategorie', 'category') . ' <code>' . esc_html($c['consent_category']) . '</code>, ' . $T('benötigt Pressidium <code>page_scripts</code> = an', 'requires Pressidium <code>page_scripts</code> = on') . ')'
                    : ('iubenda' === webaudits_cfg('consent_provider', 'pressidium') ? ' (<code>_iub_cs_activate</code>)'
                    : ('custom' === webaudits_cfg('consent_provider', 'pressidium') ? ' (<code>' . esc_html((string) webaudits_consent_gate('')[0]) . '</code>)'
                    : ' (' . $T('kein Gating — cookielos', 'no gating — cookieless') . ')')))
              . ' ' . $T('(Consent Mode v2, VOR Einwilligung kein Google-Request)', '(Consent Mode v2, no Google request before consent)') : $na),
        array($T('GA4 direkt (gtag)', 'GA4 direct (gtag)'), (!empty($c['ga4_id']) && empty($c['gtm_id'])) ? $on : $off, !empty($c['ga4_id'])
            ? (empty($c['gtm_id'])
                ? '<code>' . esc_html($c['ga4_id']) . '</code> ' . $T('via gtag.js, Consent Mode v2 (Defaults denied). Exklusiv zu GTM.', 'via gtag.js, Consent Mode v2 (defaults denied). Mutually exclusive with GTM.')
                : '<strong>' . esc_html($T('gesperrt', 'locked')) . '</strong> — ' . $T('GTM-Container ist gesetzt (Doppel-Tracking-Sperre). GA4 im GTM konfigurieren.', 'GTM container is set (double-tracking guard). Configure GA4 inside GTM.'))
            : $na),
        array($T('WS-Form-Bridge', 'WS Form bridge'), ($c['gtm_id'] && $c['wsf_bridge_event']) ? $on : $off, ($c['gtm_id'] && $c['wsf_bridge_event'])
            ? $T('Formular-Absendung (<code>wsf-submit-success</code>) → dataLayer-Event', 'Form submission (<code>wsf-submit-success</code>) → dataLayer event') . ' <code>' . esc_html($c['wsf_bridge_event']) . '</code>' : $na),
        array($T('Dashboard-Bereinigung', 'Dashboard cleanup'), !empty($c['admin_cleanup']) ? $on : $off, !empty($c['admin_cleanup'])
            ? $T('Standard-Widgets, Willkommens-Panel und Plugin-Widgets entfernt; leere Container ausgeblendet.', 'Default widgets, welcome panel and plugin widgets removed; empty containers hidden.') : $na),
        array($T('Letzter-Login-Spalte', 'Last-login column'), !empty($c['last_login_column']) ? $on : $off, !empty($c['last_login_column'])
            ? $T('Benutzer-Liste zeigt den letzten Login (sortierbar, Site-Zeitzone).', 'User list shows the last login (sortable, site timezone).') : $na),
        array($T('Datei-Editor', 'File editor'), !empty($c['disable_file_editor']) ? $on : $off, !empty($c['disable_file_editor'])
            ? $T('Theme-/Plugin-Editor deaktiviert (<code>DISALLOW_FILE_EDIT</code>).', 'Theme/plugin editor disabled (<code>DISALLOW_FILE_EDIT</code>).') : $na),
        array($T('Login-Fehlermeldung', 'Login error message'), !empty($c['generic_login_errors']) ? $on : $off, !empty($c['generic_login_errors'])
            ? $T('Generische Meldung — verrät nicht, ob der Benutzername existiert.', 'Generic message — does not reveal whether the username exists.') : $na),
        array($T('Kommentare', 'Comments'), !empty($c['disable_comments']) ? '<span style="color:#d63638;font-weight:600">' . esc_html($T('deaktiviert', 'disabled')) . '</span>' : $off, !empty($c['disable_comments'])
            ? $T('Komplett aus: Frontend geschlossen, Bestand ausgeblendet, Admin-Menü/Adminbar entfernt, REST-Endpunkte entfernt, Feed-Links aus dem Head.', 'Fully off: frontend closed, existing comments hidden, admin menu/adminbar removed, REST endpoints removed, feed links stripped from head.')
            : $T('Kommentare laufen normal.', 'Comments work as usual.')),
        array($T('Privacy-Policy aus CPT', 'Privacy policy from CPT'), !empty($c['privacy_cpt']) ? $on : $off, !empty($c['privacy_cpt'])
            ? 'CPT <code>' . esc_html($c['privacy_cpt']) . '</code> ' . $T('ist in Einstellungen → Datenschutz als Datenschutzseite wählbar.', 'is selectable as privacy page under Settings → Privacy.') : $na),
        array('301-Redirects', !empty($c['redirects']) ? $on : $off, !empty($c['redirects'])
            ? count($c['redirects']) . ' Redirect(s): ' . esc_html(implode(', ', array_map(function ($k, $v) { return "{$k} → {$v}"; }, array_keys($c['redirects']), $c['redirects']))) : $na),
        array($T('Konten & Sicherheit', 'Accounts & security'),
            WebAudits_Sec::$active ? $on : (WebAudits_Sec::$legacy ? '<span style="color:#996800;font-weight:600">' . esc_html($T('wartet', 'waiting')) . '</span>' : $off),
            WebAudits_Sec::$active
                ? $T('Sicherheits-Log', 'Security log') . ' · User Guard ' . (WebAudits_Sec_Config::enforcing() ? $T('erzwingt', 'enforcing') . ' <code>' . esc_html(implode(', ', WebAudits_Sec_Config::allowed_domains())) . '</code>' : $T('nur protokollierend', 'logging only'))
                  . ' · ' . $T('Core-Sicherheitsupdates', 'core security updates') . ' ' . (WebAudits_Sec_Config::force_core_updates() ? $T('erzwungen', 'enforced') : $T('Site-Policy', 'site policy'))
                  . ' — <a href="' . esc_url(WebAudits_Sec_Admin::url('accounts')) . '">' . $T('Einstellungen', 'settings') . '</a>'
                : (WebAudits_Sec::$legacy ? $T('Alte Datei etch-security.php ist noch aktiv — entfernen, dann übernimmt die Suite.', 'Old file etch-security.php is still active — remove it and the suite takes over.') : $na)),
    );
    // Don't list unconfigured modules (status off, no details).
    $rows = array_values(array_filter($rows, function ($r) { return $r[2] !== '—'; }));
    ?>
    <div class="wrap">
        <h1>WebAudits Suite</h1>
        <?php if (WebAudits_Sec::$active) webaudits_admin_tabs('suite'); ?>
        <table class="widefat striped" style="max-width:1100px">
            <thead><tr><th style="width:220px"><?php echo esc_html($T('Modul', 'Module')); ?></th><th style="width:80px">Status</th><th>Details</th></tr></thead>
            <tbody>
            <?php foreach ($rows as $r) : ?>
                <tr><td><strong><?php echo $r[0]; ?></strong></td><td><?php echo $r[1]; ?></td><td><?php echo $r[2]; ?></td></tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <h2 style="margin-top:28px"><?php echo esc_html($T('Einstellungen', 'Settings')); ?></h2>
        <form method="post">
            <?php wp_nonce_field('webaudits_suite_save'); ?>
            <table class="form-table" style="max-width:1100px">
                <tr>
                    <th scope="row"><label for="wa_gtm_id"><?php echo esc_html($T('GTM-Container-ID', 'GTM container ID')); ?></label></th>
                    <td><input type="text" class="regular-text" id="wa_gtm_id" name="gtm_id" value="<?php echo esc_attr(webaudits_cfg('gtm_id')); ?>" placeholder="GTM-XXXXXXX">
                    <p class="description"><?php echo wp_kses_post($T(
                        'Wird erst nach Einwilligung geladen, über den Consent-Manager aus <code>consent_provider</code> (Konfigurationsdatei). Lädt euer Consent-Manager GTM selbst (z. B. Borlabs Cookie), hier leer lassen. Leer = aus.',
                        'Loaded only after consent, via the consent manager set in <code>consent_provider</code> (config file). If your consent manager loads GTM itself (e.g. Borlabs Cookie), leave this empty. Empty = off.'
                    )); ?></p></td>
                </tr>
                <tr>
                    <th scope="row"><label for="wa_ga4_id"><?php echo esc_html($T('GA4-Mess-ID (nur ohne GTM)', 'GA4 measurement ID (only without GTM)')); ?></label></th>
                    <td><input type="text" class="regular-text" id="wa_ga4_id" name="ga4_id" value="<?php echo esc_attr(webaudits_cfg('ga4_id')); ?>" placeholder="G-XXXXXXXXXX">
                    <p class="description"><?php echo esc_html($T(
                        'Direkt per gtag.js. Ist eine GTM-ID gesetzt, bleibt dieses Modul gesperrt (Doppel-Tracking-Sperre).',
                        'Directly via gtag.js. If a GTM ID is set, this module stays locked (double-tracking guard).'
                    )); ?></p></td>
                </tr>
                <tr>
                    <th scope="row"><label for="wa_csp_mode">Content-Security-Policy</label></th>
                    <td><select id="wa_csp_mode" name="csp_mode">
                        <?php foreach (array('off' => $T('aus', 'off'), 'report-only' => $T('Report-Only (empfohlen zum Start)', 'Report-Only (recommended to start)'), 'enforce' => 'Enforce') as $val => $label) : ?>
                            <option value="<?php echo esc_attr($val); ?>" <?php selected(webaudits_cfg('csp_mode'), $val); ?>><?php echo esc_html($label); ?></option>
                        <?php endforeach; ?>
                    </select>
                    <p class="description"><?php echo esc_html($T(
                        'Auf Enforce erst schalten, wenn die Browser-Konsole über alle Seitentypen 0 Report-Only-Violations zeigt.',
                        'Only switch to Enforce once the browser console shows 0 report-only violations across all page types.'
                    )); ?></p></td>
                </tr>
                <tr>
                    <th scope="row"><label for="wa_csp_admins"><?php echo esc_html($T('CSP für Administratoren', 'CSP for administrators')); ?></label></th>
                    <td><select id="wa_csp_admins" name="csp_admins">
                        <?php foreach (array('same' => $T('wie oben', 'same as above'), 'report-only' => 'Report-Only', 'off' => $T('aus', 'off')) as $val => $label) : ?>
                            <option value="<?php echo esc_attr($val); ?>" <?php selected(webaudits_cfg('csp_admins', 'same'), $val); ?>><?php echo esc_html($label); ?></option>
                        <?php endforeach; ?>
                    </select>
                    <p class="description"><?php echo esc_html($T(
                        'Gilt nur für eingeloggte Administratoren, Besucher bekommen immer die Einstellung oben. Nötig, wenn ein Admin-Werkzeug im Frontend eval braucht (z. B. das ACSS-Dashboard).',
                        'Applies only to logged-in administrators; visitors always get the setting above. Needed when an admin tool on the frontend requires eval (e.g. the ACSS dashboard).'
                    )); ?></p></td>
                </tr>
                <tr>
                    <th scope="row"><label for="wa_theme_color">Theme-Color</label></th>
                    <td><input type="text" id="wa_theme_color" name="theme_color" value="<?php echo esc_attr(webaudits_cfg('theme_color')); ?>" placeholder="#E30613" size="10"></td>
                </tr>
                <tr>
                    <th scope="row"><?php echo esc_html($T('Schalter', 'Switches')); ?></th>
                    <td><fieldset>
                        <?php
                        $switches = array(
                            'disable_comments'     => $T('Kommentare komplett deaktivieren (Frontend, Bestand, Admin, REST)', 'Disable comments entirely (frontend, existing, admin, REST)'),
                            'admin_cleanup'        => $T('Dashboard bereinigen (Widgets, Willkommens-Panel, Plugin-Widgets)', 'Clean up dashboard (widgets, welcome panel, plugin widgets)'),
                            'block_xmlrpc'         => $T('XML-RPC blockieren (403)', 'Block XML-RPC (403)'),
                            'disable_file_editor'  => $T('Theme-/Plugin-Editor deaktivieren (DISALLOW_FILE_EDIT)', 'Disable theme/plugin editor (DISALLOW_FILE_EDIT)'),
                            'generic_login_errors' => $T('Generische Login-Fehlermeldung (kein Username-Leak)', 'Generic login error message (no username leak)'),
                            'last_login_column'    => $T('Benutzer-Liste: Spalte „Letzter Login"', 'User list: "Last login" column'),
                            'hsts_preload'         => $T('HSTS preload-Flag (NUR nach Einreichung bei hstspreload.org!)', 'HSTS preload flag (ONLY after submission to hstspreload.org!)'),
                        );
                        foreach ($switches as $key => $label) : ?>
                            <label style="display:block;margin-bottom:6px"><input type="checkbox" name="<?php echo esc_attr($key); ?>" value="1" <?php checked((bool) webaudits_cfg($key)); ?>> <?php echo esc_html($label); ?></label>
                        <?php endforeach; ?>
                    </fieldset></td>
                </tr>
            </table>
            <p class="submit"><button type="submit" name="webaudits_save" value="1" class="button button-primary"><?php echo esc_html($T('Speichern', 'Save')); ?></button>
            <button type="submit" name="webaudits_check_update" value="1" class="button" style="margin-left:8px"><?php echo esc_html($T('Jetzt auf Updates prüfen', 'Check for updates now')); ?></button></p>
        </form>
    </div>
    <?php
}

// ==================================================== 15) Accounts & security (a separate plugin "Etch Security" up to 3.5)
// User Guard (domain allowlist for new accounts + backstop against wp_insert_user and
// privilege escalation), security log (own table: actor, IP, request; 180 days,
// CSV) and forced core security updates. Taken over from Etch Security 1.1.1
// (github.com/tobiashaas/Etch-Security, archived). Options (etch_security_*), the
// table {prefix}etch_security_audit, meta, filters and the constant
// ETCH_SECURITY_ALLOWED_DOMAINS keep working unchanged: existing data is kept.
// If the old etch-security.php is still in the mu-plugins folder (or active as a
// plugin), this module stays off so nothing runs twice; the suite then shows
// a notice. Switch off entirely: 'security_module' => false in webaudits-config.php.

final class WebAudits_Sec
{
    public static $active = false;   // module is running
    public static $legacy = false;   // old Etch Security file is still loaded
}

final class WebAudits_Sec_Config
{
    const OPT_DOMAINS      = 'etch_security_allowed_domains';     // array of domains
    const OPT_ENFORCE      = 'etch_security_enforce';             // '1' | '0'
    const OPT_CORE_UPDATES = 'etch_security_force_core_updates';  // '1' | '0' (default on)

    /** Configured domains (option, otherwise the constant as the initial default). */
    public static function configured_domains()
    {
        $opt = get_option(self::OPT_DOMAINS, null);
        if ($opt === null && defined('ETCH_SECURITY_ALLOWED_DOMAINS')) $opt = self::parse(ETCH_SECURITY_ALLOWED_DOMAINS);
        return is_array($opt) ? $opt : array();
    }

    /** Effective allowlist: configured domains + domain of the admin address (against self-lockout) + filter. */
    public static function allowed_domains()
    {
        $domains = self::configured_domains();
        $admin = strtolower((string) get_option('admin_email'));
        $at = strrpos($admin, '@');
        if ($at !== false) $domains[] = substr($admin, $at + 1);
        $domains = apply_filters('etch_security_allowed_domains', $domains);
        return array_values(array_unique(array_filter(array_map('strtolower', (array) $domains))));
    }

    /** Enforcement only when switched on AND at least one domain is configured. */
    public static function enforcing()
    {
        if (get_option(self::OPT_ENFORCE, '0') !== '1') return false;
        return count(self::configured_domains()) > 0;
    }

    public static function force_core_updates() { return get_option(self::OPT_CORE_UPDATES, '1') === '1'; }

    public static function is_allowed($email)
    {
        $email = strtolower(trim((string) $email));
        $at = strrpos($email, '@');
        if ($email === '' || $at === false) return false;
        return in_array(substr($email, $at + 1), self::allowed_domains(), true);
    }

    /** "a.com, b.de\nc.org" -> ['a.com','b.de','c.org'] */
    public static function parse($raw)
    {
        $out = array();
        foreach (preg_split('/[\s,;]+/', (string) $raw, -1, PREG_SPLIT_NO_EMPTY) as $p) {
            $p = strtolower(ltrim(trim($p), '@'));
            if ($p !== '') $out[] = $p;
        }
        return array_values(array_unique($out));
    }
}

final class WebAudits_Sec_Guard
{
    const FLAG_META = 'etch_security_neutralized';
    private static $busy = false;

    public static function boot()
    {
        // Layer 1 — prevention on the regular paths.
        add_filter('rest_pre_insert_user',       array(__CLASS__, 'guard_rest'), 10, 2);
        add_action('user_profile_update_errors', array(__CLASS__, 'guard_profile'), 10, 3);
        add_filter('registration_errors',        array(__CLASS__, 'guard_registration'), 10, 3);
        // Layer 2 — backstop, also catches wp_insert_user() and escalation.
        add_action('user_register', array(__CLASS__, 'backstop'), PHP_INT_MAX, 1);
        add_action('set_user_role', array(__CLASS__, 'watch_role'), PHP_INT_MAX, 3);
    }

    private static function refusal()
    {
        return sprintf(webaudits_txt('Diese E-Mail-Adresse ist nicht zugelassen. Konten sind auf %s beschränkt.',
            'This e-mail address is not allowed. Accounts are restricted to %s.'),
            '@' . implode(', @', WebAudits_Sec_Config::allowed_domains()));
    }

    public static function guard_rest($prepared_user, $request)
    {
        if (!WebAudits_Sec_Config::enforcing()) return $prepared_user;
        $email = isset($prepared_user->user_email) ? $prepared_user->user_email : '';
        if ($email !== '' && !WebAudits_Sec_Config::is_allowed($email)) {
            WebAudits_Sec_Audit::log('guard_blocked', array('login' => $email), array('via' => 'rest', 'email' => $email));
            return new WP_Error('etch_security_user_guard', self::refusal(), array('status' => 403));
        }
        return $prepared_user;
    }

    public static function guard_profile($errors, $update, $user)
    {
        if (!WebAudits_Sec_Config::enforcing()) return;
        $email = isset($user->user_email) ? $user->user_email : '';
        if ($email === '') return;
        if ($update && !empty($user->ID)) {
            $current = get_userdata($user->ID);
            if ($current && strtolower($current->user_email) === strtolower($email)) return; // unchanged
        }
        if (!WebAudits_Sec_Config::is_allowed($email)) {
            $errors->add('etch_security_user_guard', self::refusal());
            WebAudits_Sec_Audit::log('guard_blocked', array('id' => isset($user->ID) ? (int) $user->ID : 0, 'login' => $email),
                array('via' => 'profile', 'email' => $email));
        }
    }

    public static function guard_registration($errors, $login, $email)
    {
        if (!WebAudits_Sec_Config::enforcing()) return $errors;
        if ($email !== '' && !WebAudits_Sec_Config::is_allowed($email)) {
            $errors->add('etch_security_user_guard', self::refusal());
            WebAudits_Sec_Audit::log('guard_blocked', array('login' => $email), array('via' => 'registration', 'email' => $email));
        }
        return $errors;
    }

    public static function backstop($user_id)
    {
        if (self::$busy || !WebAudits_Sec_Config::enforcing()) return;
        $user = get_userdata($user_id);
        if (!$user || WebAudits_Sec_Config::is_allowed($user->user_email)) return;
        self::neutralize($user, 'user_register');
    }

    public static function watch_role($user_id, $role, $old_roles)
    {
        if (self::$busy || !WebAudits_Sec_Config::enforcing()) return;
        $user = get_userdata($user_id);
        if ($user && !WebAudits_Sec_Config::is_allowed($user->user_email)) self::neutralize($user, 'set_user_role:' . $role);
    }

    /** Make the account unusable without deleting it (evidence). */
    private static function neutralize($user, $trigger)
    {
        self::$busy = true;
        $wp_user = new WP_User($user->ID);
        $wp_user->set_role('');
        wp_set_password(wp_generate_password(64, true, true), $user->ID);
        $tokens = WP_Session_Tokens::get_instance($user->ID);
        if ($tokens) $tokens->destroy_all();
        update_user_meta($user->ID, self::FLAG_META, current_time('mysql'));
        self::$busy = false;
        WebAudits_Sec_Audit::log('guard_neutralized', array('id' => $user->ID, 'login' => $user->user_login),
            array('trigger' => $trigger, 'email' => $user->user_email));
        self::notify($user, $trigger);
    }

    private static function notify($user, $trigger)
    {
        $to = get_option('admin_email');
        if (!$to) return;
        $brand = get_bloginfo('name') ?: 'WebAudits Suite';
        // The recipient is the site's admin address, so the mail follows the site language.
        $de = strpos((string) get_locale(), 'de') === 0;
        $body = sprintf($de
            ? "Es wurde ein Konto mit nicht zugelassener Domain angelegt und sofort entschärft.\n\n"
              . "Benutzer:  %s\nE-Mail:    %s\nID:        %d\nAusgelöst durch: %s\nZeit:      %s\nIP:        %s\n\n"
              . "Status: Rolle entzogen, Passwort invalidiert, Sessions beendet.\n"
              . "Das Konto wurde NICHT gelöscht — es ist Beweismittel.\n"
              . "Details: Werkzeuge → WebAudits Suite → Sicherheits-Log."
            : "An account with a non-allowed e-mail domain was created and neutralised immediately.\n\n"
              . "User:      %s\nE-mail:    %s\nID:        %d\nTriggered by: %s\nTime:      %s\nIP:        %s\n\n"
              . "Status: role removed, password invalidated, sessions destroyed.\n"
              . "The account was NOT deleted — it is evidence.\n"
              . "Details: Tools → WebAudits Suite → Security log.",
            $user->user_login, $user->user_email, $user->ID, $trigger, current_time('mysql'), WebAudits_Sec_Util::ip()
        );
        wp_mail($to, '[' . $brand . '] ' . ($de ? 'Fremder Benutzer blockiert: ' : 'Foreign user blocked: ') . $user->user_login, $body);
    }
}

final class WebAudits_Sec_Audit
{
    const TABLE       = 'etch_security_audit';
    const DB_VERSION  = '1';
    const DB_OPTION   = 'etch_security_audit_db_version';
    const RETAIN_DAYS = 180;
    const CRON_HOOK   = 'etch_security_audit_prune';

    public static function boot()
    {
        self::maybe_install();
        add_action('user_register',   array(__CLASS__, 'on_user_register'), 5, 1);
        add_action('profile_update',  array(__CLASS__, 'on_profile_update'), 5, 2);
        add_action('set_user_role',   array(__CLASS__, 'on_set_role'), 5, 3);
        add_action('deleted_user',    array(__CLASS__, 'on_deleted_user'), 5, 3);
        add_action('wp_create_application_password', array(__CLASS__, 'on_app_password'), 5, 2);
        add_action('wp_login',        array(__CLASS__, 'on_login'), 5, 2);
        add_action('wp_login_failed', array(__CLASS__, 'on_login_failed'), 5, 1);
        add_action('after_password_reset', array(__CLASS__, 'on_password_reset'), 5, 1);
        add_action('activated_plugin',   array(__CLASS__, 'on_plugin_activated'), 5, 1);
        add_action('deactivated_plugin', array(__CLASS__, 'on_plugin_deactivated'), 5, 1);
        add_action('switch_theme',       array(__CLASS__, 'on_switch_theme'), 5, 1);
        add_action(self::CRON_HOOK, array(__CLASS__, 'prune'));
        if (!wp_next_scheduled(self::CRON_HOOK)) wp_schedule_event(time() + 3600, 'daily', self::CRON_HOOK);
    }

    public static function table() { global $wpdb; return $wpdb->prefix . self::TABLE; }

    public static function maybe_install()
    {
        if (get_option(self::DB_OPTION) === self::DB_VERSION) return;
        global $wpdb;
        $table = self::table();
        $charset = $wpdb->get_charset_collate();
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta("CREATE TABLE $table (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            event_time DATETIME NOT NULL,
            event_time_gmt DATETIME NOT NULL,
            event VARCHAR(64) NOT NULL,
            actor_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            actor_login VARCHAR(191) NOT NULL DEFAULT '',
            target_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            target_login VARCHAR(191) NOT NULL DEFAULT '',
            detail TEXT NULL,
            ip VARCHAR(64) NOT NULL DEFAULT '',
            ua VARCHAR(255) NOT NULL DEFAULT '',
            uri VARCHAR(255) NOT NULL DEFAULT '',
            context VARCHAR(16) NOT NULL DEFAULT '',
            PRIMARY KEY  (id),
            KEY event_time_gmt (event_time_gmt),
            KEY event (event),
            KEY actor_id (actor_id),
            KEY target_id (target_id)
        ) $charset;");
        update_option(self::DB_OPTION, self::DB_VERSION, false);
    }

    /** Central write function. $target = [id, login]; $detail = array. */
    public static function log($event, $target = array(), $detail = array())
    {
        global $wpdb;
        $actor = function_exists('wp_get_current_user') ? wp_get_current_user() : null;
        $wpdb->insert(self::table(), array(
            'event_time'     => current_time('mysql'),
            'event_time_gmt' => current_time('mysql', true),
            'event'          => substr($event, 0, 64),
            'actor_id'       => $actor ? (int) $actor->ID : 0,
            'actor_login'    => $actor ? substr($actor->user_login, 0, 191) : '',
            'target_id'      => isset($target['id']) ? (int) $target['id'] : 0,
            'target_login'   => isset($target['login']) ? substr((string) $target['login'], 0, 191) : '',
            'detail'         => $detail ? wp_json_encode($detail) : null,
            'ip'             => WebAudits_Sec_Util::ip(),
            'ua'             => substr(WebAudits_Sec_Util::server('HTTP_USER_AGENT'), 0, 255),
            'uri'            => substr(WebAudits_Sec_Util::server('REQUEST_URI'), 0, 255),
            'context'        => WebAudits_Sec_Util::context(),
        ));
    }

    public static function on_user_register($user_id)
    {
        $u = get_userdata($user_id);
        self::log('user_register', array('id' => $user_id, 'login' => $u ? $u->user_login : ''),
            array('email' => $u ? $u->user_email : '', 'roles' => $u ? $u->roles : array()));
    }
    public static function on_profile_update($user_id, $old)
    {
        $u = get_userdata($user_id);
        if (!$u || !$old || strtolower($old->user_email) === strtolower($u->user_email)) return;
        self::log('profile_update', array('id' => $user_id, 'login' => $u->user_login),
            array('email' => array('from' => $old->user_email, 'to' => $u->user_email)));
    }
    public static function on_set_role($user_id, $role, $old_roles)
    {
        $u = get_userdata($user_id);
        self::log('set_user_role', array('id' => $user_id, 'login' => $u ? $u->user_login : ''),
            array('new' => $role ?: '(none)', 'previous' => $old_roles ?: array()));
    }
    public static function on_deleted_user($id, $reassign, $user)
    {
        self::log('deleted_user', array('id' => $id, 'login' => $user ? $user->user_login : ''),
            array('email' => $user ? $user->user_email : '', 'reassign_to' => $reassign ? (int) $reassign : null));
    }
    public static function on_app_password($user_id, $item)
    {
        $u = get_userdata($user_id);
        self::log('application_password_created', array('id' => $user_id, 'login' => $u ? $u->user_login : ''),
            array('name' => isset($item['name']) ? $item['name'] : ''));
    }
    public static function on_login($login, $user)
    {
        self::log('login_success', array('id' => $user ? $user->ID : 0, 'login' => $login), array('roles' => $user ? $user->roles : array()));
    }
    public static function on_login_failed($username)    { self::log('login_failed', array('login' => $username)); }
    public static function on_password_reset($user)       { self::log('password_reset', array('id' => $user ? $user->ID : 0, 'login' => $user ? $user->user_login : '')); }
    public static function on_plugin_activated($plugin)   { self::log('plugin_activated',   array(), array('plugin' => $plugin)); }
    public static function on_plugin_deactivated($plugin) { self::log('plugin_deactivated', array(), array('plugin' => $plugin)); }
    public static function on_switch_theme($name)         { self::log('switch_theme',       array(), array('theme' => $name)); }

    public static function prune()
    {
        global $wpdb;
        $table = self::table();
        $wpdb->query($wpdb->prepare("DELETE FROM $table WHERE event_time_gmt < (UTC_TIMESTAMP() - INTERVAL %d DAY)", self::RETAIN_DAYS));
    }
}

final class WebAudits_Sec_Util
{
    public static function server($key) { return isset($_SERVER[$key]) ? sanitize_text_field(wp_unslash($_SERVER[$key])) : ''; }

    /** Source IP. Deliberately REMOTE_ADDR: proxy headers can be spoofed. Behind a trusted proxy, extend via filter. */
    public static function ip() { return (string) apply_filters('etch_security_client_ip', substr(self::server('REMOTE_ADDR'), 0, 64)); }

    public static function context()
    {
        if (defined('WP_CLI') && WP_CLI) return 'cli';
        if (function_exists('wp_doing_cron') && wp_doing_cron()) return 'cron';
        if (defined('REST_REQUEST') && REST_REQUEST) return 'rest';
        if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) return 'xmlrpc';
        if (is_admin()) return 'admin';
        return 'web';
    }
}

final class WebAudits_Sec_Core
{
    public static function boot()
    {
        if (!WebAudits_Sec_Config::force_core_updates()) return;
        // Overrides blockers like Installatron (which disable via __return_false): PHP_INT_MAX runs last.
        add_filter('allow_minor_auto_core_updates', '__return_true', PHP_INT_MAX);
        add_filter('auto_update_core', array(__CLASS__, 'allow_security'), PHP_INT_MAX, 2);
        add_action('automatic_updates_complete', array(__CLASS__, 'log_result'), 10, 1);
    }

    /** Force only minor/security point releases of the same X.Y series; major releases follow the site policy. */
    public static function allow_security($update, $item)
    {
        if (!is_object($item) || empty($item->current)) return $update;
        $installed = isset($GLOBALS['wp_version']) ? $GLOBALS['wp_version'] : get_bloginfo('version');
        return self::same_branch($installed, $item->current) ? true : $update;
    }

    private static function same_branch($a, $b)
    {
        $pa = explode('.', preg_replace('/[^0-9.].*$/', '', (string) $a));
        $pb = explode('.', preg_replace('/[^0-9.].*$/', '', (string) $b));
        return isset($pa[0], $pa[1], $pb[0], $pb[1]) && $pa[0] === $pb[0] && $pa[1] === $pb[1];
    }

    public static function log_result($results)
    {
        if (empty($results['core']) || !is_array($results['core'])) return;
        foreach ($results['core'] as $r) {
            $ver = (isset($r->item) && isset($r->item->current)) ? $r->item->current : '?';
            $ok  = !empty($r->result) && !is_wp_error($r->result);
            WebAudits_Sec_Audit::log('core_auto_update', array('login' => 'WordPress'), array('version' => $ver, 'success' => $ok ? 'yes' : 'no'));
        }
    }
}

final class WebAudits_Sec_Admin
{
    public static function boot()
    {
        add_action('admin_post_webaudits_sec_save', array(__CLASS__, 'save_settings'));
        add_action('admin_post_webaudits_sec_csv',  array(__CLASS__, 'export_csv'));
    }

    public static function url($tab, $args = array())
    {
        return add_query_arg(array_merge(array('page' => 'webaudits-suite', 'tab' => $tab), $args), admin_url('tools.php'));
    }

    private static function row($k, $v) { printf('<tr><th style="width:230px;text-align:left">%s</th><td>%s</td></tr>', esc_html($k), $v); }

    public static function render_status()
    {
        $T = 'webaudits_txt';
        $domains   = WebAudits_Sec_Config::configured_domains();
        $enforce   = get_option(WebAudits_Sec_Config::OPT_ENFORCE, '0') === '1';
        $eff       = WebAudits_Sec_Config::allowed_domains();
        $enforcing = WebAudits_Sec_Config::enforcing();
        if (!empty($_GET['msg'])) echo '<div class="notice notice-success"><p>' . esc_html(sanitize_text_field(wp_unslash($_GET['msg']))) . '</p></div>';

        echo '<h2>' . esc_html($T('WordPress-Core', 'WordPress core')) . '</h2><table class="widefat" style="max-width:820px"><tbody>';
        self::row($T('Core-Version', 'Core version'), '<code>' . esc_html(get_bloginfo('version')) . '</code>');
        self::row($T('Sicherheits-Auto-Updates', 'Security auto-updates'), WebAudits_Sec_Config::force_core_updates()
            ? '<strong style="color:#1a7f37">' . esc_html($T('erzwungen', 'enforced')) . '</strong> — ' . esc_html($T('Minor-/Security-Releases laufen durch, auch gegen einen Blocker (z. B. Installatron)', 'minor/security releases go through, even against a blocker (e.g. Installatron)'))
            : '<span style="color:#996800">' . esc_html($T('nicht erzwungen', 'not enforced')) . '</span> — ' . esc_html($T('es gilt die Site-Policy', 'site policy applies')));
        echo '</tbody></table>';

        echo '<h2>User Guard</h2><table class="widefat" style="max-width:820px"><tbody>';
        self::row('Enforcement', $enforcing
            ? '<strong style="color:#1a7f37">' . esc_html($T('aktiv', 'active')) . '</strong> — ' . esc_html($T('fremde Domains werden entschärft', 'foreign domains are neutralised'))
            : '<strong style="color:#996800">' . esc_html($T('inaktiv', 'inactive')) . '</strong> — ' . esc_html($T('nur das Sicherheits-Log läuft (keine Domain gesetzt oder Schalter aus)', 'only the security log runs (no domain set or switch off)')));
        self::row($T('Erlaubte Domains (wirksam)', 'Allowed domains (effective)'), $eff ? '<code>' . esc_html(implode(', ', $eff)) . '</code>' : '—');
        echo '</tbody></table>';

        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin:1.5em 0;max-width:820px">';
        wp_nonce_field('webaudits_sec_save');
        echo '<input type="hidden" name="action" value="webaudits_sec_save">';
        echo '<p><label for="wa_sec_domains"><strong>' . esc_html($T('Erlaubte Domains', 'Allowed domains')) . '</strong> (' . esc_html($T('eine pro Zeile oder kommagetrennt, ohne @', 'one per line or comma-separated, without @')) . '):</label><br>';
        echo '<textarea id="wa_sec_domains" name="domains" rows="4" style="width:100%;max-width:520px">' . esc_textarea(implode("\n", $domains)) . '</textarea></p>';
        echo '<p><label><input type="checkbox" name="enforce" value="1"' . checked($enforce, true, false) . '> '
            . esc_html($T('Enforcement einschalten (fremde Konten sofort entschärfen)', 'Enable enforcement (neutralise foreign accounts immediately)')) . '</label></p>';
        echo '<p class="description">' . esc_html(sprintf($T('Die Domain der Site-Admin-Adresse (%s) ist immer erlaubt. Ohne konfigurierte Domain bleibt Enforcement aus.', 'The domain of the site admin address (%s) is always allowed. Without a configured domain, enforcement stays off.'), get_option('admin_email'))) . '</p>';
        echo '<p style="margin-top:1.5em"><label><input type="checkbox" name="force_core" value="1"' . checked(WebAudits_Sec_Config::force_core_updates(), true, false) . '> <strong>'
            . esc_html($T('WordPress-Core-Sicherheitsupdates erzwingen', 'Enforce WordPress core security updates')) . '</strong> — '
            . esc_html($T('lässt Minor-/Security-Releases automatisch durchlaufen, auch wenn ein Management-Tool (z. B. Installatron) sie abgeschaltet hat. Major-Versionssprünge bleiben unberührt.', 'lets minor/security releases install automatically, even if a management tool (e.g. Installatron) disabled them. Major upgrades are untouched.')) . '</label></p>';
        submit_button($T('Speichern', 'Save'));
        echo '</form>';
    }

    public static function render_log()
    {
        global $wpdb;
        $T = 'webaudits_txt';
        $table = WebAudits_Sec_Audit::table();
        $per   = 50;
        $paged = max(1, isset($_GET['paged']) ? (int) $_GET['paged'] : 1);
        $ev    = isset($_GET['ev']) ? sanitize_text_field(wp_unslash($_GET['ev'])) : '';
        $where = $ev !== '' ? $wpdb->prepare('WHERE event = %s', $ev) : '';
        $total = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table $where");
        $rows  = $wpdb->get_results($wpdb->prepare("SELECT * FROM $table $where ORDER BY id DESC LIMIT %d OFFSET %d", $per, ($paged - 1) * $per));
        $events = $wpdb->get_col("SELECT DISTINCT event FROM $table ORDER BY event");
        $csv = wp_nonce_url(admin_url('admin-post.php?action=webaudits_sec_csv'), 'webaudits_sec_csv');

        echo '<p>' . esc_html(sprintf($T('%1$d Einträge · Aufbewahrung %2$d Tage · Zeiten in Website-Zeitzone.', '%1$d entries · kept for %2$d days · times in site timezone.'), $total, WebAudits_Sec_Audit::RETAIN_DAYS)) . '</p>';
        echo '<form method="get" style="margin:1em 0"><input type="hidden" name="page" value="webaudits-suite"><input type="hidden" name="tab" value="log">';
        echo '<label class="screen-reader-text" for="wa_sec_ev">' . esc_html($T('Ereignis', 'Event')) . '</label><select id="wa_sec_ev" name="ev"><option value="">— ' . esc_html($T('alle Ereignisse', 'all events')) . ' —</option>';
        foreach ($events as $e) printf('<option value="%s"%s>%s</option>', esc_attr($e), selected($ev, $e, false), esc_html($e));
        echo '</select> <button class="button">' . esc_html($T('Filtern', 'Filter')) . '</button> <a class="button" href="' . esc_url($csv) . '">' . esc_html($T('CSV-Export', 'CSV export')) . '</a></form>';

        echo '<table class="widefat striped"><thead><tr><th>' . esc_html($T('Zeit', 'Time')) . '</th><th>' . esc_html($T('Ereignis', 'Event')) . '</th><th>Actor</th><th>' . esc_html($T('Ziel', 'Target')) . '</th><th>IP</th><th>' . esc_html($T('Kontext', 'Context')) . '</th><th>Details</th></tr></thead><tbody>';
        if (!$rows) echo '<tr><td colspan="7">' . esc_html($T('Noch keine Einträge.', 'No entries yet.')) . '</td></tr>';
        foreach ($rows as $r) {
            $actor  = $r->actor_id ? $r->actor_login . ' (#' . $r->actor_id . ')' : ($r->actor_login ?: '—');
            $target = $r->target_login ? $r->target_login . ($r->target_id ? ' (#' . $r->target_id . ')' : '') : '—';
            printf('<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><code style="font-size:11px">%s</code></td></tr>',
                esc_html($r->event_time), esc_html($r->event), esc_html($actor), esc_html($target), esc_html($r->ip), esc_html($r->context),
                esc_html($r->detail ? substr($r->detail, 0, 300) : ''));
        }
        echo '</tbody></table>';
        $pages = (int) ceil($total / $per);
        if ($pages > 1) {
            echo '<div class="tablenav"><div class="tablenav-pages">';
            for ($i = 1; $i <= $pages; $i++) {
                echo ' ' . ($i === $paged ? '<strong>' . $i . '</strong>' : '<a href="' . esc_url(self::url('log', array('ev' => $ev, 'paged' => $i))) . '">' . $i . '</a>') . ' ';
            }
            echo '</div></div>';
        }
    }

    public static function save_settings()
    {
        if (!current_user_can('manage_options')) wp_die(esc_html(webaudits_txt('Keine Berechtigung.', 'Not allowed.')));
        check_admin_referer('webaudits_sec_save');
        $domains = WebAudits_Sec_Config::parse(isset($_POST['domains']) ? wp_unslash($_POST['domains']) : '');
        update_option(WebAudits_Sec_Config::OPT_DOMAINS, $domains, false);
        update_option(WebAudits_Sec_Config::OPT_ENFORCE, empty($_POST['enforce']) ? '0' : '1', false);
        update_option(WebAudits_Sec_Config::OPT_CORE_UPDATES, empty($_POST['force_core']) ? '0' : '1', false);
        $msg = $domains ? webaudits_txt('Gespeichert.', 'Saved.') : webaudits_txt('Gespeichert (keine Domain → Enforcement bleibt aus).', 'Saved (no domain → enforcement stays off).');
        wp_safe_redirect(self::url('accounts', array('msg' => rawurlencode($msg))));
        exit;
    }

    public static function export_csv()
    {
        if (!current_user_can('manage_options')) wp_die(esc_html(webaudits_txt('Keine Berechtigung.', 'Not allowed.')));
        check_admin_referer('webaudits_sec_csv');
        global $wpdb;
        $rows = $wpdb->get_results('SELECT * FROM ' . WebAudits_Sec_Audit::table() . ' ORDER BY id DESC', ARRAY_A);
        nocache_headers();
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename=security-log-' . gmdate('Ymd-His') . '.csv');
        $out = fopen('php://output', 'w');
        fputcsv($out, array('id', 'event_time', 'event_time_gmt', 'event', 'actor_id', 'actor_login', 'target_id', 'target_login', 'detail', 'ip', 'ua', 'uri', 'context'));
        foreach ($rows as $r) fputcsv($out, $r);
        fclose($out);
        exit;
    }
}

// Start only on plugins_loaded: by then it is known for sure whether the old Etch Security
// file (mu-plugin OR regular plugin) was loaded.
add_action('plugins_loaded', function () {
    if (!webaudits_cfg('security_module', true)) return;
    // Old file still loaded? (1.1.x defines the constant, older versions only their classes.)
    $legacy = defined('ETCH_SECURITY_VERSION');
    if (!$legacy) foreach (get_declared_classes() as $cls) { if (stripos(str_replace('_', '', $cls), 'EtchSecurity') === 0) { $legacy = true; break; } }
    if ($legacy) { WebAudits_Sec::$legacy = true; return; }
    WebAudits_Sec::$active = true;
    WebAudits_Sec_Audit::boot();   // first — Guard and core updates log through this
    WebAudits_Sec_Guard::boot();
    WebAudits_Sec_Core::boot();
    if (is_admin()) WebAudits_Sec_Admin::boot();
    // The old Etch Security file's own updater no longer exists.
    if (wp_next_scheduled('etch_security_update_check')) wp_clear_scheduled_hook('etch_security_update_check');
}, 0);

/** Tabs of the suite page: Overview | Accounts & security | Security log. */
function webaudits_admin_tabs($aktiv) {
    $tabs = array(
        'suite'  => webaudits_txt('Übersicht & Einstellungen', 'Overview & settings'),
        'accounts' => webaudits_txt('Konten & Sicherheit', 'Accounts & security'),
        'log'    => webaudits_txt('Sicherheits-Log', 'Security log'),
    );
    echo '<nav class="nav-tab-wrapper" style="margin-bottom:16px">';
    foreach ($tabs as $k => $label) {
        printf('<a href="%s" class="nav-tab%s"%s>%s</a>', esc_url(add_query_arg(array('page' => 'webaudits-suite', 'tab' => $k), admin_url('tools.php'))),
            $aktiv === $k ? ' nav-tab-active' : '', $aktiv === $k ? ' aria-current="page"' : '', esc_html($label));
    }
    echo '</nav>';
}

// Old bookmarks to "Tools → Etch Security" land on the new tab
// (the page no longer exists; WordPress would otherwise show "not allowed").
add_action('admin_page_access_denied', function () {
    if (WebAudits_Sec::$active && isset($_GET['page']) && $_GET['page'] === 'etch-security' && current_user_can('manage_options')) {
        $tab = (isset($_GET['tab']) && $_GET['tab'] === 'log') ? 'log' : 'accounts';
        wp_safe_redirect(WebAudits_Sec_Admin::url($tab));
        exit;
    }
});

add_action('admin_notices', function () {
    if (!WebAudits_Sec::$legacy || !current_user_can('manage_options')) return;
    echo '<div class="notice notice-warning"><p><strong>WebAudits Suite:</strong> ' . esc_html(webaudits_txt(
        'User Guard, Sicherheits-Log und Core-Updates stecken jetzt in der Suite. Die alte Datei etch-security.php ist noch aktiv, deshalb bleibt das Suite-Modul aus. Datei aus wp-content/mu-plugins (bzw. das Plugin) entfernen — Einstellungen und Log bleiben erhalten.',
        'User guard, security log and core updates now live in the suite. The old file etch-security.php is still active, so the suite module stays off. Remove the file from wp-content/mu-plugins (or the plugin) — settings and log are kept.'
    )) . '</p></div>';
});
