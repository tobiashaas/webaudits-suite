<?php
/**
 * Plugin Name: WebAudits Site Suite
 * Description: Ein mu-plugin für den ganzen WebAudits-Stack (WordPress + Etch +
 *              ACSS + Pressidium + WS Form): Security-Header + CSP (nonce,
 *              Report-Only→Enforce), Versions-Leak-Fixes, XML-RPC-Block,
 *              security.txt, theme-color, Bild-Loading-Fixes, LocalBusiness-
 *              Schema aus CPT, consent-gated GTM + WS-Form-Lead-Bridge.
 *              Admin-Übersicht: Werkzeuge → WebAudits Suite.
 * Version: 3.2.0
 * Author: WebAudits
 *
 * 3.1: frame_ancestors — fremde Origins dürfen (optional nur auf bestimmten
 *      Pfaden) diese Site einbetten. X-Frame-Options kennt keine fremde Origin
 *      (ALLOW-FROM ist tot), also wird XFO auf genau diesen Antworten
 *      weggelassen und stattdessen ein EIGENER, immer erzwungener
 *      `Content-Security-Policy: frame-ancestors …`-Header gesendet — auch im
 *      Report-Only-Modus, der nichts erzwingen würde.
 *
 * 2.1: Admin/Backend-Modul — Dashboard-Bereinigung (Widgets/Willkommens-Panel/
 *      Plugin-Widgets), sortierbare Letzter-Login-Spalte, DISALLOW_FILE_EDIT,
 *      generische Login-Fehlermeldung. Alles einzeln per Config schaltbar.
 * 2.2: disable_comments-Schalter — Kommentare komplett aus (Frontend, Bestand,
 *      Admin-Menü/Adminbar, REST-Endpunkte).
 * 2.6: Settings-UI (Werkzeuge → WebAudits Suite): operative Werte (GTM-/GA4-ID,
 *      CSP-Modus, Schalter) sind im Admin editierbar; DB-Option gewinnt über den
 *      Datei-Default. Neues GA4-direkt-Modul (gtag) als Alternative zu GTM —
 *      gegenseitig exklusiv (GTM gewinnt, Admin-Notice warnt vor Doppel-Tracking).
 * 2.7: Zweisprachig (de/en) — Admin-UI nach Benutzersprache, Frontend-Strings
 *      nach Site-Locale (webaudits_txt). Übersicht zeigt nur konfigurierte
 *      Module (inaktive ohne Details werden ausgeblendet).
 * 3.0: Code/Konfig-Trennung — Site-Werte leben in webaudits-config.php daneben
 *      (define('WEBAUDITS_CONFIG_SITE', array(...))), diese Datei ist generisch
 *      und wird per Self-Updater aus GitHub-Releases aktuell gehalten
 *      (github.com/tobiashaas/webaudits-suite — DORT ändern + Release taggen;
 *      diese Kopie in etch-intelligence ist nur ein Mirror fürs Erst-Deployment).
 * 2.4: privacy_cpt — CPT in WP-Settings → Datenschutz waehlbar (wp_dropdown_pages-Filter).
 * 2.3: CSP + Output-Buffer werden in der Etch-Builder-Ansicht (?etch=magic)
 *      NICHT gesendet — sonst blockiert CSP eval + Bridge-WebSocket und der
 *      Builder lädt nicht. Anonyme Besucher unberührt.
 *
 * INSTALL: Konfig unten pro Site anpassen, Datei nach wp-content/mu-plugins/
 * kopieren (auto-aktiv). ERSETZT die Einzeldateien mu-plugin-security-headers,
 * mu-plugin-csp sowie separate Performance-/Schema-/GTM-Dateien — alte Dateien
 * löschen, sonst doppelte Header/Buffer!
 * Statische Ebene (Kompression, Asset-Cache, readme/license/xmlrpc-Block für
 * Apache) bleibt in der .htaccess (htaccess-hardening.txt).
 */
if (!defined('ABSPATH')) exit;

// ============================================================ KONFIG
// Generische Defaults. SITE-Werte gehören NICHT hierher, sondern in die
// Datei webaudits-config.php im selben Ordner (Vorlage: webaudits-config-sample.php):
//   define('WEBAUDITS_CONFIG_SITE', array('site_url' => ..., ...));
// Sie überschreiben die Defaults Schlüssel für Schlüssel und überleben
// jedes Self-Update (das nur DIESE Datei ersetzt).
function webaudits_file_config() {
    static $cfg = null;
    if ($cfg !== null) return $cfg;
    $defaults = array(
        // --- Site ---
        'site_url'          => 'https://EXAMPLE.COM',       // ohne Slash am Ende
        'brand_name'        => 'EXAMPLE',                   // Schema/Anzeige
    
        // --- Security-Header ---
        'hsts_preload'      => false,                       // erst nach Subdomain-Audit + www-Check!
        'csp_mode'          => 'report-only',               // 'report-only' | 'enforce' | 'off'
        'security_contact'  => 'mailto:CONTACT@EXAMPLE.COM',// '' = keine security.txt-Route
        'security_expires'  => '2027-01-01T00:00:00.000Z',  // RFC 9116: <= 1 Jahr, vorher erneuern
        'block_xmlrpc'      => true,

        // --- Framing: wer darf diese Site in einen iframe stecken? ---
        // Default = niemand ausser der eigenen Origin (X-Frame-Options:
        // SAMEORIGIN + frame-ancestors 'self').
        // 'origins' = zusaetzlich erlaubte fremde Origins (Schema + Host, ohne
        // Pfad, ohne Slash am Ende). 'paths' = auf welche Pfade die Ausnahme
        // begrenzt ist (ohne Slash am Ende, leeres Array = site-weit).
        // Auf den passenden Antworten faellt X-Frame-Options WEG — der Header
        // kann keine fremde Origin erlauben (ALLOW-FROM ist in allen aktuellen
        // Browsern wirkungslos) und wuerde die Einbettung sonst blockieren.
        'frame_ancestors'   => array(
            'origins' => array(),   // z. B. array('https://lms.example.com')
            'paths'   => array(),   // z. B. array('/datenschutz', '/impressum')
        ),

        // --- Foundations ---
        'theme_color'       => '',                          // z. B. '#E30613'; '' = aus
        'color_scheme'      => 'light',
    
        // --- Performance ---
        // img-Klassen, die NIE eager/fetchpriority=high laden sollen (WPs
        // LCP-Heuristik greift daneben, wenn der echte Hero ein Canvas ist).
        'force_lazy_classes' => array(),                    // z. B. array('bignum__media')
    
        // --- Schema: LocalBusiness aus Standort-CPT (auf einer Seite) ---
        'localbusiness'     => array(
            'enabled'   => false,
            'page'      => 'kontakt',                       // is_page(slug)
            'post_type' => 'standorte',
            'fields'    => array(                            // CPT-Metakeys
                'street' => 'strasse_nr',
                'zip'    => 'postleitzahl',
                'city'   => 'ort',
                'phone'  => 'telefon',
            ),
            'image'     => '',                              // z. B. og-default.png-URL
        ),
    
        // --- Tracking: GTM consent-gated (Pressidium, page_scripts muss AN sein) ---
        'gtm_id'            => '',                          // 'GTM-XXXXXXX'; '' = aus
        // GA4 DIREKT per gtag (ohne GTM). Exklusiv zu gtm_id — ist BEIDES gesetzt,
        // gewinnt GTM und GA4-direkt bleibt aus (Doppel-Tracking-Sperre + Notice).
        'ga4_id'            => '',                          // 'G-XXXXXXXXXX'; '' = aus
        'consent_category'  => 'analytics',                 // Pressidium-Kategorie (nur consent_provider=pressidium)
        // Consent-Manager, der die text/plain-Scripts nach Einwilligung aktiviert:
        //   'pressidium' (Default) | 'iubenda' | 'none' (GTM lädt cookielos via Consent Mode)
        'consent_provider'  => 'pressidium',
        'iubenda_purposes'  => '4',                         // iubenda Purpose-ID(s) f. Measurement (nur consent_provider=iubenda)
        // WS-Form-Bridge: pusht Event bei wsf-submit-success. 'generate_lead' wenn
        // jedes Formular ein Lead ist; 'wsf_submit' wenn der Container per form_id
        // entscheidet (Multi-Formular-Sites). '' = Bridge aus.
        'wsf_bridge_event'  => 'generate_lead',
    
        // --- Admin/Backend ---
        'admin_cleanup'        => true,   // Dashboard-Widgets + Willkommens-Panel raus
        // Plugin-Widgets zusätzlich entfernen (remove_meta_box auf nicht vorhandene
        // IDs ist ein No-Op — Liste darf großzügig sein):
        'dashboard_remove_extra' => array(
            'seopress-dashboard-widget',           // SEOPress
            'wordfence_activity_report_widget',    // Wordfence
            'woocommerce_dashboard_status',        // WooCommerce
            'woocommerce_dashboard_recent_reviews',
            'wc_admin_dashboard_setup',
            'yoast_db_widget',                     // Yoast (Fremd-Setups)
            'rg_forms_dashboard',                  // Gravity Forms
            'bbp-dashboard-right-now',             // bbPress
        ),
        'last_login_column'    => true,   // Benutzer-Liste: Spalte "Letzter Login" (sortierbar)
        'disable_file_editor'  => true,   // Theme-/Plugin-Editor im Admin aus (DISALLOW_FILE_EDIT)
        'generic_login_errors' => true,   // Login verrät nicht, ob der Benutzername existiert
        // Kommentare KOMPLETT aus (Frontend zu, Bestand ausgeblendet, Admin-Menü/
        // Adminbar weg, REST-Endpunkte entfernt). Nur aktivieren, wenn die Site
        // wirklich keine Kommentare nutzt.
        'disable_comments'     => true,
    
        // --- Privacy-Policy aus CPT (WP-Settings → Datenschutz lässt nativ nur
        //     `page` zu). Macht die Posts dieses CPT im Privacy-Dropdown wählbar. ---
        'privacy_cpt'          => '',   // z. B. 'compliance'; '' = Modul aus
    
        // --- Explizite 301-Redirects (alter Pfad => neuer Pfad, je mit Slash).
        //     Für root-basierte CPTs greift WPs "alter Slug"-Redirect nicht. ---
        'redirects'            => array(),   // z. B. array('/alt/' => '/neu/')
    );
    $site = defined('WEBAUDITS_CONFIG_SITE') ? WEBAUDITS_CONFIG_SITE : array();
    $cfg = array_merge($defaults, (array) $site);
    return $cfg;
}

// Diese Schlüssel sind im Admin (Werkzeuge → WebAudits Suite) editierbar.
// Die DB-Option `webaudits_suite_options` GEWINNT über den Datei-Default;
// alles andere bleibt bewusst Datei-Konfig (versioniert im Repo).
const WEBAUDITS_UI_KEYS = array(
    'gtm_id'               => 'text',
    'ga4_id'               => 'text',
    'csp_mode'             => 'select',
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

// Zweisprachigkeit ohne .po-Apparat: Deutsch, wenn die relevante Locale de_* ist,
// sonst Englisch. Admin-Seiten folgen der BENUTZER-Sprache, Frontend-Strings
// (z. B. Login-Fehler) der Site-Locale.
function webaudits_txt($de, $en) {
    $locale = (is_admin() && function_exists('get_user_locale')) ? get_user_locale() : determine_locale();
    return (strpos($locale, 'de') === 0) ? $de : $en;
}

// Etch-Builder-Ansicht (?etch=magic): CSP + Output-Buffer würden den Builder
// aussperren (er braucht 'unsafe-eval' via new Function() und die Bridge-
// WebSocket ws://127.0.0.1:7331/7332). Für diese eingeloggte Editor-Ansicht
// senden wir daher KEINE CSP und lassen den Buffer aus. Anonyme Besucher sind
// unberührt.
function webaudits_is_etch_editor() {
    return isset($_GET['etch']) && $_GET['etch'] === 'magic';
}

// ---------------------------------------------------------------- Framing
/**
 * Fremde Origins, die GENAU DIESE Antwort einbetten duerfen.
 * Leeres Array = niemand (dann bleibt es bei X-Frame-Options: SAMEORIGIN).
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
        // Nur echte Origins: Schema + Host, kein Pfad, kein Wildcard.
        if (!preg_match('~^https?://[A-Za-z0-9.\-]+(:\d+)?$~', $o)) continue;
        $origins[] = $o;
    }
    if (!$origins) return $cache;
    $paths = array_filter(array_map(function ($p) {
        return rtrim((string) $p, '/');
    }, (array) (isset($fa['paths']) ? $fa['paths'] : array())), 'strlen');
    if (!$paths) { $cache = $origins; return $cache; }   // site-weit
    $path = rtrim((string) parse_url(isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/', PHP_URL_PATH), '/');
    if (in_array($path, $paths, true)) $cache = $origins;
    return $cache;
}

/** Wert der frame-ancestors-Direktive fuer diese Antwort. */
function webaudits_frame_ancestors_value() {
    $extra = webaudits_frame_ancestor_origins();
    return $extra ? "'self' " . implode(' ', $extra) : "'self'";
}

// ==================================================== 1) XML-RPC komplett dicht
// xmlrpc.php definiert XMLRPC_REQUEST vor wp-load.php -> mu-plugin sieht es früh.
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

// ==================================================== 2) Response-Security-Header
add_action('send_headers', function () {
    if (headers_sent()) return;
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains' . (webaudits_cfg('hsts_preload') ? '; preload' : ''));
    header('X-Content-Type-Options: nosniff');
    // XFO kann keine fremde Origin erlauben — auf Antworten mit erlaubten
    // Fremd-Ancestors muss er entfallen, sonst blockiert er die Einbettung
    // trotz frame-ancestors. Der Schutz kommt dort aus dem eigenen,
    // erzwungenen CSP-Header weiter unten (Prioritaet 1001).
    if (!webaudits_frame_ancestor_origins()) header('X-Frame-Options: SAMEORIGIN');
    // same-origin: intern voller Referrer (WP braucht ihn teils), cross-origin
    // gar keiner — strenger als strict-origin-when-cross-origin, gefahrlos
    // solange kein externer Dienst einen Referrer von uns braucht.
    header('Referrer-Policy: same-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), browsing-topics=()');
    // COEP bewusst NICHT: require-corp bräche externe Embeds (nur nötig für
    // Cross-Origin-Isolation/SharedArrayBuffer).
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    header('X-Permitted-Cross-Domain-Policies: none');
    @header_remove('X-Powered-By');
}, 999);

// ==================================================== 3) Versions-Leaks
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

// ==================================================== 6) CSP (nonce-basiert, dynamisch)
/** Nonce pro Request (einmal berechnet, dann konstant). */
function webaudits_csp_nonce() {
    static $n = null;
    if ($n === null) $n = base64_encode(random_bytes(16));
    return $n;
}

/** Nonce an enqueued <script src="…"> hängen. */
add_filter('script_loader_tag', function ($tag, $handle) {
    if (webaudits_cfg('csp_mode') === 'off' || is_admin()) return $tag;
    if (strpos($tag, ' nonce=') !== false || strpos($tag, '<script') === false) return $tag;
    return preg_replace('/<script\s/', '<script nonce="' . esc_attr(webaudits_csp_nonce()) . '" ', $tag, 1);
}, 11, 2);

/** Nonce auf wp_add_inline_script/wp_script-Ausgabe (WP >= 6.3). */
add_filter('wp_inline_script_attributes', function ($attr) {
    if (webaudits_cfg('csp_mode') !== 'off' && !is_admin()) $attr['nonce'] = webaudits_csp_nonce();
    return $attr;
}, 10, 1);
add_filter('wp_script_attributes', function ($attr) {
    if (webaudits_cfg('csp_mode') !== 'off' && !is_admin() && empty($attr['nonce'])) $attr['nonce'] = webaudits_csp_nonce();
    return $attr;
}, 10, 1);

/** CSP-Header senden (Name je nach Modus). */
add_action('send_headers', function () {
    if (webaudits_cfg('csp_mode') === 'off' || is_admin() || headers_sent()) return;
    if (webaudits_is_etch_editor()) return;   // Builder braucht eval + ws-Bridge
    $n = webaudits_csp_nonce();
    $csp = implode('; ', array(
        "default-src 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        'frame-ancestors ' . webaudits_frame_ancestors_value(),
        "form-action 'self'",
        // Nonce + strict-dynamic ist die eigentliche Policy (CSP3-Browser
        // ignorieren dann 'unsafe-inline' und https: — reine Alt-Browser-
        // Fallbacks, Google-Muster). Jedes script-Tag bekommt die Nonce im
        // Output-Buffer -> externe Skripte laufen ohne Allowlist-Pflege.
        "script-src 'self' 'nonce-$n' 'strict-dynamic' 'unsafe-inline' https:",
        "style-src 'self' 'unsafe-inline'",   // Builder-Inline-style=""-Attribute
        "img-src 'self' data: https:",
        "font-src 'self' data:",
        "connect-src 'self' https:",
        "frame-src 'self' https:",
        "worker-src 'self' blob:",
        "upgrade-insecure-requests",
    ));
    $name = webaudits_cfg('csp_mode') === 'enforce' ? 'Content-Security-Policy' : 'Content-Security-Policy-Report-Only';
    header("$name: $csp");
}, 1000);

/**
 * frame-ancestors IMMER erzwungen — als eigener Header, unabhaengig vom
 * csp_mode. Gruende: (a) Report-Only erzwingt gar nichts, (b) bei csp_mode=off
 * gaebe es sonst nach dem XFO-Wegfall ueberhaupt keinen Framing-Schutz mehr.
 * Zweiter Header ist gewollt: mehrere CSP-Header werden UND-verknuepft.
 * Laeuft NACH dem grossen CSP-Header (1000), damit dessen replace=true den
 * hier gesetzten Wert nicht ueberschreibt.
 */
add_action('send_headers', function () {
    if (is_admin() || headers_sent()) return;
    if (webaudits_is_etch_editor()) return;
    if (webaudits_cfg('csp_mode') === 'enforce') return;   // steckt dort schon drin
    header('Content-Security-Policy: frame-ancestors ' . webaudits_frame_ancestors_value(), false);
}, 1001);

// ==================================================== 7) EIN Output-Buffer:
// (a) Bild-Loading-Fixes, (b) CSP-Nonce an ALLE script-Tags (inline + src).
add_action('template_redirect', function () {
    if (is_admin() || webaudits_is_etch_editor()) return;
    if (webaudits_cfg('csp_mode') === 'off' && !webaudits_cfg('force_lazy_classes')) return;
    ob_start('webaudits_filter_output');
}, 1);

function webaudits_filter_output($html) {
    // (a) fälschlich eager geladene Bilder (WP-LCP-Heuristik) auf lazy zwingen.
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
    // (b) Nonce an jedes script-Tag (auch src/extern — der "dynamische" Teil
    // der CSP; Daten-/Template-Typen überspringen).
    if (webaudits_cfg('csp_mode') !== 'off' && stripos($html, '<script') !== false) {
        $n = webaudits_csp_nonce();
        $html = preg_replace_callback('#<script\b([^>]*)>#i', function ($m) use ($n) {
            $a = $m[1];
            if (stripos($a, 'nonce=') !== false) return $m[0];
            if (preg_match('#type\s*=\s*["\']?(application/(ld\+)?json|text/(template|html))#i', $a)) return $m[0];
            return '<script nonce="' . $n . '"' . $a . '>';
        }, $html);
    }
    return $html;
}

// ==================================================== 8) LocalBusiness-Schema (CPT-getrieben)
add_action('wp_head', function () {
    $lb = webaudits_cfg('localbusiness', array());
    if (empty($lb['enabled']) || !is_page($lb['page'])) return;
    $q = new WP_Query(array('post_type' => $lb['post_type'], 'posts_per_page' => -1, 'post_status' => 'publish'));
    if (!$q->posts) return;
    $f = $lb['fields'];
    $site = webaudits_cfg('site_url');
    $brand = webaudits_cfg('brand_name');
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
            'parentOrganization' => array('@type' => 'Organization', 'name' => $brand, 'url' => $site),
        );
        if (!empty($lb['image'])) $node['image'] = $lb['image'];
        if ($tel) $node['telephone'] = '+49' . preg_replace('/\D+/', '', preg_replace('/^0/', '', $tel));
        $nodes[] = $node;
    }
    if (!$nodes) return;
    echo '<script type="application/ld+json">' . wp_json_encode(array('@context' => 'https://schema.org', '@graph' => $nodes), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . '</script>' . "\n";
}, 20);

// ==================================================== 9) GTM consent-gated + WS-Form-Bridge

/** Ist Pressidium Cookie Consent aktiv? Relevant für consent_provider=pressidium.
 *  Slug aus echten Site-Daten verifiziert; is_plugin_active ist der zuverlässige Check. */
function webaudits_pressidium_active() {
    if (!function_exists('is_plugin_active')) require_once ABSPATH . 'wp-admin/includes/plugin.php';
    return is_plugin_active('pressidium-cookie-consent/pressidium-cookie-consent.php');
}

/**
 * Liefert die Attribute für das consent-gated GTM-<script> je nach consent_provider.
 * Rückgabe: array($attrs, $grant).
 *   $attrs === null  -> nicht emittieren (Provider nicht einsatzbereit, z. B. Pressidium inaktiv)
 *   $attrs === ''    -> plain <script> (provider=none): lädt, bleibt aber cookielos
 *   sonst            -> '<script '.$attrs.'>' (text/plain, vom Consent-Manager aktiviert)
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
    // pressidium (Default): nur wenn aktiv, sonst inert
    if (!webaudits_pressidium_active()) return array(null, false);
    return array('type="text/plain" data-cookiecategory="' . esc_attr($category) . '"', true);
}

// Admin-Warnung: Pressidium als Consent-Provider gewählt, aber Plugin nicht aktiv -> GTM-Gating inaktiv.
add_action('admin_notices', function () {
    if (!current_user_can('manage_options')) return;
    if (!webaudits_cfg('gtm_id')) return;
    if (webaudits_cfg('consent_provider', 'pressidium') !== 'pressidium') return;
    if (webaudits_pressidium_active()) return;
    echo '<div class="notice notice-warning"><p><strong>WebAudits Suite:</strong> ' . esc_html(webaudits_txt(
        'consent_provider = pressidium, aber das Pressidium-Cookie-Consent-Plugin ist nicht aktiv — das GTM-Consent-Gating ist deshalb inaktiv (GTM wird nicht geladen). consent_provider auf "iubenda" oder "none" setzen, oder Pressidium aktivieren.',
        'consent_provider = pressidium, but the Pressidium Cookie Consent plugin is not active — GTM consent-gating is therefore inactive (GTM is not loaded). Set consent_provider to "iubenda" or "none", or activate Pressidium.'
    )) . '</p></div>';
});

// Consent Mode v2 Defaults — immer, VOR GTM (speichert nichts, DSGVO-ok).
add_action('wp_head', function () {
    if (!webaudits_cfg('gtm_id') && !webaudits_cfg('ga4_id')) return;
    ?>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}
gtag('consent','default',{ad_storage:'denied',ad_user_data:'denied',ad_personalization:'denied',analytics_storage:'denied',wait_for_update:500});</script>
    <?php
}, 4);

// GTM-Loader — consent-gated je nach consent_provider:
//  - pressidium: <script type="text/plain" data-cookiecategory> (Pressidium flippt nach Consent).
//    Nur wenn Pressidium aktiv, sonst inert (kein toter Script) + Admin-Warnung.
//  - iubenda:    <script type="text/plain" class="_iub_cs_activate"> (iubenda aktiviert nach Consent).
//  - none:       plain <script> ohne Consent-Grant -> GTM lädt, bleibt aber cookielos (Consent Mode denied).
// Kein noscript-iframe (würde vor Consent feuern).
add_action('wp_head', function () {
    if (!webaudits_cfg('gtm_id')) return;
    $id  = esc_js(webaudits_cfg('gtm_id'));
    $cat = webaudits_cfg('consent_category', 'analytics');
    list($attrs, $grant) = webaudits_consent_gate($cat);
    if ($attrs === null) return; // Provider gewählt aber nicht einsatzbereit (z. B. Pressidium inaktiv)
    $loader = "(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src='https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);})(window,document,'script','dataLayer','" . $id . "');";
    if ($attrs === '') {
        echo "<script>\n" . $loader . "\n</script>\n";
    } else {
        echo '<script ' . $attrs . ">\ngtag('consent','update',{analytics_storage:'granted'});\n" . $loader . "\n</script>\n";
    }
}, 5);

// ==================================================== 9b) GA4 direkt (gtag) — Alternative zu GTM
// Läuft NUR ohne GTM-Container (sonst zählt jede Seite doppelt — GTM gewinnt).
// Consent Mode v2: die Defaults oben (Prio 4) stehen VOR diesem Loader; GA4
// läuft cookielos, bis der Consent-Manager analytics_storage granted meldet.
add_action('wp_head', function () {
    if (!webaudits_cfg('ga4_id') || webaudits_cfg('gtm_id') || is_admin() || is_user_logged_in()) return;
    $id = webaudits_cfg('ga4_id');
    if (!preg_match('/^G-[A-Z0-9]+$/', $id)) return;
    echo '<script async src="https://www.googletagmanager.com/gtag/js?id=' . esc_attr($id) . '"></script>' . "
";
    echo "<script>gtag('js',new Date());gtag('config','" . esc_js($id) . "');</script>
";
}, 6);

// Doppel-Tracking-Sperre sichtbar machen: beide IDs gesetzt -> Warnung im Admin.
add_action('admin_notices', function () {
    if (!current_user_can('manage_options')) return;
    if (webaudits_cfg('gtm_id') && webaudits_cfg('ga4_id')) {
        echo '<div class="notice notice-warning"><p><strong>WebAudits Suite:</strong> ' . esc_html(webaudits_txt(
            'GTM-Container UND GA4-Mess-ID sind konfiguriert — GA4-direkt ist deshalb deaktiviert (Doppel-Tracking-Sperre). GA4 im GTM-Container konfigurieren oder eine der IDs leeren (Werkzeuge → WebAudits Suite).',
            'Both a GTM container AND a GA4 measurement ID are configured — direct GA4 is therefore disabled (double-tracking guard). Configure GA4 inside the GTM container or clear one of the IDs (Tools → WebAudits Suite).'
        )) . '</p></div>';
    }
});

// WS-Form-Bridge: offizielles document-Event `wsf-submit-success` (WS-Form-Doku).
add_action('wp_footer', function () {
    if (!webaudits_cfg('gtm_id') || !webaudits_cfg('wsf_bridge_event')) return;
    $event = esc_js(webaudits_cfg('wsf_bridge_event'));
    ?>
<script>document.addEventListener('wsf-submit-success',function(e){var d=(e&&e.detail)||{};window.dataLayer=window.dataLayer||[];window.dataLayer.push({event:'<?php echo $event; ?>',form_id:String(d.form_id||d.id||''),page_location:location.href});});</script>
    <?php
}, 20);

// ==================================================== 10) Admin/Backend-Aufräumen
// Datei-Editor aus (Security: kein Code-Editing über kompromittierte Admin-Session).
if (webaudits_cfg('disable_file_editor') && !defined('DISALLOW_FILE_EDIT')) {
    define('DISALLOW_FILE_EDIT', true);
}

// Login-Fehler verschleiern (kein Username-Enumeration-Hinweis).
if (webaudits_cfg('generic_login_errors')) {
    add_filter('login_errors', function () {
        return webaudits_txt(
            'Anmeldung fehlgeschlagen: Benutzername oder Passwort ist nicht korrekt.',
            'Login failed: username or password is incorrect.'
        );
    });
}

// Dashboard bereinigen: Standard-Widgets, Willkommens-Panel, Plugin-Widgets.
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

// Visuelle Überreste (leere Container, Community-Events-Footer).
add_action('admin_head', function () {
    if (!webaudits_cfg('admin_cleanup')) return;
    echo '<style>#dashboard-widgets .empty-container,.dashboard-post-browser,.community-events-footer{display:none !important;}</style>';
}, 100);

// Benutzer-Liste: sortierbare Spalte "Letzter Login".
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
        // wp_date = Site-Zeitzone (date() wäre UTC).
        return $ts ? wp_date('d.m.Y H:i', $ts) : '—';
    }, 10, 3);
    add_filter('manage_users_sortable_columns', function ($columns) {
        $columns['last_login'] = 'last_login';
        return $columns;
    });
    add_action('pre_get_users', function ($query) {
        if (!is_admin() || ($_GET['orderby'] ?? '') !== 'last_login') return;
        // OR-meta_query, damit Benutzer OHNE last_login beim Sortieren nicht
        // aus der Liste fallen (der klassische meta_key-Ansatz filtert sie weg).
        $query->set('meta_query', array(
            'relation' => 'OR',
            'last_login_clause' => array('key' => 'last_login', 'compare' => 'EXISTS', 'type' => 'NUMERIC'),
            array('key' => 'last_login', 'compare' => 'NOT EXISTS'),
        ));
        $query->set('orderby', array('last_login_clause' => strtoupper($_GET['order'] ?? 'DESC') === 'ASC' ? 'ASC' : 'DESC'));
    });
}

// ==================================================== 11) Kommentare komplett aus
if (webaudits_cfg('disable_comments')) {
    // Support von allen Post-Types entfernen + überall schließen.
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
    // Bestehende Kommentare nirgends mehr ausgeben.
    add_filter('comments_array', '__return_empty_array', 20);
    // Kommentar-Feed-Links aus dem <head> (feed_links + feed_links_extra).
    add_filter('feed_links_show_comments_feed', '__return_false');
    add_filter('feed_links_extra_show_post_comments_feed', '__return_false');
    // Admin: Menüpunkt weg, Kommentar-Seite umleiten, Adminbar-Blase weg.
    add_action('admin_menu', function () { remove_menu_page('edit-comments.php'); });
    add_action('admin_init', function () {
        global $pagenow;
        if ($pagenow === 'edit-comments.php') { wp_safe_redirect(admin_url()); exit; }
    });
    add_action('admin_bar_menu', function ($bar) { $bar->remove_node('comments'); }, 999);
    // REST-Endpunkte entfernen (sonst bleiben Kommentare per API lesbar).
    add_filter('rest_endpoints', function ($endpoints) {
        unset($endpoints['/wp/v2/comments'], $endpoints['/wp/v2/comments/(?P<id>[\d]+)']);
        return $endpoints;
    });
}

// ==================================================== 11b) Explizite 301-Redirects
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

// ==================================================== 12) Privacy-Policy aus CPT
// WP Settings → Datenschutz baut den Seiten-Dropdown mit wp_dropdown_pages()
// und listet nur `page`. Wir hängen die CPT-Posts als <option> an — beim
// Speichern legt WP `wp_page_for_privacy_policy` = gewählte ID ab (ohne
// post_type-Prüfung), get_privacy_policy_url() funktioniert für jeden Posttyp.
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

// ==================================================== 14) Self-Update (GitHub-Releases)
// Kanonisches Repo (öffentlich, kein Token nötig). Ein Release = ein Tag vX.Y.Z;
// der Cron vergleicht 2x täglich und ersetzt NUR webaudits-suite.php — die
// Site-Konfig (webaudits-config.php) und die DB-Option bleiben unberührt.
const WEBAUDITS_SUITE_VERSION = '3.2.0';
const WEBAUDITS_SUITE_REPO = 'tobiashaas/webaudits-suite';

add_action('init', function () {
    if (!wp_next_scheduled('webaudits_update_check')) {
        wp_schedule_event(time() + HOUR_IN_SECONDS, 'twicedaily', 'webaudits_update_check');
    }
});
add_action('webaudits_update_check', 'webaudits_run_update_check');

function webaudits_run_update_check() {
    $status = array('checked_at' => time(), 'current' => WEBAUDITS_SUITE_VERSION, 'error' => '');
    // Version UND Code in EINEM Request von raw.githubusercontent.com.
    //
    // Warum nicht api.github.com/releases/latest: die API ist pro IP auf 60
    // Requests/Stunde limitiert. Auf Shared Hosting teilen sich alle Kunden
    // eine Ausgangs-IP, dort ist das Kontingent praktisch immer aufgebraucht —
    // am 2026-07-22 auf Strato (81.169.144.135) gemessen: HTTP 403,
    // "remaining: 0". Der Updater lief dadurch NIE. raw.githubusercontent.com
    // liegt auf einem CDN ohne dieses Limit (gleiche Messung: HTTP 200).
    //
    // VERTRAG: der main-Branch ist immer die aktuellste Release-Fassung —
    // die Version wird erst beim Release angehoben, nicht waehrend der Arbeit.
    $raw = wp_remote_get('https://raw.githubusercontent.com/' . WEBAUDITS_SUITE_REPO . '/main/webaudits-suite.php', array(
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
    // HART validieren, bevor irgendetwas ersetzt wird — eine kaputte
    // mu-plugin-Datei legt die ganze Site lahm.
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
    $file = WPMU_PLUGIN_DIR . '/webaudits-suite.php';
    if (@file_put_contents($file . '.new', $code) === false || !@copy($file, $file . '.bak') || !@rename($file . '.new', $file)) {
        $status['error'] = 'write_failed';
        update_option('webaudits_suite_update_status', $status, false);
        return $status;
    }
    $status['updated_to'] = $latest;
    $status['updated_at'] = time();
    update_option('webaudits_suite_update_status', $status, false);
    return $status;
}

// ==================================================== 13) Admin-Übersicht (Werkzeuge)
add_action('admin_menu', function () {
    add_management_page('WebAudits Suite', 'WebAudits Suite', 'manage_options', 'webaudits-suite', 'webaudits_admin_page');
});

function webaudits_admin_page() {
    $T = 'webaudits_txt';
    // Speichern (Settings-UI): nur die UI-Schlüssel, Checkboxen explizit 0/1.
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
    // Übersicht zeigt den WIRKSAMEN Wert (Datei-Default + UI-Override gemerged).
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
        array($T('Version / Self-Update', 'Version / self-update'), $on,
            $upd_txt . ' — ' . $T('2×/Tag automatisch aus', 'auto twice a day from') . ' <a href="https://github.com/' . esc_attr(WEBAUDITS_SUITE_REPO) . '/releases" target="_blank">github.com/' . esc_html(WEBAUDITS_SUITE_REPO) . '</a>'),
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
                    : ('iubenda' === webaudits_cfg('consent_provider', 'pressidium') ? ' (<code>_iub_cs_activate</code>)' : ' (' . $T('kein Gating — cookielos', 'no gating — cookieless') . ')'))
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
            ? count($c['redirects']) . ' Redirect(s): ' . esc_html(implode(', ', array_map(function ($k, $v) { return "$k→$v"; }, array_keys($c['redirects']), $c['redirects']))) : $na),
    );
    // Unkonfigurierte Module (Status aus, keine Details) nicht listen.
    $rows = array_values(array_filter($rows, function ($r) { return $r[2] !== '—'; }));
    ?>
    <div class="wrap">
        <h1>WebAudits Suite</h1>
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
                        'Consent-gated über Pressidium; braucht Pressidium-Option <code>page_scripts</code> = an. Leer = aus.',
                        'Consent-gated via Pressidium; requires Pressidium option <code>page_scripts</code> = on. Empty = off.'
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
