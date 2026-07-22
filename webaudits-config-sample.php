<?php
/**
 * WebAudits Suite — Site-Konfiguration (Vorlage).
 * Kopiere diese Datei als `webaudits-config.php` neben webaudits-suite.php in
 * wp-content/mu-plugins/ und trage die Werte deiner Site ein. Nur Schlüssel,
 * die vom Default abweichen, müssen gesetzt werden. Diese Datei überlebt jedes
 * Self-Update der Suite. Die operativen Werte (IDs, Schalter, CSP-Modus) sind
 * zusätzlich unter Werkzeuge/Tools → WebAudits Suite editierbar.
 */
if (!defined('ABSPATH')) exit;

define('WEBAUDITS_CONFIG_SITE', array(
    'site_url'          => 'https://example.com',
    'brand_name'        => 'Example',
    'security_contact'  => 'mailto:security@example.com',
    'security_expires'  => '2027-01-01T00:00:00.000Z',
    'csp_mode'          => 'report-only',   // 'off' | 'report-only' | 'enforce'
    // Fremde Origins, die diese Site einbetten duerfen. Leer = niemand.
    // Auf den betroffenen Antworten entfaellt X-Frame-Options (kann keine
    // fremde Origin ausdruecken); der Schutz kommt aus einem erzwungenen
    // frame-ancestors-Header. 'paths' leer = site-weit.
    'frame_ancestors'   => array(
        'origins' => array(),           // z. B. array('https://lms.example.com')
        'paths'   => array(),           // z. B. array('/datenschutz', '/impressum')
    ),
    'theme_color'       => '',              // z. B. '#E30613'
    'gtm_id'            => '',              // 'GTM-XXXXXXX' — consent-gated (Pressidium page_scripts = an)
    'ga4_id'            => '',              // 'G-XXXXXXXXXX' — nur OHNE GTM (Doppel-Tracking-Sperre)
    'disable_comments'  => true,
    'privacy_cpt'       => '',              // CPT-Slug, dessen Posts als Datenschutzseite wählbar sind
    'redirects'         => array(),         // array('/alt/' => '/neu/')
));
