<?php
/**
 * WebAudits Suite — site configuration (template).
 *
 * Copy this file as `webaudits-config.php`:
 *   - must-use install: into wp-content/mu-plugins/ (next to webaudits-suite.php)
 *   - regular-plugin install: into wp-content/ (outside the plugin folder)
 * Only keys that differ from the defaults need to be set; everything here is
 * optional. This file survives every self-update of the suite. The operational
 * values (IDs, switches, CSP mode) can also be edited under Tools → WebAudits Suite.
 */
if (!defined('ABSPATH')) exit;

define('WEBAUDITS_CONFIG_SITE', array(
    // Site identity. Empty = taken from the WordPress settings.
    'site_url'          => '',              // e.g. 'https://example.com' (no trailing slash)
    'brand_name'        => '',              // e.g. 'Example Ltd'

    // security.txt (RFC 9116) — only served when a contact is set.
    'security_contact'  => '',              // e.g. 'mailto:security@example.com'
    'security_expires'  => '2027-01-01T00:00:00.000Z',   // max. 1 year ahead, renew in time

    // Content-Security-Policy. Start with report-only, switch to enforce once the
    // console shows zero violations (logged out, before and after consent).
    'csp_mode'          => 'report-only',   // 'off' | 'report-only' | 'enforce'
    'csp_admins'        => 'same',          // logged-in admins: 'same' | 'report-only' | 'off' (e.g. the ACSS dashboard needs eval)
    // Inline event handlers allowed by hash (exact text). The default covers deferred CSS loading.
    // 'csp_handler_hashes' => array("this.media='all';this.onload=null", "this.media='all'", "this.onload=null;this.media='all'"),

    // Foreign origins allowed to embed this site. Empty = nobody.
    // X-Frame-Options is dropped on the affected responses (it cannot express
    // a foreign origin); protection comes from an enforced frame-ancestors
    // header instead. Empty 'paths' = site-wide.
    'frame_ancestors'   => array(
        'origins' => array(),           // e.g. array('https://lms.example.com')
        'paths'   => array(),           // e.g. array('/privacy', '/imprint')
    ),

    'theme_color'       => '',              // e.g. '#E30613'

    // Tracking. GTM is only loaded after consent, through the consent manager below.
    // If your consent manager loads GTM itself (Borlabs Cookie, Complianz, Real Cookie
    // Banner, …), leave gtm_id empty.
    'gtm_id'            => '',              // 'GTM-XXXXXXX'
    'ga4_id'            => '',              // 'G-XXXXXXXXXX' — only WITHOUT GTM (double-tracking lock)
    'consent_provider'  => 'pressidium',    // 'pressidium' | 'iubenda' | 'custom' | 'none'
    // consent_provider = custom: attributes of the inert GTM script, e.g. Cookiebot:
    // 'consent_script_attrs' => array('type' => 'text/plain', 'data-cookieconsent' => 'statistics'),

    'disable_comments'  => false,           // true = comments completely off
    'privacy_cpt'       => '',              // CPT slug whose posts can be selected as the privacy policy page
    'redirects'         => array(),         // array('/old/' => '/new/')

    // Self-update from GitHub (twice a day). false = pin the current version.
    'self_update'       => true,
    // 'update_repo'    => 'you/your-fork',
));
