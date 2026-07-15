# WebAudits Suite

Ein einziges WordPress-**mu-plugin** für den kompletten Site-Hardening- und
Tracking-Unterbau: Security-Header, nonce-basierte CSP (Report-Only → Enforce),
Versions-Leak-Fixes, XML-RPC-Block, `security.txt`, Dashboard-Bereinigung,
Kommentar-Deaktivierung, Login-Härtung, Privacy-CPT-Unterstützung, 301-Redirects,
consent-gated Google Tag Manager **oder** GA4-direkt (gegenseitig exklusiv,
Doppel-Tracking-Sperre) und eine WS-Form→dataLayer-Lead-Bridge.
Admin-UI (zweisprachig de/en) unter **Werkzeuge → WebAudits Suite**.

Gebaut für den Stack WordPress + Etch + Automatic.css + Pressidium Cookie
Consent + SEOPress + WS Form — läuft aber auf jedem WordPress.

## Installation

1. `webaudits-suite.php` nach `wp-content/mu-plugins/` kopieren (auto-aktiv).
2. `webaudits-config-sample.php` als `webaudits-config.php` daneben legen und
   die Site-Werte eintragen.
3. Operative Werte (GTM-/GA4-ID, CSP-Modus, Schalter) unter
   **Werkzeuge → WebAudits Suite** pflegen — die DB-Option überstimmt die Datei.

## Self-Update

Die Suite prüft 2×/Tag die [Releases](../../releases) dieses Repos und ersetzt
sich selbst (nur `webaudits-suite.php`; Konfig und DB-Option bleiben unberührt).
Jeder Download wird vor dem Einspielen hart validiert (Version-Marker,
Klammer-Balance, PHP-Parse-Check), die Vorversion bleibt als `.bak` liegen.
Manuell: Button „Jetzt auf Updates prüfen" auf der Werkzeuge-Seite.

## Release-Flow (Maintainer)

1. `webaudits-suite.php` ändern, `WEBAUDITS_SUITE_VERSION` UND den
   `Version:`-Header bumpen.
2. Commit + Tag `vX.Y.Z` + GitHub-Release — fertig; die Sites ziehen es selbst.
