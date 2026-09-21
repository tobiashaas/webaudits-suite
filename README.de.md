# WebAudits Suite

**Ein einziges Must-Use-Plugin für die komplette WordPress-Hardening- und Tracking-Basis** — Security-Header, nonce-basierte CSP, Admin-Aufräumen, Kommentare-aus, consent-gated Google Tag Manager *oder* GA4-direkt (gegenseitig exklusiv, mit eingebauter Doppel-Tracking-Sperre) und ein Self-Update-Mechanismus, der jede Site automatisch auf dem neuesten Release hält.

🇬🇧 *English version (main): [README.md](README.md)*

Gebaut für den Stack **WordPress + Etch + Automatic.css + Pressidium Cookie Consent + SEOPress + WS Form** — läuft aber auf jeder WordPress-Installation. Kein Build-Schritt, kein Composer, keine Abhängigkeiten: zwei einfache PHP-Dateien.

---

## Funktionen

| Modul | Was es tut |
|---|---|
| **Security-Header** | HSTS (optional `preload`), `X-Content-Type-Options: nosniff`, `X-Frame-Options`, `Referrer-Policy: same-origin`, `Permissions-Policy`, COOP/CORP, `X-Permitted-Cross-Domain-Policies`; entfernt `X-Powered-By`. Bewusst **kein** COEP (bräche externe Embeds). |
| **Einbettung (`frame_ancestors`)** | Erlaubt benannten fremden Origins, die Site per `<iframe>` einzubetten — optional nur auf bestimmten Pfaden (z. B. ein LMS, das die Datenschutzseite einbindet). `X-Frame-Options` kann keine fremde Origin ausdrücken (`ALLOW-FROM` ist tot), entfällt deshalb auf genau diesen Antworten und wird durch einen **immer erzwungenen** `Content-Security-Policy: frame-ancestors …`-Header ersetzt — auch im `report-only`-Modus, der nichts erzwingen würde. Default: nur die eigene Origin. |
| **Content-Security-Policy** | Nonce-basiert + `strict-dynamic`. Ein einziger Output-Buffer hängt die Per-Request-Nonce an *jedes* Script-Tag — auch an rohe Inline-Scripts von Buildern und Plugins, die die WP-Script-API umgehen — externe Skripte laufen daher ohne Allowlist-Pflege. Drei Modi: `off` → `report-only` → `enforce`. Die Etch-Builder-Ansicht (`?etch=magic`) ist automatisch ausgenommen. |
| **Versions-Leak-Fixes** | Entfernt das `generator`-Meta und Generator-Strings. |
| **XML-RPC-Block** | `POST /xmlrpc.php` → 403; Pingback-Header und RSD-Link entfernt. |
| **security.txt** | Liefert `/.well-known/security.txt` (RFC 9116) aus der Konfiguration — keine physische Datei nötig. |
| **theme-color / color-scheme** | Gibt das Marken-`<meta name="theme-color">` und `color-scheme` aus. |
| **Bild-Loading-Fix** | Erzwingt optional `loading="lazy"` (und entfernt `fetchpriority`) für Bilder mit passender Klasse — für Fälle, in denen die LCP-Heuristik von WordPress danebengreift (z. B. wenn der echte Hero ein Canvas ist). |
| **LocalBusiness-Schema** | Optionales CPT-getriebenes `LocalBusiness`-JSON-LD (Multi-Standort) auf einer gewählten Seite. Optional `parent` (Name + URL) nennt den Rechtsträger, wenn die Site eine Marke einer größeren Firma ist (Standard: `brand_name`). Aus lassen, wenn das SEO-Plugin die Schemas besitzt. |
| **Google Tag Manager** | Consent-gated Container: als `<script type="text/plain" data-cookiecategory="…">` gerendert, wird von Pressidium Cookie Consent erst nach Einwilligung freigeschaltet — **null Google-Requests vor Consent**, kein `noscript`-iframe. Consent-Mode-v2-Defaults (`denied`) stehen immer davor. Braucht die Pressidium-Option `page_scripts` = an. |
| **GA4 direkt (gtag.js)** | Alternative zu GTM für einfache Sites. **Gegenseitig exklusiv:** Ist eine GTM-Container-ID gesetzt, bleibt GA4-direkt gesperrt und eine Admin-Notice erklärt warum — ein Tracking-Pfad, nie zwei (Doppel-Tracking-Sperre). |
| **WS-Form-Lead-Bridge** | Pusht bei `wsf-submit-success` ein dataLayer-Event (z. B. `generate_lead`) mit `form_id` — bereit für einen GTM-Trigger. |
| **Admin-Aufräumen** | Entfernt Dashboard-Widgets, Willkommens-Panel und eine konfigurierbare Liste von Plugin-Widgets; blendet leere Container aus. |
| **Kommentare aus** | Komplett: Frontend geschlossen, Bestand ausgeblendet, Admin-Menü/Adminbar-Einträge entfernt, REST-Endpunkte entfernt, Feed-Links aus dem `<head>`. |
| **Login-Härtung** | Generische Login-Fehlermeldung (keine Username-Enumeration), `DISALLOW_FILE_EDIT`, sortierbare „Letzter Login"-Spalte in der Benutzerliste. |
| **Datenschutzseite aus CPT** | Macht Posts eines Custom Post Types als Datenschutzseite wählbar (WordPress erlaubt nativ nur `page`). |
| **301-Redirects** | Explizite Pfad-zu-Pfad-Redirects aus der Konfiguration (deckt Slug-Umbenennungen root-basierter CPTs ab, bei denen WPs Alt-Slug-Redirect nicht greift). |
| **Settings-UI** | **Werkzeuge → WebAudits Suite**: Status-Übersicht aller konfigurierten Module (wirksame, gemergte Werte) plus Formular für die operativen Werte. Zweisprachig — Englisch/Deutsch folgt der Sprache des Admin-Benutzers. |
| **Self-Update** | Die Suite prüft 2×/Tag die [Releases](../../releases) dieses Repos und ersetzt sich selbst. Jeder Download wird vor dem Einspielen hart validiert; die Vorversion bleibt als `.bak` liegen. Manueller Prüf-Button inklusive. |

## Voraussetzungen

- WordPress 6.x+ (getestet bis 7.x), PHP 7.4+
- Für consent-gated GTM: [Pressidium Cookie Consent](https://wordpress.org/plugins/pressidium-cookie-consent/) mit aktiviertem `page_scripts`
- Alles andere läuft standalone

## Installation

1. **`webaudits-suite.php`** nach `wp-content/mu-plugins/` kopieren (Must-Use-Plugins sind auto-aktiv; Ordner ggf. anlegen).
2. **`webaudits-config-sample.php`** als `wp-content/mu-plugins/webaudits-config.php` kopieren und die Werte der Site eintragen.
3. **Werkzeuge → WebAudits Suite** in wp-admin öffnen: Modul-Übersicht prüfen, operative Werte setzen (GTM-/GA4-ID, CSP-Modus, Schalter).

Das war's — kein Aktivierungs-Screen, keine Datenbank-Migration.

## Konfiguration — drei Ebenen

Werte lösen in dieser Reihenfolge auf (später gewinnt):

1. **Generische Defaults** in `webaudits-suite.php` — nie editieren; der Self-Updater ersetzt diese Datei.
2. **`webaudits-config.php`** — die Site-Werte via `define('WEBAUDITS_CONFIG_SITE', array(...))`. Überlebt jedes Update. Nur Schlüssel setzen, die vom Default abweichen.
3. **Settings-UI** (Werkzeuge → WebAudits Suite) — die operative Teilmenge (GTM-/GA4-ID, CSP-Modus, Kommentar-/Admin-/XML-RPC-/Login-Schalter, Theme-Color, HSTS-preload) als DB-Option. **Überstimmt beide Dateien.**

## CSP-Rollout

Mit `report-only` starten (Default). Die Browser-Konsole über alle Seitentypen beobachten; sobald **null** Violations gemeldet werden, in der UI auf `enforce` schalten. Der Nonce-Buffer der Suite deckt Builder-Inline-Scripts ab — die meisten Sites brauchen keinerlei Policy-Anpassung.

**Eingeloggte Administratoren** lassen sich über **CSP für Administratoren** (`csp_admins`: `same` | `report-only` | `off`, Standard `same`) lockern. Sinnvoll, wenn ein reines Admin-Werkzeug im Frontend `eval` braucht, z. B. das Automatic.css-Frontend-Dashboard. Besucher bekommen immer `csp_mode`; der separate `frame-ancestors`-Header bleibt für alle erzwungen.

## Self-Update — wie es funktioniert und warum es sicher ist

- Ein WP-Cron-Event (2×/Tag) fragt `GET /repos/tobiashaas/webaudits-suite/releases/latest` ab — anonym, **kein Token, kein Secret auf der Kundensite**.
- Ist der Release-Tag neuer als die laufende `WEBAUDITS_SUITE_VERSION`, wird die Rohdatei aus dem getaggten Commit geladen.
- Bevor irgendetwas ersetzt wird, muss der Download **alle** Prüfungen bestehen: beginnt mit `<?php`, plausible Größe, enthält den exakten neuen Versions-Marker, Klammer-Balance und ein echter PHP-Parse-Check (`token_get_all(..., TOKEN_PARSE)`) — eine kaputte Must-Use-Datei würde die ganze Site lahmlegen, deshalb geht nichts Unvalidiertes live.
- Der Tausch ist atomar (`.new` → rename), die Vorversion bleibt als `webaudits-suite.php.bak` für sofortiges Rollback liegen.
- Es wird nur `webaudits-suite.php` angefasst — `webaudits-config.php` und die DB-Option bleiben unberührt.
- Status (Version, letzte Prüfung, verfügbares Update) steht auf der Werkzeuge-Seite, samt Button **„Jetzt auf Updates prüfen"**.

## Release-Flow (Maintainer)

1. `webaudits-suite.php` ändern — **beides** bumpen: `WEBAUDITS_SUITE_VERSION` und den `Version:`-Header (müssen übereinstimmen; der Updater prüft den Marker).
2. Commit, Tag `vX.Y.Z`, GitHub-Release anlegen.
3. Fertig — jede Site zieht es innerhalb von ~12 Stunden (oder sofort über den Button).

## Bewusst nicht enthalten

- Kompression, Asset-Cache, WebP-Negotiation, statisches Blocken von `readme.html`/`license.txt`/`xmlrpc.php` → gehört in die **`.htaccess`** (bzw. Server-Konfig), nicht in PHP.
- DNS-Härtung (CAA, DNSSEC), HTTP/2, `ServerTokens` → Hoster-Panel.
- SEO-Metas und Per-Post-Schemas → das SEO-Plugin (wir nutzen SEOPress).

## Lizenz

[MIT](LICENSE) © Tobias Haas
