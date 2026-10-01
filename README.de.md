# WebAudits Suite

**Ein selbst aktualisierendes WordPress-Plugin für die Sicherheits- und Tracking-Basis einer Website** — Security-Header, nonce-basierte Content-Security-Policy, Versions-Leak-Fixes, consent-gated Google Tag Manager *oder* GA4, Admin-Aufräumen, Konten-Allowlist mit Sicherheits-Log und erzwungene Core-Sicherheitsupdates.

🇬🇧 *English version (main): [README.md](README.md)*

Läuft auf jeder WordPress-Site. Kein Build-Schritt, kein Composer, keine Abhängigkeiten: zwei PHP-Dateien (das Plugin und die Konfiguration der Site). Im Einsatz auf Sites mit Etch, Bricks, Automatic.css, SEOPress und WS Form, mit Pressidium Cookie Consent, Borlabs Cookie oder iubenda als Consent-Manager.

---

## Funktionen

| Modul | Was es tut |
|---|---|
| **Security-Header** | HSTS (optional `preload`), `X-Content-Type-Options: nosniff`, `X-Frame-Options`, `Referrer-Policy: same-origin`, `Permissions-Policy`, COOP/CORP, `X-Permitted-Cross-Domain-Policies`; entfernt `X-Powered-By`. Bewusst **kein** COEP (bräche externe Embeds). |
| **Einbettung (`frame_ancestors`)** | Erlaubt benannten fremden Origins, die Site per `<iframe>` einzubetten, optional nur auf bestimmten Pfaden (z. B. ein LMS, das die Datenschutzseite einbindet). `X-Frame-Options` kann keine fremde Origin ausdrücken, entfällt deshalb auf genau diesen Antworten und wird durch einen **immer erzwungenen** `frame-ancestors`-Header ersetzt. Standard: nur die eigene Origin. |
| **Content-Security-Policy** | Nonce-basiert + `strict-dynamic`. Ein Output-Buffer hängt die Nonce an *jedes* Script-Tag — auch an Inline-Scripts von Buildern und Plugins —, externe Skripte laufen ohne Allowlist-Pflege. Modi: `off` → `report-only` → `enforce`. Bearbeitungsansichten von Page-Buildern sind für eingeloggte Redakteure ausgenommen (siehe unten). |
| **Versions-Leak-Fixes** | Entfernt das `generator`-Meta und Generator-Strings. |
| **XML-RPC-Block** | `POST /xmlrpc.php` → 403; Pingback-Header und RSD-Link entfernt. |
| **security.txt** | Liefert `/.well-known/security.txt` (RFC 9116) aus der Konfiguration, sobald ein Kontakt eingetragen ist. |
| **theme-color / color-scheme** | Gibt `<meta name="theme-color">` und `color-scheme` aus. |
| **Bild-Loading-Fix** | Erzwingt optional `loading="lazy"` (und entfernt `fetchpriority`) für Bilder mit einer bestimmten Klasse. |
| **LocalBusiness-Schema** | Optionales CPT-getriebenes `LocalBusiness`-JSON-LD (mehrere Standorte) auf einer Seite. Aus lassen, wenn das SEO-Plugin die Schemas liefert. |
| **Google Tag Manager** | Consent-gated Container: als inaktives `<script type="text/plain" …>` ausgegeben, das der Consent-Manager erst nach Einwilligung freischaltet — **null Google-Requests vor Einwilligung**. Consent-Mode-v2-Defaults (`denied`) stehen immer davor. Siehe [Consent-Manager](#consent-manager). |
| **GA4 direkt (gtag.js)** | Alternative zu GTM für einfache Sites. **Gegenseitig exklusiv:** Ist eine GTM-ID gesetzt, bleibt GA4-direkt gesperrt (Doppel-Tracking-Sperre). |
| **WS-Form-Lead-Bridge** | Pusht bei `wsf-submit-success` ein dataLayer-Event (z. B. `generate_lead`) mit `form_id`. |
| **Admin-Aufräumen** | Entfernt Dashboard-Widgets, Willkommens-Panel und eine konfigurierbare Liste von Plugin-Widgets. |
| **Kommentare aus** (einschaltbar) | Komplett: Frontend geschlossen, Bestand ausgeblendet, Admin-Menü/Adminbar-Einträge und REST-Endpunkte entfernt, Feed-Links weg. |
| **Login-Härtung** | Generische Login-Fehlermeldung, `DISALLOW_FILE_EDIT`, sortierbare „Letzter Login"-Spalte. |
| **Konten & Sicherheit** | **User Guard:** neue Konten nur mit erlaubter E-Mail-Domain. REST, Profil und Registrierung lehnen fremde Adressen ab; ein Backstop auf `user_register`/`set_user_role` fängt auch `wp_insert_user()` und Rechte-Eskalation. Ein fremdes Konto wird **entschärft, nicht gelöscht** (Rolle weg, Passwort zufällig, Sessions beendet, Mail an die Admin-Adresse) — es bleibt Beweismittel. Die Domain der Admin-Adresse ist immer erlaubt; ohne eingetragene Domain wird nur protokolliert. **Sicherheits-Log:** eigene Tabelle mit Akteur, IP, User-Agent, Request und Kontext; 180 Tage, CSV-Export. **Core-Sicherheitsupdates:** Minor-/Security-Releases der installierten `X.Y`-Reihe laufen durch, auch wenn ein Hoster-Tool (z. B. Installatron) Core-Updates abschaltet. |
| **Datenschutzseite aus CPT** | Macht Beiträge eines Custom Post Types als Datenschutzseite wählbar. |
| **301-Redirects** | Explizite Pfad-zu-Pfad-Weiterleitungen aus der Konfiguration. |
| **Settings-UI** | **Werkzeuge → WebAudits Suite**: Status aller konfigurierten Module, Formular für die operativen Werte, Reiter für Konten & Sicherheit und das Sicherheits-Log. Deutsch oder Englisch je nach Sprache des Admin-Benutzers. |
| **Self-Update** | Prüft 2×/Tag dieses Repo und ersetzt sich nach harter Prüfung selbst; die Vorversion bleibt als `.bak`. Abschaltbar. |

## Voraussetzungen

- WordPress 6.0+ (im Einsatz bis 7.x), **PHP 8.1+** (im Einsatz auf 8.4). Der Updater installiert nie eine Version, die ein neueres PHP braucht als der Server hat; stattdessen erscheint ein Hinweis.
- Optional: ein Consent-Manager für gesteuertes Tracking (siehe unten)

## Installation

**Als Must-Use-Plugin (empfohlen)** — immer aktiv, nicht versehentlich abschaltbar:

1. `webaudits-suite.php` nach `wp-content/mu-plugins/` kopieren (Ordner ggf. anlegen).
2. `webaudits-config-sample.php` als `wp-content/mu-plugins/webaudits-config.php` kopieren und die Werte eintragen.
3. **Werkzeuge → WebAudits Suite** öffnen, Übersicht prüfen, operative Werte setzen.

**Als normales Plugin** — `webaudits-suite.php` nach `wp-content/plugins/webaudits-suite/` legen und aktivieren. Die `webaudits-config.php` dann in `wp-content/` ablegen (außerhalb des Plugin-Ordners, damit eine Neuinstallation sie nicht löscht). Die Suite sucht die Konfiguration in `wp-content/mu-plugins/`, `wp-content/` und neben sich selbst.

Nur **einen** der beiden Wege nutzen, nie beide.

**Erster Start ohne Konfigurationsdatei** ist unbedenklich: CSP startet als `report-only`, kein Tracking, keine security.txt, Kommentare bleiben an, der User Guard protokolliert nur. `site_url` und `brand_name` kommen aus den WordPress-Einstellungen.

**Umstieg von Etch Security:** `etch-security.php` löschen. Einstellungen, Sicherheits-Log und Tabelle übernimmt die Suite unverändert. Solange die alte Datei geladen ist, bleibt das Modul aus und der Admin zeigt einen Hinweis — es läuft nie doppelt.

## Consent-Manager

`gtm_id` lädt Google Tag Manager nur in einer Form, die der Consent-Manager freischalten kann. Passenden `consent_provider` wählen:

| `consent_provider` | Für | Was die Suite ausgibt |
|---|---|---|
| `pressidium` (Standard) | [Pressidium Cookie Consent](https://wordpress.org/plugins/pressidium-cookie-consent/) mit aktiviertem `page_scripts` | `<script type="text/plain" data-cookiecategory="analytics">` |
| `iubenda` | iubenda | `<script type="text/plain" class="_iub_cs_activate" data-iub-purposes="4">` |
| `custom` | jeder Consent-Manager, der `type="text/plain"`-Skripte per Attribut freischaltet | die Attribute aus `consent_script_attrs`, z. B. Cookiebot: `array('type' => 'text/plain', 'data-cookieconsent' => 'statistics')` — in der Doku des Tools unter „manuelles Blockieren von Skripten" nachsehen |
| `none` | kein Banner (cookieloser GTM) | ein normales `<script>`; Consent Mode bleibt `denied` |

Ist der gewählte Provider nicht einsatzbereit (z. B. `pressidium` ohne das Plugin), wird GTM **nicht** geladen und der Admin zeigt einen Hinweis — Tracking läuft nie versehentlich ohne Einwilligung.

**Consent-Manager, die GTM selbst laden** (Borlabs Cookie, Complianz, Real Cookie Banner u. a.): `gtm_id` leer lassen und den Container vom Consent-Manager ausliefern lassen. Der Rest der Suite läuft unverändert; die CSP erlaubt den Handler für das verzögerte Borlabs-CSS bereits (siehe unten).

## Page-Builder

CSP und Nonce-Buffer werden für **eingeloggte Redakteure** in den Bearbeitungsansichten von Page-Buildern ausgelassen, weil Builder `eval` und eigene Vorschau-Kanäle brauchen: Etch (`?etch=magic`), Bricks (`?bricks=run`), Elementor (`?elementor-preview`), Oxygen (`?ct_builder`), Breakdance (`?breakdance=builder`, `?breakdance_iframe`), Beaver Builder (`?fl_builder`), Divi (`?et_fb`), Brizy (`?brizy-edit`, `?brizy-edit-iframe`). Besucher bekommen immer die volle Policy.

## Konfiguration — drei Ebenen

Werte lösen in dieser Reihenfolge auf (später gewinnt):

1. **Generische Defaults** in `webaudits-suite.php` — nie editieren; der Self-Updater ersetzt diese Datei.
2. **`webaudits-config.php`** — die Site-Werte via `define('WEBAUDITS_CONFIG_SITE', array(...))`. Überlebt jedes Update. Nur Schlüssel setzen, die vom Default abweichen.
3. **Settings-UI** (Werkzeuge → WebAudits Suite) — die operative Teilmenge (GTM-/GA4-ID, CSP-Modus, Schalter, Theme-Color, HSTS-preload) als DB-Option. **Überstimmt beide Dateien.**

## CSP-Rollout

Mit `report-only` starten (Standard). Die Browser-Konsole über alle Seitentypen beobachten — ausgeloggt, vor **und** nach der Einwilligung im Banner. Erst bei **null** Meldungen in der UI auf `enforce` schalten.

**Inline-Event-Handler** (`onload="…"` usw.) deckt eine Nonce nicht ab. Für bekannte, harmlose Handler setzt die Suite `'unsafe-hashes'` plus SHA-256 des exakten Handler-Texts (`csp_handler_hashes`; Standard: das verzögerte CSS-Laden `this.media='all';this.onload=null` von Borlabs Cookie, Perfmatters u. a.). Alle anderen Inline-Handler bleiben verboten. `<link rel="preload" as="script">` und `modulepreload` bekommen ebenfalls die Nonce. `upgrade-insecure-requests` steht nur im erzwungenen Header.

**Eingeloggte Administratoren** lassen sich über **CSP für Administratoren** (`csp_admins`: `same` | `report-only` | `off`) lockern, z. B. für das Frontend-Dashboard von Automatic.css, das `eval` braucht. Besucher bekommen immer `csp_mode`.

## Self-Update — wie es funktioniert und wie man es abschaltet

- Ein WP-Cron-Event (2×/Tag) lädt `webaudits-suite.php` von `raw.githubusercontent.com/<update_repo>/main` und liest die Version aus der Datei — anonym, **kein Token, kein Secret auf der Site**. (Die GitHub-API erlaubt nur 60 Anfragen/Stunde pro IP; auf Shared Hosting läuft ein Updater darüber nie.)
- Ist diese Version neuer, muss die Datei **alle** Prüfungen bestehen, bevor etwas ersetzt wird: beginnt mit `<?php`, plausible Größe, exakter Versions-Marker, Klammer-Balance und ein echter PHP-Parse (`token_get_all(..., TOKEN_PARSE)`).
- Der Tausch ist atomar (`.new` → rename) und trifft die Datei, aus der die Suite tatsächlich läuft; die Vorversion bleibt als `.bak`.
- Nur die Plugin-Datei wird angefasst — `webaudits-config.php` und die DB-Option nie.
- **Man vertraut damit der Update-Quelle.** Version festhalten: `'self_update' => false` (der Button „Jetzt auf Updates prüfen" funktioniert weiter). Aus einem eigenen Fork aktualisieren: `'update_repo' => 'du/dein-fork'`.

## Release-Flow (Maintainer)

1. `webaudits-suite.php` ändern und **beides** bumpen: `WEBAUDITS_SUITE_VERSION` und den `Version:`-Header.
2. Commit und Push auf `main` (= Release für alle Sites), Tag `vX.Y.Z`.
3. Sites ziehen es innerhalb von ~12 Stunden, sofort über den Button.

## Bewusst nicht enthalten

- Kompression, Asset-Cache, WebP-Negotiation, statisches Blocken von `readme.html`/`license.txt`/`xmlrpc.php` → `.htaccess` bzw. Server-Konfig.
- DNS-Härtung (CAA, DNSSEC), HTTP/2, `ServerTokens` → Hoster-Panel.
- SEO-Metas und Per-Post-Schemas → das SEO-Plugin.

## Lizenz

[MIT](LICENSE) © Tobias Haas
