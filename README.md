# WebAudits Suite

**One self-updating WordPress plugin for the security and tracking baseline of a site** — security headers, a nonce-based Content-Security-Policy, version-leak fixes, consent-gated Google Tag Manager *or* GA4, admin cleanup, an account allowlist with a security log, and forced core security updates.

🇩🇪 *Deutsche Fassung: [README.de.md](README.de.md)*

It runs on any WordPress site. No build step, no Composer, no dependencies: two plain PHP files (the plugin and your site's config). In production on sites built with Etch, Bricks, Automatic.css, SEOPress and WS Form, with Pressidium Cookie Consent, Borlabs Cookie or iubenda as consent manager.

---

## Features

| Module | What it does |
|---|---|
| **Security headers** | HSTS (optional `preload`), `X-Content-Type-Options: nosniff`, `X-Frame-Options`, `Referrer-Policy: same-origin`, `Permissions-Policy`, COOP/CORP, `X-Permitted-Cross-Domain-Policies`; strips `X-Powered-By`. Deliberately **no** COEP (would break external embeds). |
| **Framing (`frame_ancestors`)** | Lets named foreign origins embed the site in an `<iframe>`, optionally only on specific paths (e.g. an LMS embedding the privacy page). `X-Frame-Options` cannot express a foreign origin (`ALLOW-FROM` is dead), so it is omitted on exactly those responses and replaced by an **always-enforced** `Content-Security-Policy: frame-ancestors …` header. Default: own origin only. |
| **Content-Security-Policy** | Nonce-based + `strict-dynamic`. One output buffer attaches the per-request nonce to *every* script tag — including inline scripts from builders and plugins that bypass the WP script API — so external scripts work without allowlist maintenance. Modes: `off` → `report-only` → `enforce`. Page-builder editing views are exempt for logged-in editors (see below). |
| **Version-leak fixes** | Removes the `generator` meta and generator strings. |
| **XML-RPC block** | `POST /xmlrpc.php` → 403; pingback header and RSD link removed. |
| **security.txt** | Serves `/.well-known/security.txt` (RFC 9116) from config once you set a contact — no physical file needed. |
| **theme-color / color-scheme** | Emits `<meta name="theme-color">` and `color-scheme`. |
| **Image loading fix** | Optionally forces `loading="lazy"` (and strips `fetchpriority`) for images with a given class — for when WordPress' LCP heuristic guesses wrong. |
| **LocalBusiness schema** | Optional CPT-driven `LocalBusiness` JSON-LD (multi-location) on one page. Keep it off if your SEO plugin owns schemas. |
| **Google Tag Manager** | Consent-gated container: rendered as an inert `<script type="text/plain" …>` that your consent manager unblocks after consent — **zero Google requests before consent**, no `noscript` iframe. Consent Mode v2 defaults (`denied`) are always set first. See [Consent managers](#consent-managers). |
| **GA4 direct (gtag.js)** | Alternative to GTM for simple sites. **Mutually exclusive:** if a GTM ID is set, GA4-direct stays locked and an admin notice explains why — one tracking path, never two. |
| **WS Form lead bridge** | Pushes a dataLayer event (e.g. `generate_lead`) on `wsf-submit-success`, with `form_id`. |
| **Admin cleanup** | Removes dashboard widgets, the welcome panel and a configurable list of plugin widgets. |
| **Comments off** (opt-in) | Complete: frontend closed, existing comments hidden, admin menu/adminbar entries and REST endpoints removed, feed links stripped. |
| **Login hardening** | Generic login error (no username enumeration), `DISALLOW_FILE_EDIT`, sortable "Last login" column in the users list. |
| **Accounts & security** | **User guard:** new accounts only with an allowed e-mail domain. REST, profile and registration reject foreign addresses; a backstop on `user_register`/`set_user_role` also catches `wp_insert_user()` and privilege escalation. A foreign account is **neutralised, not deleted** (role removed, random password, sessions destroyed, mail to the admin address) — it stays as evidence. The admin address's domain is always allowed; enforcement stays off until you configure a domain. **Security log:** own table with actor, IP, user agent, request and context for logins, accounts, roles, application passwords, plugins and themes; 180 days, CSV export. **Core security updates:** minor/security releases of the installed `X.Y` branch install automatically even when a host tool (e.g. Installatron) disables core updates. |
| **Privacy policy from CPT** | Makes posts of a custom post type selectable as the privacy policy page. |
| **301 redirects** | Explicit path-to-path redirects from config. |
| **Settings UI** | **Tools → WebAudits Suite**: status of every configured module plus a form for the operational values; tabs for accounts & security and the security log. English or German, following the admin user's language. |
| **Self-update** | Twice a day the suite checks this repository and replaces itself after hard validation; the previous version is kept as `.bak`. Can be switched off. |

## Requirements

- WordPress 6.0+ (in production up to 7.x), **PHP 8.1+** (in production on 8.4). The updater never installs a release that needs a newer PHP than your server runs; it shows a notice instead.
- Optional: a consent manager for gated tracking (see below)

## Installation

**As a must-use plugin (recommended)** — always active, cannot be switched off by accident:

1. Copy `webaudits-suite.php` into `wp-content/mu-plugins/` (create the folder if needed).
2. Copy `webaudits-config-sample.php` to `wp-content/mu-plugins/webaudits-config.php` and set your values.
3. Open **Tools → WebAudits Suite**, check the overview and set the operational values.

**As a regular plugin** — put `webaudits-suite.php` into `wp-content/plugins/webaudits-suite/` and activate it. Keep your `webaudits-config.php` in `wp-content/` (outside the plugin folder, so reinstalling the plugin cannot delete it). The suite looks for the config in `wp-content/mu-plugins/`, `wp-content/` and next to itself.

Use **one** of the two ways, never both.

**First run without a config file** is safe: CSP starts in `report-only`, no tracking is loaded, no security.txt is served, comments stay on, the account guard only logs. `site_url` and `brand_name` fall back to the WordPress settings.

**Coming from Etch Security:** delete `etch-security.php`. Settings, security log and table carry over unchanged. While the old file is still loaded, the module stays off and the admin shows a notice — it never runs twice.

## Consent managers

`gtm_id` only loads Google Tag Manager in a form your consent manager can unblock. Pick the matching `consent_provider`:

| `consent_provider` | Use with | What the suite renders |
|---|---|---|
| `pressidium` (default) | [Pressidium Cookie Consent](https://wordpress.org/plugins/pressidium-cookie-consent/) with `page_scripts` enabled | `<script type="text/plain" data-cookiecategory="analytics">` |
| `iubenda` | iubenda | `<script type="text/plain" class="_iub_cs_activate" data-iub-purposes="4">` |
| `custom` | any consent manager that unblocks `type="text/plain"` scripts by attribute | the attributes from `consent_script_attrs`, e.g. Cookiebot: `array('type' => 'text/plain', 'data-cookieconsent' => 'statistics')` — check your tool's documentation for "manual script blocking" |
| `none` | no banner (cookieless GTM) | a plain `<script>`; Consent Mode stays `denied` |

If the configured provider is not ready (e.g. `pressidium` without the plugin), GTM is **not** loaded and an admin notice says so — tracking never runs without consent by accident.

**Consent managers that load GTM themselves** (Borlabs Cookie, Complianz, Real Cookie Banner and others): leave `gtm_id` empty and let the consent manager deliver the container. Everything else in the suite works unchanged; the CSP already allows Borlabs' deferred-CSS handler (see below).

## Page builders

CSP and the nonce buffer are skipped for **logged-in editors** in builder editing views, because builders need `eval` and their own preview channels: Etch (`?etch=magic`), Bricks (`?bricks=run`), Elementor (`?elementor-preview`), Oxygen (`?ct_builder`), Breakdance (`?breakdance=builder`, `?breakdance_iframe`), Beaver Builder (`?fl_builder`), Divi (`?et_fb`), Brizy (`?brizy-edit`, `?brizy-edit-iframe`). Visitors always get the full policy.

## Configuration — three layers

Values resolve in this order (later wins):

1. **Generic defaults** inside `webaudits-suite.php` — never edit them; the self-updater replaces this file.
2. **`webaudits-config.php`** — your site's values via `define('WEBAUDITS_CONFIG_SITE', array(...))`. Survives every update. Only set keys that differ from the defaults.
3. **Settings UI** (Tools → WebAudits Suite) — the operational subset (GTM/GA4 ID, CSP mode, switches, theme color, HSTS preload) stored as a DB option. **Overrides both files.**

## CSP rollout

Start with `report-only` (the default). Watch the browser console across all page types — logged out, before **and** after accepting the consent banner. Once it reports **zero** violations, switch to `enforce` in the UI.

**Inline event handlers** (`onload="…"` etc.) are not covered by a nonce. For known, harmless handlers the suite adds `'unsafe-hashes'` plus the SHA-256 of the exact handler text (`csp_handler_hashes`; default: the deferred-CSS pattern `this.media='all';this.onload=null` used by Borlabs Cookie, Perfmatters and others). Every other inline handler stays blocked. `<link rel="preload" as="script">` and `modulepreload` get the nonce as well. `upgrade-insecure-requests` is only sent in the enforced header.

**Logged-in administrators** can get a looser mode via **CSP for administrators** (`csp_admins`: `same` | `report-only` | `off`). Use it when an admin-only frontend tool needs `eval`, e.g. the Automatic.css frontend dashboard. Visitors always get `csp_mode`.

## Self-update — how it works and how to turn it off

- A WP-Cron event (twice daily) downloads `webaudits-suite.php` from `raw.githubusercontent.com/<update_repo>/main` and reads the version from the file — anonymous, **no token, no secret on your site**. (The GitHub API allows only 60 requests/hour per IP; on shared hosting an updater using it never runs.)
- If that version is newer than the running one, the file must pass **all** checks before it replaces anything: starts with `<?php`, plausible size, exact new version marker, balanced braces and a real PHP parse (`token_get_all(..., TOKEN_PARSE)`).
- The swap is atomic (`.new` → rename) and writes to the file the suite is actually running from; the previous version stays as `.bak`.
- Only the plugin file is touched — your `webaudits-config.php` and the DB option never are.
- **You are trusting the update source.** To pin a version, set `'self_update' => false` (the "Check for updates now" button still works). To update from your own fork, set `'update_repo' => 'you/your-fork'`.

## Release flow (maintainers)

1. Edit `webaudits-suite.php` and bump **both** `WEBAUDITS_SUITE_VERSION` and the `Version:` header.
2. Commit and push to `main` (= release for every site), tag `vX.Y.Z`.
3. Sites pick it up within ~12 hours, or immediately via the button.

## Deliberately not included

- Compression, asset caching, WebP negotiation, static blocking of `readme.html`/`license.txt`/`xmlrpc.php` → `.htaccess` or server config.
- DNS-level hardening (CAA, DNSSEC), HTTP/2, `ServerTokens` → hosting panel.
- SEO metas and per-post schemas → your SEO plugin.

## License

[MIT](LICENSE) © Tobias Haas
