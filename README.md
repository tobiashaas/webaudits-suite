# WebAudits Suite

**One single must-use plugin for the entire WordPress hardening and tracking baseline** — security headers, nonce-based CSP, admin cleanup, comments-off, consent-gated Google Tag Manager *or* direct GA4 (mutually exclusive, with a built-in double-tracking guard), and a self-update mechanism that keeps every site on the latest release automatically.

🇩🇪 *Deutsche Fassung: [README.de.md](README.de.md)*

Built for the stack **WordPress + Etch + Automatic.css + Pressidium Cookie Consent + SEOPress + WS Form** — but it runs on any WordPress installation. No build step, no Composer, no dependencies: two plain PHP files.

---

## Features

| Module | What it does |
|---|---|
| **Security headers** | HSTS (optional `preload`), `X-Content-Type-Options: nosniff`, `X-Frame-Options`, `Referrer-Policy: same-origin`, `Permissions-Policy`, COOP/CORP, `X-Permitted-Cross-Domain-Policies`; strips `X-Powered-By`. Deliberately **no** COEP (would break external embeds). |
| **Framing (`frame_ancestors`)** | Lets named foreign origins embed the site in an `<iframe>`, optionally only on specific paths (e.g. an LMS embedding the privacy page). `X-Frame-Options` cannot express a foreign origin (`ALLOW-FROM` is dead), so it is omitted on exactly those responses and replaced by an **always-enforced** `Content-Security-Policy: frame-ancestors …` header — sent even in `report-only` mode, which would enforce nothing. Default: own origin only. |
| **Content-Security-Policy** | Nonce-based + `strict-dynamic`. A single output buffer attaches the per-request nonce to *every* script tag — including raw inline scripts from builders and plugins that bypass the WP script API — so external scripts work without allowlist maintenance. Three modes: `off` → `report-only` → `enforce`. The Etch builder view (`?etch=magic`) is automatically exempt. |
| **Version-leak fixes** | Removes the `generator` meta and generator strings. |
| **XML-RPC block** | `POST /xmlrpc.php` → 403; pingback header and RSD link removed. |
| **security.txt** | Serves `/.well-known/security.txt` (RFC 9116) from config — no physical file needed. |
| **theme-color / color-scheme** | Emits the brand `<meta name="theme-color">` and `color-scheme`. |
| **Image loading fix** | Optionally forces `loading="lazy"` (and strips `fetchpriority`) for images whose class matches — for cases where WordPress' LCP heuristic guesses wrong (e.g. the real hero is a canvas). |
| **LocalBusiness schema** | Optional CPT-driven `LocalBusiness` JSON-LD (multi-location) on a chosen page. Optional `parent` (name + URL) names the legal entity when the site is a brand of a larger company (default: `brand_name`). Keep it off if your SEO plugin owns schemas. |
| **Google Tag Manager** | Consent-gated container: rendered as `<script type="text/plain" data-cookiecategory="…">`, unblocked by Pressidium Cookie Consent only after consent — **zero Google requests before consent**, no `noscript` iframe. Consent Mode v2 defaults (`denied`) are always set first. Requires the Pressidium option `page_scripts` = on. |
| **GA4 direct (gtag.js)** | Alternative to GTM for simple sites. **Mutually exclusive:** if a GTM container ID is set, GA4-direct stays locked and an admin notice explains why — one tracking path, never two (double-tracking guard). |
| **WS Form lead bridge** | Pushes a dataLayer event (e.g. `generate_lead`) on `wsf-submit-success`, with `form_id` — ready for a GTM trigger. |
| **Admin cleanup** | Removes dashboard widgets, welcome panel and a configurable list of plugin widgets; hides empty containers. |
| **Comments off** | Complete: frontend closed, existing comments hidden, admin menu/adminbar entries removed, REST endpoints removed, feed links stripped from `<head>`. |
| **Login hardening** | Generic login error (no username enumeration), `DISALLOW_FILE_EDIT`, sortable "Last login" column in the users list. |
| **Privacy policy from CPT** | Makes posts of a custom post type selectable as the privacy policy page (WordPress natively only allows `page`). |
| **301 redirects** | Explicit path-to-path redirects from config (covers root-based CPT slug renames where WP's old-slug redirect doesn't fire). |
| **Settings UI** | **Tools → WebAudits Suite**: status overview of all configured modules (effective, merged values) plus a form for the operational values. Bilingual — English/German follows the admin user's locale. |
| **Self-update** | Twice a day the suite checks this repo's [releases](../../releases) and replaces itself. Every download is hard-validated before it goes live; the previous version is kept as `.bak`. Manual check button included. |

## Requirements

- WordPress 6.x+ (tested up to 7.x), PHP 7.4+
- For consent-gated GTM: [Pressidium Cookie Consent](https://wordpress.org/plugins/pressidium-cookie-consent/) with `page_scripts` enabled
- Everything else works standalone

## Installation

1. Copy **`webaudits-suite.php`** into `wp-content/mu-plugins/` (must-use plugins are auto-active; create the folder if it doesn't exist).
2. Copy **`webaudits-config-sample.php`** to `wp-content/mu-plugins/webaudits-config.php` and fill in your site's values.
3. Review **Tools → WebAudits Suite** in wp-admin: check the module overview, set the operational values (GTM/GA4 ID, CSP mode, switches).

That's it — no activation screen, no database migration.

## Configuration — three layers

Values resolve in this order (later wins):

1. **Generic defaults** inside `webaudits-suite.php` — never edit these; the self-updater replaces this file.
2. **`webaudits-config.php`** — your site's values via `define('WEBAUDITS_CONFIG_SITE', array(...))`. Survives every update. Only set the keys that differ from the defaults.
3. **Settings UI** (Tools → WebAudits Suite) — the operational subset (GTM/GA4 ID, CSP mode, comments/admin/XML-RPC/login switches, theme color, HSTS preload) stored as a DB option. **Overrides both files.**

## CSP rollout

Start with `report-only` (the default). Watch the browser console across all page types; once it reports **zero** violations, switch the mode to `enforce` in the UI. The suite's nonce buffer covers builder-emitted inline scripts, so most sites need no policy edits at all.

## Self-update — how it works and why it's safe

- A WP-Cron event (twice daily) queries `GET /repos/tobiashaas/webaudits-suite/releases/latest` — anonymous, **no token, no secret on the client site**.
- If the release tag is newer than the running `WEBAUDITS_SUITE_VERSION`, the raw file is downloaded from the tagged commit.
- Before anything is replaced, the download must pass **all** checks: starts with `<?php`, plausible size, contains the exact new version marker, balanced braces, and a real PHP parse check (`token_get_all(..., TOKEN_PARSE)`) — a broken must-use plugin would take the whole site down, so nothing unvalidated ever goes live.
- The swap is atomic (`.new` → rename), the previous version stays as `webaudits-suite.php.bak` for instant rollback.
- Only `webaudits-suite.php` is ever touched — your `webaudits-config.php` and the DB option are never modified.
- Status (version, last check, available update) is shown on the Tools page, with a **"Check for updates now"** button.

## Release flow (maintainers)

1. Edit `webaudits-suite.php` — bump **both** `WEBAUDITS_SUITE_VERSION` and the `Version:` header (they must match; the updater verifies the marker).
2. Commit, tag `vX.Y.Z`, create a GitHub release.
3. Done — every site picks it up within ~12 hours (or immediately via the manual button).

## Deliberately not included

- Compression, asset caching, WebP negotiation, static blocking of `readme.html`/`license.txt`/`xmlrpc.php` → these belong in **`.htaccess`** (or your server config), not in PHP.
- DNS-level hardening (CAA, DNSSEC), HTTP/2, `ServerTokens` → hosting panel.
- SEO metas and per-post schemas → your SEO plugin (we use SEOPress).

## License

[MIT](LICENSE) © Tobias Haas
