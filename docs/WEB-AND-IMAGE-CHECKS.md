# Web app and container image checks

On the Code page. Results are kept in `console/webscans/`; each finding can be added to a site's Fix plan.

## Web app check

A polite, read-only crawl modelled on the passive checks of Tenable WAS, Qualys WAS and OWASP ZAP's baseline.

**Rules:** GET and HEAD only; the target's own origin only (redirects elsewhere aren't followed); 2 requests a second;
150 pages by default (up to 500); links that look like actions (logout, delete, reset, unsubscribe…) are skipped;
forms are never submitted. An admin starts it with a passkey after confirming they may test the app. The optional
sign-in header (Cookie or Authorization of a **test account without admin rights**) stays in memory.

**Checks:** missing HSTS, CSP, X-Content-Type-Options, Referrer-Policy and framing protection; cookies without Secure,
HttpOnly or SameSite; version numbers in Server / X-Powered-By; stack traces and database errors shown to visitors;
directory listings; scripts over HTTP on HTTPS pages; password forms over HTTP; exposed files (`.git`, `.env`,
`web.config`, backups, Spring actuator `env` / `heapdump`, phpinfo, server-status, WordPress user list, API
descriptions); CORS that reflects any origin with credentials; no security.txt; and, signed in, pages for signed-in
users that also load the same way without signing in (missing access control).

## Container image check

Reads an image from its registry (Docker Hub, GHCR, any Registry API v2; a pull token for private images, kept in
memory) without running it. Layers are streamed and decompressed in memory (up to 1.5 GB compressed); only package
lists are kept.

**Checks:** Debian / Ubuntu (dpkg, by source package), Alpine (apk), Python (dist-info) and npm (package.json) packages
against OSV (known vulnerabilities, and malicious packages as critical); runs as root; secret-looking environment
variables (names only); base OS out of support; image older than a year. Not yet: RPM-based images, zstd layers, Go
and Java binaries.
