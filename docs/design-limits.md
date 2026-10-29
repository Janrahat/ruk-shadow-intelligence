# Design decisions and their limits

Being explicit about what is *not* verified is part of the deliverable.

## Language choices

Python for the engine, API, analytics and terminal; JavaScript for the browser
side of the dashboard (roughly 260 lines, no build step); HTML/CSS for templates
and theme; Bash for the two installers; SQL for schema and queries.

A Rust or Go component would add a second toolchain to every install path -
including Termux, where cross-compiling is painful - for no measured benefit at
this scale. Adding a language to look thorough would have made the project harder
to install, which is the opposite of the intent.

## Real bugs found by running it, not by unit tests

Three defects surfaced only under real execution and were fixed:

1. **Consent decline still set a visitor cookie.** The unit tests passed because
   they checked database rows; a live HTTP trace showed `Set-Cookie: ruk_v=...`
   on the decline path. Leaving an identifier on the device of someone who just
   refused is exactly the behaviour this project exists to avoid. The decline
   path now sets no cookie, and a regression test asserts it.
2. **The SSE endpoint returned `500` under Waitress.** The handler set
   `Connection: keep-alive`, which is a hop-by-hop header and forbidden by
   PEP 3333. The Flask test client never exercises Waitress, so the suite was
   green while the feature was broken in production. Removed, and four tests now
   assert the response contract.
3. **`/admin/` returned 404.** A hand-typed trailing slash is common; it now
   redirects `308` to `/admin`.

Two more surfaced while testing the honest-failure paths: a typo in
`GEO_PROVIDER` was reported as a deliberate "disabled" setting instead of an
error, and `GEO_PROVIDER=http` with no endpoint claimed to be working. Both now
report the misconfiguration.

## Verified

- 446 automated tests pass on Python 3.11, run against a clean checkout of this
  repository (not just the development tree).
- A live Waitress server handled the full flow: admin login, link creation,
  visitor consent, event persisted, dashboard rendered, SSE pushed the event in
  real time, CSV and JSON export, QR PNG served, and revocation blocked further
  tracking.
- Consent enforcement was checked at the database level: an accepted visit
  produced exactly one row; a declined visit produced zero.

## Not verified - stated plainly

- **HTTPS with a real certificate was not exercised.** The TLS-dependent paths
  (secure cookies, HSTS, `REQUIRE_HTTPS_LINKS`) are implemented and
  configuration-checked, but no certificate was installed here. Test behind a
  reverse proxy before trusting them.
- **Termux on a physical Android device was not tested.** Development was on
  Debian Linux. The Termux installer uses documented `pkg` names and handles the
  Pillow build fallback, but package names do change - if `pkg install` fails,
  run `pkg search <name>`.
- **The MaxMind provider was never run against a real `.mmdb`.** Its failure
  paths are tested; its success path requires a licensed database file.
- **The `http` geolocation provider was not run against a live third-party API.**
  It correctly reports failures instead of inventing data.
- **No browser was driven against the dashboard.** Templates and JavaScript are
  structurally asserted, but no headless render check was performed, so a layout
  bug on an unusual viewport would not have been caught.
- **Rate limiting is per-process**, as described in
  [security](security.md).
- **No background scheduler ships in the app.** `RETENTION_SWEEP_SECONDS` is read
  and reported, and the purge can be run from the privacy page; wire it to cron
  if you want it automatic.
- **Single-node only.** SQLite with WAL is correct for one writer process.
  Multiple application servers need PostgreSQL and a shared rate-limit store.

## Deliberate omissions

- **No third-party analytics, fonts or CDNs.** Every asset is served locally, so
  no visitor data reaches another company by accident.
- **No screen resolution field.** It adds fingerprinting entropy without
  answering a business question, and the flow does not request the permission
  that would be needed to collect it acceptably.
- **No fingerprinting of any kind** - no canvas, WebGL, font or audio probing,
  and no cross-site pixel.
- **No admin credentials in the source.** `--create-admin` prompts; nothing is
  baked in.
- **No claim of lawfulness.** The software provides the mechanism for
  consented-to analytics. Whether a deployment is lawful depends on the notice,
  the jurisdiction and the relationship to the visitor, which the software cannot
  determine.
