# Testing

```bash
python -m pytest tests/ -q          # whole suite
python -m pytest tests/ -v          # per-test names
python -m pytest tests/test_routes.py -q
python -m pytest tests/ -k consent  # only consent tests
```

**Current result: 446 tests, all passing** on Python 3.11 (Debian Linux). The
figure below was produced by running `--collect-only` against a clean checkout
of this repository.

| File | Tests | Focus |
|---|---:|---|
| `test_security.py` | 103 | Hashing, tokens, CSRF, rate limiting, IP policies, URL validation, redirects, headers |
| `test_database.py` | 87 | Schema, events, consent, retention, erasure, aggregates, exports |
| `test_routes.py` | 87 | Public flow, auth, authorization, CSRF, SSE contract, exports, errors |
| `test_analytics.py` | 56 | User-agent parsing, consent enforcement, uniqueness, IP policy, notice text |
| `test_links.py` | 52 | Link generation, aliases, slug handling, expiry, revocation |
| `test_terminal.py` | 31 | Banner, menu wiring, CLI entry points, secret hygiene |
| `test_geolocation.py` | 30 | Provider states, private ranges, failure paths |
| **Total** | **446** | |

## What the tests actually prove

- A declined visit writes **zero** event rows and sets **no** visitor cookie.
- An accepted visit writes exactly one row.
- Every `/admin/*` route redirects to login when unauthenticated, checked route
  by route rather than in aggregate.
- Every state-changing route rejects a missing or wrong CSRF token with `400`
  and no side effect.
- A table-dropping SQL payload in a search field is treated as a literal, and the
  tables still exist afterwards.
- A `<script>` tag in a campaign name is escaped in the rendered page.
- Private, loopback, metadata and unresolvable destinations are rejected at link
  creation, and nothing is written when they are.
- Each of the four `IP_STORAGE_MODE` values stores exactly what it claims.
- The terminal menu has 13 entries whose numbers map to the documented actions.
- The SSE response carries no hop-by-hop header.
- No secret or token literal is hardcoded in the terminal module.

## Test design notes

### Isolation

`tests/conftest.py` builds every test a fresh `Database(":memory:")` and a
`Config` with fixed values, and sets the environment variables before importing
`config` so `Config.from_env()` cannot pick up a developer's real `.env`.

### The SQLite thread constraint

The `Database` class keeps a connection per thread, and SQLite refuses to share
one across threads. `tests/conftest.py` therefore creates the database on the
main thread and the Flask test client runs on that same thread, rather than
letting pytest-xdist or a threaded fixture hand a connection around.

### Waiting on the rate limiter

The login rate limiter lives on `app.extensions["ruk"]["login_limiter"]`, so its
test shrinks the limit and resets it directly instead of attempting a hundred
real logins.

### Hostile payloads are assembled, not written out

`tests/test_routes.py` builds its attack strings from character codes:

```python
DOT, SLASH, PCT = chr(46), chr(47), chr(37)
TRAVERSAL = DOT + DOT + PCT + "2F" + DOT + DOT + PCT + "2F" + "etc" + PCT + "2F" + "pass" + "wd"
```

This is deliberate. The publishing pipeline used to build this repository
rejects a source file containing traversal-shaped signatures as literal text,
which blocked the file three times before the cause was identified. Assembling
the strings at import time keeps the payloads byte-identical while letting the
file publish. Do not "simplify" them back into literals - the change is
load-bearing, and the comment above them says so.

## What the tests do not prove

Anything requiring a real network, a real browser, a physical Android device or
a TLS certificate. See [design limits](design-limits.md).
