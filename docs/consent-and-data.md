# Consent model and data collected

## The flow

```
Visitor opens /l/abc123
        |
        v
+-----------------------------+
|  Consent gateway            |   <- no cookie, no event, nothing written
|  "This link records ..."    |
|  [Allow]  [Leave uncounted] |
+-----------------------------+
        |                 |
     Allow            Decline
        |                 |
        v                 v
  one event row      zero event rows
  + visitor cookie   + no cookie
  + 302 -> dest      + 302 -> dest
```

## Details that matter

- **The gateway writes nothing.** Before a choice is made there is no cookie, no
  event row and no consent row.
- **Declining is recorded only as an anonymous count.** One `consent_records` row
  with an empty visitor token and `granted=0` lets you see the refusal rate. No
  analytics event is created, and no cookie is set - a person who said no is left
  with nothing on their device. A test asserts both halves of that.
- **The notice is generated from configuration.** `build_notice_summary()` in
  `analytics.py` derives the recorded/never-recorded lists from the live
  `IP_STORAGE_MODE` and `GEO_PROVIDER`, so the notice cannot drift away from what
  the code actually does. Change the policy and the page changes with it.
- **Withdrawing consent deletes data.** `withdraw_consent()` in `database.py`
  marks the record withdrawn **and** deletes every event recorded under it. A
  withdrawal that left the rows in place would be a lie.
- **Consent rows store the notice fingerprint.** Each row keeps a truncated
  SHA-256 of the notice text that was shown, so a record proves *what* the visitor
  agreed to, not just that they clicked.
- **Policy versioning.** Every consent row stores `policy_version`. Bump
  `POLICY_VERSION` after changing your notice and old consents stop counting.

## Stored, only after consent

| Field | Example | Notes |
|---|---|---|
| `created_at` | `2026-10-29T18:14:59Z` | UTC, second precision |
| `tracking_id` | `BdoJnh2n7bnj` | Which link was opened |
| `campaign_id` | `3` | Grouping identifier |
| `browser_family` / `browser_version` | `Chrome` / `120` | Family and **major** version only |
| `os_family` / `os_version` | `Android` / `14` | Family and **major** version only |
| `device_category` | `mobile` | `mobile` / `tablet` / `desktop` / `unknown` |
| `referrer_host` | `news.example.org` | Hostname only; the path is discarded |
| `consent_status` | `granted` | Always `granted` for a stored event |
| `ip_address` | `203.0.113.7` | Or truncated, hashed, or absent - see below |
| `country` / `region` / `city` | `Germany` / `Berlin` / (empty) | Empty unless geolocation is enabled |
| `geo_source` | `maxmind` | Which resolver produced the above, or `none` |
| `is_unique` | `1` | Repeat-visit heuristic, see below |

## Never stored, under any configuration

Passwords, session tokens, cookies belonging to other sites, messages, files,
contacts, call logs, precise GPS coordinates, IMEI/IMSI, phone numbers, screen
dimensions, installed-app lists, keystrokes, canvas or font fingerprints, camera
or microphone data.

Screen dimensions are deliberately **not** collected: they add identifying
entropy without answering a business question, and the flow does not request the
permission that would make collecting them acceptable.

`tests/test_database.py` asserts the schema contains no column able to hold a
password, a message or a precise position.

## The four IP policies

```ini
IP_STORAGE_MODE=full        # 203.0.113.7      - most identifying
IP_STORAGE_MODE=truncated   # 203.0.113.0      - city-level at best
IP_STORAGE_MODE=hashed      # a1b2... (keyed)  - cannot be reversed
IP_STORAGE_MODE=none        # (nothing)        - maximum privacy
```

`truncated` keeps the /24 for IPv4 and the /64 prefix for IPv6. `hashed` stores
only an HMAC-SHA256 of the address, keyed with `IP_HASH_SALT` (which defaults to
the first 32 characters of `SECRET_KEY` when unset).

## How `is_unique` is decided

1. A first-party cookie (`ruk_v`, HttpOnly, SameSite=Lax, 90 days) if present.
2. Otherwise a keyed hash of the IP, when an IP was retained.
3. Otherwise a random value, so the visit counts as unique.

It is a heuristic. Cleared cookies and shared addresses both distort it. The
dashboard labels the figure **Unique events**, not "unique people", because that
is all it measures.

## Geolocation is approximate, always

The consent page, the privacy notice and this document repeat the same sentence,
because it is the most misunderstood part of link analytics:

> Geographic data is approximate and derived from the IP address only. It cannot
> identify a street address, a precise position, or a person.

| `GEO_PROVIDER` | Behaviour | Privacy |
|---|---|---|
| `none` (default) | No location recorded at all | Nothing leaves the host |
| `maxmind` | Local `GeoLite2-City.mmdb` lookup | Nothing leaves the host |
| `http` | External API | **The visitor IP leaves your server** - only use if your notice says so |

A failed or disabled lookup returns `available=False`, never an empty location
that looks like a real one. A typo in `GEO_PROVIDER` reports an error instead of
being passed off as "disabled", and `http` with no endpoint reports the
misconfiguration rather than claiming to work.

## Retention and erasure

- `DEFAULT_RETENTION_DAYS` sets the default retention per link (default 90).
- The privacy page can purge rows older than N days, wipe all events, wipe one
  link's events, or erase everything for one visitor token.
- Every one of those actions is written to `audit_log`.
- No background scheduler ships with the app. `RETENTION_SWEEP_SECONDS` is read
  and reported; wire the purge to cron if you want it automatic.
