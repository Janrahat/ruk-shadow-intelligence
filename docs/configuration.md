# Configuration reference

All settings are environment variables read by `Config.from_env()`. A `.env`
file in the project root is loaded automatically when present. `.env.example`
documents each one inline.

## Runtime

| Variable | Default | Meaning |
|---|---|---|
| `RUK_ENV` | `development` | `development`, `production` or `test`. Production enables hard checks. |
| `PUBLIC_BASE_URL` | `http://127.0.0.1:8000` | The address visitors use. Share URLs and QR codes are built from it. |
| `BIND_HOST` | `127.0.0.1` | Interface to listen on. `0.0.0.0` exposes it on every interface. |
| `BIND_PORT` | `8000` | Port. |

## Secrets

| Variable | Default | Meaning |
|---|---|---|
| `SECRET_KEY` | generated in development | Session signing key. **Required** in production, minimum 32 characters. |
| `IP_HASH_SALT` | first 32 chars of `SECRET_KEY` | Salt for `IP_STORAGE_MODE=hashed`. A dedicated value is better. |

Generate a key:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

## Storage

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_PATH` | `data/ruk_shadow.db` | SQLite file path. |
| `IP_STORAGE_MODE` | `full` | `full`, `truncated`, `hashed` or `none`. |
| `DEFAULT_RETENTION_DAYS` | `90` | Default analytics retention per link. |
| `RETENTION_SWEEP_SECONDS` | `3600` | Purge interval, read and reported (no built-in scheduler). |

## Geolocation

| Variable | Default | Meaning |
|---|---|---|
| `GEO_PROVIDER` | `none` | `none`, `maxmind` or `http`. |
| `GEO_DB_PATH` | *(empty)* | Path to `GeoLite2-City.mmdb` when using `maxmind`. |
| `GEO_HTTP_ENDPOINT` | *(empty)* | Template containing `{ip}`, e.g. `https://ip-api.com/json/{ip}`. |

`GEO_PROVIDER=http` sends visitor IP addresses to a third party. Only enable it
if your privacy notice says so.

## Link behaviour

| Variable | Default | Meaning |
|---|---|---|
| `REQUIRE_HTTPS_LINKS` | `false` (`true` in production) | Reject `http://` destinations and share URLs. |
| `POLICY_VERSION` | `1.0` | Bump when the notice changes; old consents stop counting. |

## Sessions and proxies

| Variable | Default | Meaning |
|---|---|---|
| `SESSION_COOKIE_SECURE` | `false` (`true` in production) | Mark the admin session cookie `Secure`. |
| `SESSION_LIFETIME_SECONDS` | `3600` | Idle session timeout. |
| `TRUST_PROXY_HEADERS` | `false` | Honour `X-Forwarded-For`. Only enable behind your own reverse proxy. |

## Rate limiting

| Variable | Default | Meaning |
|---|---|---|
| `LOGIN_RATE_LIMIT` | `8` | Login attempts allowed per window. |
| `LOGIN_RATE_WINDOW` | `300` | Window length in seconds. |
| `PUBLIC_RATE_LIMIT` | `120` | Public link hits per window. |
| `PUBLIC_RATE_WINDOW` | `60` | Window length in seconds. |

## Production guards

With `RUK_ENV=production` the app refuses to start when any of these is violated:

- `SECRET_KEY` is unset, shorter than 32 characters, or looks like a sample value
- `PUBLIC_BASE_URL` does not start with `https://`
- `SESSION_COOKIE_SECURE` is false
- `IP_STORAGE_MODE` or `GEO_PROVIDER` holds an unrecognised value
- a numeric setting is not a number or is out of range

Each failure names the offending variable and how to fix it.

## Warnings (non-fatal)

The app also reports, on the dashboard and in the terminal's security screen:

- `PUBLIC_BASE_URL` points at localhost, so links only work on this machine
- plain `http://` is in use outside production
- `IP_STORAGE_MODE=full` is storing complete addresses
- `GEO_PROVIDER=http` sends visitor IPs to a third party
- a geolocation provider is selected but its endpoint or database path is empty
- `IP_HASH_SALT` is unset and derived from `SECRET_KEY`
- `TRUST_PROXY_HEADERS` is on

## Reading the effective configuration

```bash
python terminal_dashboard.py --diagnose     # includes the active posture
```

Or from Python:

```python
from config import Config
cfg = Config.from_env()
for key, value in cfg.describe():
    print(key, value)
print(cfg.warnings)
```
