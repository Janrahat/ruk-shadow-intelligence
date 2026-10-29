@"""Configuration loading and validation.

The whole application reads its settings from here, so this module is the one
place where a bad deployment can be caught. In production it refuses to start
with an insecure configuration rather than warning and continuing.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(RuntimeError):
    """Raised when the environment cannot describe a safe deployment."""


VALID_ENVS = {"development", "production", "test"}
VALID_IP_MODES = {"full", "truncated", "hashed", "none"}
VALID_GEO_PROVIDERS = {"none", "maxmind", "http"}

MIN_SECRET_LENGTH = 32
LOCAL_SECRET_FILE = ".ruk_secret"

TRUTHY = {"1", "true", "yes", "on", "y", "t"}
FALSY = {"0", "false", "no", "off", "n", "f", ""}


# ---------------------------------------------------------------------------
# .env loading
# ---------------------------------------------------------------------------
def load_dotenv(path: str | Path = ".env", override: bool = False) -> int:
    """Minimal .env reader.

    Real dotenv packages exist, but this keeps the dependency list short and the
    behaviour obvious: `KEY=value`, optional surrounding quotes, `#` comments,
    blank lines ignored. Returns the number of variables set.
    """
    file_path = Path(path)
    if not file_path.is_file():
        return 0

    count = 0
    try:
        raw = file_path.read_text(encoding="utf-8")
    except OSError:
        return 0

    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key or not key.replace("_", "").isalnum():
            continue
        value = value.strip()
        # Only strip matching quote pairs, so a password containing a quote at
        # one end is not silently altered.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if override or key not in os.environ:
            os.environ[key] = value
            count += 1
    return count


# ---------------------------------------------------------------------------
# Typed readers
# ---------------------------------------------------------------------------
def _env_str(name: str, default: str = "") -> str:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip()


def _env_int(name: str, default: int, minimum: int | None = None,
             maximum: int | None = None) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{name} must be a whole number (got {raw!r})") from exc
    if minimum is not None and value < minimum:
        raise ConfigError(f"{name} must be at least {minimum} (got {value})")
    if maximum is not None and value > maximum:
        raise ConfigError(f"{name} must be at most {maximum} (got {value})")
    return value


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    lowered = str(raw).strip().lower()
    if lowered in TRUTHY:
        return True
    if lowered in FALSY:
        return False
    raise ConfigError(f"{name} must be true or false (got {raw!r})")


def _looks_like_placeholder(value: str) -> bool:
    """Detect the sample values people forget to replace."""
    lowered = value.lower()
    return any(
        marker in lowered
        for marker in ("change-me", "changeme", "your-", "replace", "example.com")
    )


def _load_or_create_local_secret() -> tuple[str, str]:
    """Development fallback: persist a generated key outside the repo.

    Written with mode 0600 so another local user cannot read the session key.
    """
    import secrets

    path = Path(LOCAL_SECRET_FILE)
    if path.is_file():
        try:
            existing = path.read_text(encoding="utf-8").strip()
            if len(existing) >= MIN_SECRET_LENGTH:
                return existing, "file"
        except OSError:
            pass

    generated = secrets.token_hex(32)
    try:
        path.write_text(generated + "\n", encoding="utf-8")
        os.chmod(path, 0o600)
    except OSError:
        # A read-only working directory is not fatal in development: the key
        # still works for this process, it just will not survive a restart.
        return generated, "ephemeral"
    return generated, "file"


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class Config:
    """Validated, immutable-ish application settings."""

    env: str = "development"
    secret_key: str = ""
    secret_source: str = "generated"

    bind_host: str = "127.0.0.1"
    bind_port: int = 8000
    public_base_url: str = "http://127.0.0.1:8000"
    require_https_links: bool = False

    database_file: str = "data/ruk.db"
    trust_proxy_headers: bool = False

    ip_storage_mode: str = "full"
    ip_hash_salt: str = ""

    geo_provider: str = "none"
    geo_db_path: str = ""
    geo_http_endpoint: str = ""

    default_retention_days: int = 90
    retention_sweep_seconds: int = 3600

    session_lifetime_seconds: int = 3600
    session_cookie_secure: bool = False

    login_rate_limit: int = 8
    login_rate_window: int = 300
    public_rate_limit: int = 120
    public_rate_window: int = 60

    policy_version: str = "1.0"

    warnings: list[str] = field(default_factory=list)

    # -- derived --------------------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def base_url(self) -> str:
        return self.public_base_url.rstrip("/")

    @property
    def is_local_only(self) -> bool:
        """True when visitors could not possibly reach this deployment."""
        lowered = self.public_base_url.lower()
        return any(
            marker in lowered
            for marker in ("127.0.0.1", "localhost", "0.0.0.0", "[::1]")
        )

    def share_url(self, tracking_id: str) -> str:
        return f"{self.base_url}/l/{tracking_id}"

    def qr_url(self, tracking_id: str) -> str:
        return f"{self.base_url}/l/{tracking_id}.png"

    # -- construction ---------------------------------------------------
    @classmethod
    def from_env(cls) -> "Config":
        load_dotenv()

        env = _env_str("RUK_ENV", "development").lower()
        if env not in VALID_ENVS:
            raise ConfigError(
                f"RUK_ENV must be one of {sorted(VALID_ENVS)} (got {env!r})"
            )

        secret_key = _env_str("SECRET_KEY")
        secret_source = "environment"
        if not secret_key or _looks_like_placeholder(secret_key):
            if env == "production":
                raise ConfigError(
                    "SECRET_KEY must be set to at least "
                    f"{MIN_SECRET_LENGTH} characters in production. Generate one:"
                    " python -c \"import secrets; print(secrets.token_hex(32))\""
                )
            secret_key, secret_source = _load_or_create_local_secret()
        if len(secret_key) < MIN_SECRET_LENGTH:
            raise ConfigError(
                f"SECRET_KEY must be at least {MIN_SECRET_LENGTH} characters "
                f"(got {len(secret_key)})"
            )

        bind_port = _env_int("BIND_PORT", 8000, minimum=1, maximum=65535)
        bind_host = _env_str("BIND_HOST", "127.0.0.1") or "127.0.0.1"

        public_base_url = _env_str(
            "PUBLIC_BASE_URL", f"http://{bind_host}:{bind_port}"
        ).rstrip("/")
        if not public_base_url.startswith(("http://", "https://")):
            raise ConfigError(
                "PUBLIC_BASE_URL must start with http:// or https:// "
                f"(got {public_base_url!r})"
            )

        is_prod = env == "production"
        if is_prod and not public_base_url.startswith("https://"):
            raise ConfigError(
                "PUBLIC_BASE_URL must use https:// in production, because "
                "tracking links carry a consent notice and session cookies"
            )

        ip_storage_mode = _env_str("IP_STORAGE_MODE", "full").lower()
        if ip_storage_mode not in VALID_IP_MODES:
            raise ConfigError(
                f"IP_STORAGE_MODE must be one of {sorted(VALID_IP_MODES)} "
                f"(got {ip_storage_mode!r})"
            )

        geo_provider = _env_str("GEO_PROVIDER", "none").lower()
        if geo_provider not in VALID_GEO_PROVIDERS:
            raise ConfigError(
                f"GEO_PROVIDER must be one of {sorted(VALID_GEO_PROVIDERS)} "
                f"(got {geo_provider!r})"
            )

        ip_hash_salt = _env_str("IP_HASH_SALT")
        if not ip_hash_salt and ip_storage_mode == "hashed":
            # Deriving from the secret is acceptable: it is already required and
            # never leaves the host. A dedicated salt is better.
            ip_hash_salt = secret_key[:32]

        session_cookie_secure = _env_bool("SESSION_COOKIE_SECURE", is_prod)
        if is_prod and not session_cookie_secure:
            raise ConfigError(
                "SESSION_COOKIE_SECURE must be true in production, otherwise "
                "the admin session cookie travels over plain HTTP"
            )

        database_file = _env_str("DATABASE_PATH", "data/ruk.db") or "data/ruk.db"

        config = cls(
            env=env,
            secret_key=secret_key,
            secret_source=secret_source,
            bind_host=bind_host,
            bind_port=bind_port,
            public_base_url=public_base_url,
            require_https_links=_env_bool("REQUIRE_HTTPS_LINKS", is_prod),
            database_file=database_file,
            trust_proxy_headers=_env_bool("TRUST_PROXY_HEADERS", False),
            ip_storage_mode=ip_storage_mode,
            ip_hash_salt=ip_hash_salt,
            geo_provider=geo_provider,
            geo_db_path=_env_str("GEO_DB_PATH"),
            geo_http_endpoint=_env_str("GEO_HTTP_ENDPOINT"),
            default_retention_days=_env_int(
                "DEFAULT_RETENTION_DAYS", 90, minimum=1, maximum=3650
            ),
            retention_sweep_seconds=_env_int(
                "RETENTION_SWEEP_SECONDS", 3600, minimum=60
            ),
            session_lifetime_seconds=_env_int(
                "SESSION_LIFETIME_SECONDS", 3600, minimum=300
            ),
            session_cookie_secure=session_cookie_secure,
            login_rate_limit=_env_int("LOGIN_RATE_LIMIT", 8, minimum=1),
            login_rate_window=_env_int("LOGIN_RATE_WINDOW", 300, minimum=1),
            public_rate_limit=_env_int("PUBLIC_RATE_LIMIT", 120, minimum=1),
            public_rate_window=_env_int("PUBLIC_RATE_WINDOW", 60, minimum=1),
            policy_version=_env_str("POLICY_VERSION", "1.0") or "1.0",
        )
        config.warnings = _collect_warnings(config)
        return config


def _collect_warnings(config: Config) -> list[str]:
    """Non-fatal problems worth putting in front of the operator."""
    out: list[str] = []

    if config.is_local_only:
        out.append(
            "PUBLIC_BASE_URL points at this machine, so tracking links will "
            "only work on this machine until you set a reachable address."
        )
    if config.env != "production" and not config.is_local_only:
        out.append(
            f"RUK_ENV is {config.env!r}: the development server is not hardened "
            "for public traffic. Use a reverse proxy in production."
        )
    if config.ip_storage_mode == "full":
        out.append(
            "IP_STORAGE_MODE=full stores complete visitor addresses. Consider "
            "truncated, hashed or none."
        )
    if config.geo_provider == "http" and not config.geo_http_endpoint:
        out.append(
            "GEO_PROVIDER=http but GEO_HTTP_ENDPOINT is empty, so no location "
            "will ever be recorded."
        )
    if config.geo_provider == "http":
        out.append(
            "GEO_PROVIDER=http sends visitor IP addresses to an external "
            "service. Disclose this in your privacy notice."
        )
    if config.geo_provider == "maxmind" and not config.geo_db_path:
        out.append(
            "GEO_PROVIDER=maxmind but GEO_DB_PATH is empty, so no location "
            "will ever be recorded."
        )
    if config.ip_storage_mode == "hashed" and not _env_str("IP_HASH_SALT"):
        out.append(
            "IP_HASH_SALT is unset, so the hash salt is derived from "
            "SECRET_KEY. Setting a dedicated salt is preferable."
        )
    if config.trust_proxy_headers:
        out.append(
            "TRUST_PROXY_HEADERS=true: X-Forwarded-For is believed. Only keep "
            "this on behind your own reverse proxy."
        )
    return out
