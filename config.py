"""Configuration loading for RUK SHADOW INTELLIGENCE.

All secrets come from the environment (or a .env file that is never committed).
Nothing sensitive is ever written into source code.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

VALID_IP_MODES = {"full", "truncated", "hashed", "none"}
VALID_GEO_PROVIDERS = {"none", "maxmind", "http"}
VALID_ENVS = {"development", "production", "testing"}


class ConfigError(RuntimeError):
    """Raised when the configuration cannot be used safely."""


def load_dotenv_file(path: Path | None = None) -> bool:
    """Load a .env file if python-dotenv is installed.

    Returns True when the file existed and was parsed. Real environment
    variables always win over the file because override=False is used.
    """
    path = path or (PROJECT_ROOT / ".env")
    if not path.exists():
        return False
    try:
        from dotenv import load_dotenv  # type: ignore
    except ImportError:  # pragma: no cover - optional dependency
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip("'\""))
        return True
    load_dotenv(path, override=False)
    return True


def _env_str(name: str, default: str = "") -> str:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env_str(name, "").lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = _env_str(name, "")
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


@dataclass
class Config:
    """Resolved runtime configuration.

    ``warnings`` collects non-fatal policy problems so callers (CLI, terminal
    UI) can surface them honestly instead of silently running in a weaker mode
    than the operator expects.
    """

    env: str = "development"
    secret_key: str = ""
    secret_source: str = "generated"

    bind_host: str = "127.0.0.1"
    bind_port: int = 8000
    public_base_url: str = "http://127.0.0.1:8000"
    require_https_links: bool = False

    database_path: str = "data/ruk_shadow.db"
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

    # ------------------------------------------------------------------
    @classmethod
    def from_env(cls, load_env_file: bool = True) -> "Config":
        if load_env_file:
            load_dotenv_file()

        warnings: list[str] = []

        env = _env_str("RUK_ENV", "development").lower()
        if env not in VALID_ENVS:
            raise ConfigError(f"RUK_ENV must be one of {sorted(VALID_ENVS)}, got {env!r}")

        secret_key = _env_str("SECRET_KEY")
        secret_source = "environment"
        if not secret_key:
            if env == "production":
                raise ConfigError(
                    "SECRET_KEY is required when RUK_ENV=production. "
                    'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(64))"'
                )
            secret_key, secret_source = _load_or_create_local_secret()

        if len(secret_key) < 32:
            raise ConfigError("SECRET_KEY must be at least 32 characters long")

        bind_port = _env_int("BIND_PORT", 8000)
        if not 1 <= bind_port <= 65535:
            raise ConfigError(f"BIND_PORT out of range: {bind_port}")

        bind_host = _env_str("BIND_HOST", "127.0.0.1") or "127.0.0.1"

        public_base_url = _env_str(
            "PUBLIC_BASE_URL", f"http://127.0.0.1:{bind_port}"
        ).rstrip("/")
        if not public_base_url.startswith(("http://", "https://")):
            raise ConfigError(
                "PUBLIC_BASE_URL must start with http:// or https:// "
                f"(got {public_base_url!r})"
            )

        ip_mode = _env_str("IP_STORAGE_MODE", "full").lower()
        if ip_mode not in VALID_IP_MODES:
            raise ConfigError(
                f"IP_STORAGE_MODE must be one of {sorted(VALID_IP_MODES)}, got {ip_mode!r}"
            )

        geo_provider = _env_str("GEO_PROVIDER", "none").lower()
        if geo_provider not in VALID_GEO_PROVIDERS:
            raise ConfigError(
                f"GEO_PROVIDER must be one of {sorted(VALID_GEO_PROVIDERS)}, got {geo_provider!r}"
            )

        geo_db_path = _env_str("GEO_DB_PATH")
        if geo_provider == "maxmind" and not geo_db_path:
            raise ConfigError(
                "GEO_PROVIDER=maxmind requires GEO_DB_PATH pointing at a "
                "GeoLite2-City.mmdb file"
            )

        ip_hash_salt = _env_str("IP_HASH_SALT")
        if ip_mode == "hashed" and not ip_hash_salt:
            ip_hash_salt = secret_key[:32]
            warnings.append(
                "IP_HASH_SALT is empty; derived it from SECRET_KEY. Set an explicit "
                "value in production so rotating SECRET_KEY does not change every "
                "visitor hash."
            )

        if env == "production":
            if not public_base_url.startswith("https://"):
                raise ConfigError(
                    "PUBLIC_BASE_URL must use https:// in production; tracking cookies "
                    "and admin sessions must not travel in clear text"
                )
            if not _env_bool("SESSION_COOKIE_SECURE", True):
                warnings.append(
                    "SESSION_COOKIE_SECURE is disabled in production; admin session "
                    "cookies can leak over plain HTTP."
                )

        if bind_host not in {"127.0.0.1", "localhost", "::1"} and not _env_bool(
            "TRUST_PROXY_HEADERS", False
        ):
            warnings.append(
                f"BIND_HOST={bind_host} exposes the app beyond localhost. Put it behind "
                "an HTTPS reverse proxy and set TRUST_PROXY_HEADERS=true only when "
                "that proxy is trusted."
            )

        retention_days = _env_int("DEFAULT_RETENTION_DAYS", 90)
        if retention_days < 1:
            raise ConfigError("DEFAULT_RETENTION_DAYS must be at least 1")

        return cls(
            env=env,
            secret_key=secret_key,
            secret_source=secret_source,
            bind_host=bind_host,
            bind_port=bind_port,
            public_base_url=public_base_url,
            require_https_links=_env_bool("REQUIRE_HTTPS_LINKS", env == "production"),
            database_path=_env_str("DATABASE_PATH", "data/ruk_shadow.db"),
            trust_proxy_headers=_env_bool("TRUST_PROXY_HEADERS", False),
            ip_storage_mode=ip_mode,
            ip_hash_salt=ip_hash_salt,
            geo_provider=geo_provider,
            geo_db_path=geo_db_path,
            geo_http_endpoint=_env_str(
                "GEO_HTTP_ENDPOINT",
                "https://ip-api.com/json/{ip}?fields=status,country,regionName,city",
            ),
            default_retention_days=retention_days,
            retention_sweep_seconds=_env_int("RETENTION_SWEEP_SECONDS", 3600),
            session_lifetime_seconds=_env_int("SESSION_LIFETIME_SECONDS", 3600),
            session_cookie_secure=_env_bool(
                "SESSION_COOKIE_SECURE", env == "production"
            ),
            login_rate_limit=_env_int("LOGIN_RATE_LIMIT", 8),
            login_rate_window=_env_int("LOGIN_RATE_WINDOW", 300),
            public_rate_limit=_env_int("PUBLIC_RATE_LIMIT", 120),
            public_rate_window=_env_int("PUBLIC_RATE_WINDOW", 60),
            policy_version=_env_str("POLICY_VERSION", "1.0"),
            warnings=warnings,
        )

    # ------------------------------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def database_file(self) -> Path:
        path = Path(self.database_path)
        return path if path.is_absolute() else PROJECT_ROOT / path

    @property
    def public_base(self) -> str:
        return self.public_base_url.rstrip("/")

    def share_url(self, tracking_id: str) -> str:
        return f"{self.public_base}/l/{tracking_id}"

    def qr_url(self, tracking_id: str) -> str:
        return f"{self.public_base}/l/{tracking_id}.png"

    def describe(self) -> list[tuple[str, str]]:
        """Human-readable settings table for the terminal UI (no secrets)."""
        return [
            ("Environment", self.env),
            ("Bind address", f"{self.bind_host}:{self.bind_port}"),
            ("Public base URL", self.public_base),
            ("Database", str(self.database_file)),
            ("Secret source", self.secret_source),
            ("IP storage", self.ip_storage_mode),
            ("Geolocation", self.geo_provider),
            ("Trust proxy headers", str(self.trust_proxy_headers)),
            ("HTTPS links required", str(self.require_https_links)),
            ("Retention (days)", str(self.default_retention_days)),
            ("Session lifetime (s)", str(self.session_lifetime_seconds)),
            ("Policy version", self.policy_version),
        ]


def _load_or_create_local_secret() -> tuple[str, str]:
    """Return (secret, source). Creates .ruk_secret with mode 0600 on first run."""
    path = PROJECT_ROOT / ".ruk_secret"
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if len(value) >= 32:
            _harden_permissions(path)
            return value, "file:.ruk_secret"
    value = secrets.token_urlsafe(48)
    path.write_text(value + "\n", encoding="utf-8")
    _harden_permissions(path)
    return value, "file:.ruk_secret (created)"


def _harden_permissions(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:  # pragma: no cover - platform dependent
        pass
