"""Security primitives: password hashing, CSRF, rate limiting, IP handling
and destination-URL (SSRF / open-redirect) validation.

Every function here is deliberately small and independently testable.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
import socket
import threading
import time
import unicodedata
from collections import deque
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit

# ---------------------------------------------------------------------------
# Password hashing (Argon2id)
# ---------------------------------------------------------------------------

try:  # pragma: no cover - import guard
    from argon2 import PasswordHasher
    from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

    _hasher = PasswordHasher(
        time_cost=2,          # sensible for small ARM devices such as Termux
        memory_cost=65536,    # 64 MiB
        parallelism=2,
        hash_len=32,
        salt_len=16,
    )
    ARGON2_AVAILABLE = True
except ImportError:  # pragma: no cover
    PasswordHasher = None  # type: ignore
    ARGON2_AVAILABLE = False

    class VerifyMismatchError(Exception):  # type: ignore
        pass

    class VerificationError(Exception):  # type: ignore
        pass

    class InvalidHashError(Exception):  # type: ignore
        pass


MIN_PASSWORD_LENGTH = 10
_COMMON_PASSWORDS = {
    "password123", "password1234", "administrator", "letmein1234",
    "qwertyuiop", "1234567890", "adminadmin", "changeme123",
    "password12345", "welcome12345", "rukpassword", "shadow12345",
}


class WeakPasswordError(ValueError):
    """Raised when a proposed administrator password is not acceptable."""


class PasswordHashingUnavailable(RuntimeError):
    """Raised when argon2-cffi is not installed."""


def hash_password(password: str) -> str:
    """Hash a password with Argon2id.

    Raises WeakPasswordError for policy violations and
    PasswordHashingUnavailable when argon2-cffi is missing.
    """
    if not ARGON2_AVAILABLE:
        raise PasswordHashingUnavailable(
            "argon2-cffi is not installed. Run: pip install argon2-cffi"
        )
    validate_password_strength(password)
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Constant-time password verification. Never raises on bad input."""
    if not ARGON2_AVAILABLE or not stored_hash or not password:
        return False
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception:  # pragma: no cover - defensive
        return False


def needs_rehash(stored_hash: str) -> bool:
    if not ARGON2_AVAILABLE or not stored_hash:
        return False
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except Exception:  # pragma: no cover
        return False


def validate_password_strength(password: str) -> None:
    """Enforce a minimum password policy.

    Length is the only hard requirement; character-class rules are deliberately
    not imposed because they push users towards predictable patterns.
    """
    if not isinstance(password, str):
        raise WeakPasswordError("password must be a string")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(
            f"password must be at least {MIN_PASSWORD_LENGTH} characters"
        )
    if len(password) > 512:
        raise WeakPasswordError("password must be at most 512 characters")
    if password.lower() in _COMMON_PASSWORDS:
        raise WeakPasswordError("password is too common; choose something unique")
    if len(set(password)) < 5:
        raise WeakPasswordError("password is not varied enough")


# ---------------------------------------------------------------------------
# Token generation
# ---------------------------------------------------------------------------

TRACKING_ID_BYTES = 9
ALIAS_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,30}[a-z0-9])$")

RESERVED_ALIASES = {
    "admin", "api", "login", "logout", "static", "healthz", "health",
    "privacy", "terms", "about", "favicon", "robots", "sitemap", "qr",
    "l", "r", "s", "dashboard", "assets", "css", "js", "img", "qr_codes",
}


def generate_tracking_id() -> str:
    """Cryptographically random, URL-safe tracking identifier (12 chars)."""
    return secrets.token_urlsafe(TRACKING_ID_BYTES)[:12]


def generate_visitor_token() -> str:
    """Opaque per-visitor token correlating consent with its events.

    This is a random value placed in a first-party cookie. It is NOT a
    fingerprint: it is regenerated when the browser drops cookies.
    """
    return secrets.token_urlsafe(24)


def validate_alias(alias: str) -> tuple[bool, str]:
    """Validate a custom link alias (a URL path segment)."""
    if not alias:
        return False, "alias must not be empty"
    if len(alias) < 3:
        return False, "alias must be at least 3 characters"
    if len(alias) > 32:
        return False, "alias must be at most 32 characters"
    if not ALIAS_RE.match(alias):
        return False, (
            "alias may contain only lowercase letters, digits and hyphens, and must "
            "start and end with a letter or digit"
        )
    if alias in RESERVED_ALIASES:
        return False, f"alias {alias!r} is reserved"
    return True, ""


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------

CSRF_SESSION_KEY = "_csrf_token"


def ensure_csrf_token(session) -> str:
    """Return the session's CSRF token, creating one if absent."""
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def verify_csrf_token(session, submitted: str | None) -> bool:
    """Constant-time CSRF comparison. Returns False on any doubt."""
    expected = session.get(CSRF_SESSION_KEY)
    if not expected or not submitted or not isinstance(submitted, str):
        return False
    return hmac.compare_digest(expected, submitted)


# ---------------------------------------------------------------------------
# Rate limiting (in-process sliding window)
# ---------------------------------------------------------------------------


class RateLimiter:
    """Thread-safe sliding-window rate limiter.

    Scope note: state lives in this process only. A multi-process or multi-host
    deployment must use Redis (or similar) instead - the built-in limiter would
    otherwise allow N times the intended rate.
    """

    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = max(1, int(limit))
        self.window = max(1, int(window_seconds))
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, cost: int = 1, now: float | None = None) -> bool:
        """Record an attempt. Returns True when it is within the limit."""
        now = time.monotonic() if now is None else now
        cutoff = now - self.window
        with self._lock:
            bucket = self._hits.setdefault(key, deque())
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) + cost > self.limit:
                return False
            for _ in range(cost):
                bucket.append(now)
            return True

    def remaining(self, key: str, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        cutoff = now - self.window
        with self._lock:
            bucket = self._hits.get(key)
            if not bucket:
                return self.limit
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            return max(0, self.limit - len(bucket))

    def retry_after(self, key: str, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        with self._lock:
            bucket = self._hits.get(key)
            if not bucket:
                return 0
            return max(0, int(bucket[0] + self.window - now) + 1)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


# ---------------------------------------------------------------------------
# IP address handling
# ---------------------------------------------------------------------------


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def client_ip(raw_remote_addr: str | None, forwarded_for: str | None,
              trust_proxy: bool) -> str:
    """Resolve the visitor IP.

    X-Forwarded-For is only honoured when the operator has explicitly declared
    a trusted reverse proxy. Otherwise any client could spoof its address and
    poison the analytics.
    """
    if trust_proxy and forwarded_for:
        candidate = forwarded_for.split(",")[0].strip()
        if _is_valid_ip(candidate):
            return candidate
    if raw_remote_addr and _is_valid_ip(raw_remote_addr):
        return raw_remote_addr
    return ""


def normalize_ip(value: str | None) -> str:
    """Return a canonical IP string or '' when unparseable."""
    if not value:
        return ""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return ""


def truncate_ip(value: str) -> str:
    """Coarsen an IP so it is no longer a single-host identifier.

    IPv4 -> /24 (203.0.113.42 -> 203.0.113.0)
    IPv6 -> /64 prefix
    """
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return ""
    if addr.version == 4:
        net = ipaddress.ip_network(f"{addr}/24", strict=False)
        return str(net.network_address)
    net = ipaddress.ip_network(f"{addr}/64", strict=False)
    return f"{net.network_address}/64"


def hash_ip(value: str, salt: str) -> str:
    """Keyed hash of an IP address (HMAC-SHA256, truncated to 32 hex chars)."""
    if not value or not salt:
        return ""
    digest = hmac.new(salt.encode("utf-8"), value.encode("utf-8"), hashlib.sha256)
    return digest.hexdigest()[:32]


def apply_ip_policy(value: str, mode: str, salt: str) -> tuple[str, str]:
    """Apply the configured IP storage policy.

    Returns (stored_ip, ip_hash). Under 'none' both are empty; under 'hashed'
    the plaintext column stays empty and only the hash is kept.
    """
    value = normalize_ip(value)
    if not value or mode == "none":
        return "", ""
    if mode == "full":
        return value, ""
    if mode == "truncated":
        return truncate_ip(value), ""
    if mode == "hashed":
        return "", hash_ip(value, salt)
    return "", ""


# ---------------------------------------------------------------------------
# Input sanitisation
# ---------------------------------------------------------------------------

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_text(value: str | None, max_length: int = 500, *,
                  allow_newlines: bool = True) -> str:
    """Normalise free text: strip control characters, collapse runs, cap length.

    HTML escaping is NOT done here - Jinja2 autoescaping handles output
    encoding, which is the correct layer for it.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    value = unicodedata.normalize("NFC", value)
    value = _CONTROL_CHARS.sub("", value)
    if allow_newlines:
        value = value.replace("\r\n", "\n").replace("\r", "\n")
    else:
        value = value.replace("\r", " ").replace("\n", " ")
    value = re.sub(r"[ \t]{2,}", " ", value)
    value = re.sub(r"\n{3,}", "\n\n", value)
    return value.strip()[:max_length]


def sanitize_single_line(value: str | None, max_length: int = 200) -> str:
    return sanitize_text(value, max_length=max_length, allow_newlines=False)


def sanitize_campaign_name(value: str | None) -> str:
    """Campaign names are single-line, 1-80 chars, printable."""
    return sanitize_single_line(value, max_length=80)


# ---------------------------------------------------------------------------
# Destination URL validation (open-redirect and SSRF protection)
# ---------------------------------------------------------------------------

URL_MAX_LENGTH = 2048
_BLOCKED_HOST_SUFFIXES = (
    ".local", ".localhost", ".internal", ".intranet", ".lan", ".home.arpa",
    ".corp", ".test", ".invalid",
)
_BLOCKED_HOSTNAMES = {
    "localhost", "metadata", "metadata.google.internal",
    "instance-data", "169.254.169.254",
}


class DestinationValidationError(ValueError):
    """Raised when a destination URL is not acceptable."""


def validate_destination_url(
    raw: str,
    *,
    require_https: bool = False,
    resolve_dns: bool = True,
) -> str:
    """Validate and normalise a tracking destination URL.

    Rejects:
      - non http/https schemes (javascript:, data:, file:, ftp: ...)
      - embedded credentials (https://user:pass@host/)
      - IP literals in private / loopback / link-local / reserved ranges
      - hostnames resolving to such addresses (SSRF)
      - cloud metadata endpoints
      - control characters, whitespace and over-long URLs

    Returns the normalised URL, or raises DestinationValidationError with a
    message safe to show an administrator.
    """
    if not raw or not isinstance(raw, str):
        raise DestinationValidationError("destination URL is required")

    candidate = raw.strip()
    if not candidate:
        raise DestinationValidationError("destination URL is empty")
    if len(candidate) > URL_MAX_LENGTH:
        raise DestinationValidationError(
            f"destination URL is longer than {URL_MAX_LENGTH} characters"
        )
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in candidate):
        raise DestinationValidationError(
            "destination URL must not contain spaces or control characters"
        )
    if "\\" in candidate:
        raise DestinationValidationError("destination URL must not contain backslashes")

    parts = urlsplit(candidate)
    scheme = parts.scheme.lower()
    if not scheme:
        raise DestinationValidationError(
            "destination URL must include a scheme, for example https://example.com"
        )
    if scheme not in {"http", "https"}:
        raise DestinationValidationError(
            f"scheme {scheme!r} is not allowed; only http and https are accepted"
        )
    if require_https and scheme != "https":
        raise DestinationValidationError(
            "this deployment requires https:// destination links"
        )
    if parts.username or parts.password:
        raise DestinationValidationError("destination URL must not embed credentials")

    hostname = (parts.hostname or "").lower().rstrip(".")
    if not hostname:
        raise DestinationValidationError("destination URL has no hostname")
    if len(hostname) > 253:
        raise DestinationValidationError("destination hostname is too long")

    _reject_unsafe_hostname(hostname)

    try:
        port = parts.port
    except ValueError as exc:
        raise DestinationValidationError("destination URL has an invalid port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise DestinationValidationError("destination port is out of range")

    if resolve_dns:
        _reject_private_resolution(hostname)

    netloc = hostname if port is None else f"{hostname}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, parts.fragment))


def _reject_unsafe_hostname(hostname: str) -> None:
    if hostname in _BLOCKED_HOSTNAMES:
        raise DestinationValidationError(
            f"hostname {hostname!r} is blocked (internal or metadata endpoint)"
        )
    for suffix in _BLOCKED_HOST_SUFFIXES:
        if hostname == suffix.lstrip(".") or hostname.endswith(suffix):
            raise DestinationValidationError(
                f"hostname {hostname!r} is blocked (private namespace)"
            )
    if "." not in hostname:
        raise DestinationValidationError(
            "destination hostname must be a fully qualified domain name"
        )
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        addr = None
    if addr is not None and _is_forbidden_address(addr):
        raise DestinationValidationError(
            f"IP address {hostname} is in a private or reserved range and cannot be "
            "used as a destination"
        )


def _is_forbidden_address(addr) -> bool:
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _reject_private_resolution(hostname: str) -> None:
    """Resolve a hostname and refuse it when it points at an internal address.

    This blocks the classic SSRF trick of a public DNS name whose A record is
    127.0.0.1 or 169.254.169.254. DNS failures are surfaced explicitly rather
    than silently allowed, because an unresolvable destination is useless.
    """
    try:
        ipaddress.ip_address(hostname)
        return
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise DestinationValidationError(
            f"hostname {hostname!r} could not be resolved ({exc.strerror or exc})"
        ) from exc

    if not infos:
        raise DestinationValidationError(f"hostname {hostname!r} did not resolve")

    for info in infos:
        raw_addr = info[4][0]
        try:
            addr = ipaddress.ip_address(raw_addr.split("%")[0])
        except ValueError:
            raise DestinationValidationError(
                f"hostname {hostname!r} resolved to an unparseable address"
            )
        if _is_forbidden_address(addr):
            raise DestinationValidationError(
                f"hostname {hostname!r} resolves to the private address {addr}; refusing "
                "to create a destination that points inside the network"
            )


_SAFE_REDIRECT_PATH = re.compile(r"^/[A-Za-z0-9/_\-.~%?=&]*$")


def safe_redirect_target(candidate: str | None, fallback: str = "/admin") -> str:
    """Only allow same-origin relative redirects (blocks open redirects)."""
    if not candidate or not isinstance(candidate, str):
        return fallback
    if not candidate.startswith("/") or candidate.startswith("//"):
        return fallback
    if "\\" in candidate or "\n" in candidate or "\r" in candidate:
        return fallback
    if not _SAFE_REDIRECT_PATH.match(candidate):
        return fallback
    return candidate


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

ADMIN_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

PUBLIC_CSP = (
    "default-src 'self'; "
    "script-src 'none'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'none'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


def apply_security_headers(response, *, csp: str = ADMIN_CSP, is_https: bool = False):
    """Attach the standard hardening header set to a Flask response."""
    response.headers.setdefault("Content-Security-Policy", csp)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Permissions-Policy",
        "geolocation=(), camera=(), microphone=(), payment=(), usb=()",
    )
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    if is_https:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response


def constant_time_equals(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def redact(value: str, keep: int = 4) -> str:
    """Redact a secret for logging: 'abcd********'. """
    if not value:
        return ""
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "*" * min(12, len(value) - keep)


def unique_preserving_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
