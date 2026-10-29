"""Approximate geolocation for analytics events.

Honesty contract
----------------
This module returns *approximate* country / region / city derived from the
visitor's IP address. It can never know a street address or a precise
position, and it must never imply otherwise.

Three providers:
  none     -> nothing is looked up (default). Fully offline, fully private.
  maxmind  -> local GeoLite2-City.mmdb. The IP never leaves the host.
  http     -> an external web API. The visitor IP leaves your host; only
              enable it if that is disclosed in your privacy notice.

Every failure path returns an explicit ``available=False`` result rather than
guessing or silently returning an empty location that looks like a real one.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field

from security import normalize_ip


@dataclass(slots=True)
class GeoResult:
    """Outcome of a lookup. ``available`` distinguishes 'not found' from 'no data'."""

    country: str = ""
    region: str = ""
    city: str = ""
    source: str = "none"
    available: bool = False
    error: str = ""

    def as_event_fields(self) -> dict[str, str]:
        return {
            "country": self.country[:64],
            "region": self.region[:96],
            "city": self.city[:96],
            "geo_source": self.source[:32],
        }


class GeoResolver:
    """Caches lookups so a repeat visitor does not trigger a second request."""

    def __init__(
        self,
        provider: str = "none",
        db_path: str = "",
        http_endpoint: str = "",
        cache_size: int = 2048,
        timeout: float = 3.0,
    ) -> None:
        self.provider = (provider or "none").lower()
        self.db_path = db_path
        self.http_endpoint = http_endpoint
        self.timeout = timeout
        self._cache: dict[str, GeoResult] = {}
        self._cache_size = max(16, cache_size)
        self._lock = threading.Lock()
        self._reader = None
        self._init_error = ""

        if self.provider == "maxmind":
            self._init_maxmind()
        elif self.provider not in {"none", "http"}:
            self._init_error = f"unknown GEO_PROVIDER {self.provider!r}"
            self.provider = "none"

    # -- provider init -------------------------------------------------
    def _init_maxmind(self) -> None:
        try:
            import geoip2.database  # type: ignore
        except ImportError:
            self._init_error = (
                "GEO_PROVIDER=maxmind requires the geoip2 package: "
                "pip install geoip2"
            )
            return
        try:
            self._reader = geoip2.database.Reader(self.db_path)
        except Exception as exc:
            self._init_error = f"could not open GeoIP database: {exc}"
            self._reader = None

    @property
    def status(self) -> str:
        """Short human-readable provider status for the terminal UI.

        A misconfiguration must be reported as a misconfiguration. Checking
        ``_init_error`` first means a typo in GEO_PROVIDER or a missing
        GeoIP database is surfaced instead of being reported as a deliberate
        "disabled" setting.
        """
        if self._init_error:
            return f"unavailable: {self._init_error}"
        if self.provider == "none":
            return "disabled (no geographic data recorded)"
        if self.provider == "maxmind":
            return "maxmind (local database)"
        if not self.http_endpoint:
            return "unavailable: GEO_PROVIDER=http but GEO_HTTP_ENDPOINT is empty"
        return "http (external API - visitor IP leaves this host)"

    @property
    def is_available(self) -> bool:
        if self.provider == "none":
            return False
        if self.provider == "maxmind":
            return self._reader is not None
        return self.provider == "http"

    # -- lookup --------------------------------------------------------
    def lookup(self, ip: str) -> GeoResult:
        ip = normalize_ip(ip)
        if not ip or self.provider == "none":
            return GeoResult(source="none", available=False)

        # Private / loopback addresses have no meaningful public location.
        if _is_private(ip):
            return GeoResult(
                source="none",
                available=False,
                error="private address; no public geolocation",
            )

        with self._lock:
            cached = self._cache.get(ip)
        if cached is not None:
            return cached

        if self.provider == "maxmind":
            result = self._lookup_maxmind(ip)
        else:
            result = self._lookup_http(ip)

        with self._lock:
            if len(self._cache) >= self._cache_size:
                self._cache.clear()
            self._cache[ip] = result
        return result

    def _lookup_maxmind(self, ip: str) -> GeoResult:
        if self._reader is None:
            return GeoResult(
                source="maxmind", available=False, error=self._init_error or "no reader"
            )
        try:
            response = self._reader.city(ip)
            country = response.country.name or ""
            region = ""
            if response.subdivisions:
                region = response.subdivisions.most_specific.name or ""
            city = response.city.name or ""
            return GeoResult(
                country=_safe(country),
                region=_safe(region),
                city=_safe(city),
                source="maxmind",
                available=bool(country),
                error="" if country else "not found in database",
            )
        except Exception as exc:  # geoip2 raises AddressNotFoundError and friends
            return GeoResult(
                source="maxmind",
                available=False,
                error=f"lookup failed: {type(exc).__name__}",
            )

    def _lookup_http(self, ip: str) -> GeoResult:
        if not self.http_endpoint:
            return GeoResult(
                source="http", available=False, error="no GEO_HTTP_ENDPOINT configured"
            )
        try:
            import requests
        except ImportError:  # pragma: no cover
            return GeoResult(
                source="http", available=False, error="requests is not installed"
            )

        url = self.http_endpoint.replace("{ip}", ip)
        if not url.startswith(("http://", "https://")):
            return GeoResult(
                source="http", available=False, error="endpoint must be http(s)"
            )
        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                headers={"User-Agent": "RUK-Shadow-Intelligence/1.0"},
            )
            if response.status_code != 200:
                return GeoResult(
                    source="http",
                    available=False,
                    error=f"HTTP {response.status_code}",
                )
            payload = response.json()
        except Exception as exc:  # network + JSON errors
            return GeoResult(
                source="http",
                available=False,
                error=f"lookup failed: {type(exc).__name__}",
            )

        if isinstance(payload, dict) and payload.get("status") == "fail":
            return GeoResult(
                source="http",
                available=False,
                error=str(payload.get("message", "provider reported failure"))[:120],
            )

        country = _pick(payload, "country", "country_name", "countryName")
        region = _pick(payload, "regionName", "region", "region_name")
        city = _pick(payload, "city", "city_name")

        return GeoResult(
            country=country,
            region=region,
            city=city,
            source="http",
            available=bool(country),
            error="" if country else "provider returned no country",
        )

    def close(self) -> None:
        if self._reader is not None:
            try:
                self._reader.close()
            except Exception:  # pragma: no cover
                pass
            self._reader = None


PICK_KEYS = ("country", "region", "city")


def _pick(payload: dict, *keys: str) -> str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return _safe(value)
    return ""


def _safe(value: str) -> str:
    """Keep only printable characters; geolocation names are display strings."""
    return "".join(ch for ch in str(value) if ch.isprintable()).strip()[:96]


def _is_private(ip: str) -> bool:
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return bool(
        addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_unspecified
    )


def describe_limitation() -> str:
    """The honest sentence shown in the UI and the README."""
    return (
        "Geographic data is approximate and derived from the IP address only. "
        "It cannot identify a street address, a precise position, or a person."
    )
