"""Event recording, user-agent parsing, aggregation and export.

Consent is enforced here, not in the caller, so there is exactly one place
where 'should this be stored?' is answered.
"""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from typing import Any

from config import Config
from database import Database, utc_now
from geolocation import GeoResolver
from models import AnalyticsEvent, Breakdown, DashboardTotals
from security import (
    apply_ip_policy,
    client_ip,
    sanitize_single_line,
    sanitize_text,
)

# ---------------------------------------------------------------------------
# User-agent parsing
# ---------------------------------------------------------------------------

# Order matters: Edge/Opera/Chrome all claim to be Chrome; iOS Chrome claims
# Safari. Checks run from most specific to least specific.
_BROWSER_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("Edge", re.compile(r"Edg(?:e|A|iOS)?/([\d.]+)")),
    ("Opera", re.compile(r"OPR/([\d.]+)|Opera[ /]([\d.]+)")),
    ("Samsung Internet", re.compile(r"SamsungBrowser/([\d.]+)")),
    ("Firefox", re.compile(r"Firefox/([\d.]+)|FxiOS/([\d.]+)")),
    ("Chrome", re.compile(r"Chrome/([\d.]+)|CriOS/([\d.]+)")),
    ("Safari", re.compile(r"Version/([\d.]+).*Safari/")),
    ("Internet Explorer", re.compile(r"MSIE ([\d.]+)|Trident/.*rv:([\d.]+)")),
    ("curl", re.compile(r"^curl/([\d.]+)")),
    ("Wget", re.compile(r"^Wget/([\d.]+)")),
    ("Python requests", re.compile(r"python-requests/([\d.]+)")),
]

_OS_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("Android", re.compile(r"Android[ /]([\d.]+)")),
    ("iOS", re.compile(r"(?:iPhone )?OS ([\d_]+) like Mac OS X")),
    ("Windows", re.compile(r"Windows NT ([\d.]+)")),
    ("macOS", re.compile(r"Mac OS X ([\d_.]+)")),
    ("ChromeOS", re.compile(r"CrOS \w+ ([\d.]+)")),
    ("Ubuntu", re.compile(r"Ubuntu(?:/([\d.]+))?")),
    ("Linux", re.compile(r"Linux")),
]

_WINDOWS_NT_MAP = {
    "10.0": "10/11",
    "6.3": "8.1",
    "6.2": "8",
    "6.1": "7",
    "6.0": "Vista",
    "5.1": "XP",
}

_CELLULAR_HINTS = ("iphone", "ipod", "windows phone", "blackberry", "mobile")
_TABLET_HINTS = ("ipad", "tablet", "kindle", "silk", "playbook")


@dataclass(slots=True)
class UserAgentInfo:
    browser_family: str = ""
    browser_version: str = ""
    os_family: str = ""
    os_version: str = ""
    device_category: str = "desktop"


def parse_user_agent(user_agent: str | None) -> UserAgentInfo:
    """Classify a User-Agent string into coarse browser / OS / device buckets.

    Deliberately coarse: exact versions and hardware models are not needed for
    aggregate reporting and are more identifying than useful.
    """
    info = UserAgentInfo()
    if not user_agent or not isinstance(user_agent, str):
        info.browser_family = "unknown"
        info.os_family = "unknown"
        info.device_category = "unknown"
        return info

    ua = user_agent[:512]

    for family, pattern in _BROWSER_RULES:
        match = pattern.search(ua)
        if match:
            info.browser_family = family
            groups = [g for g in match.groups() if g]
            info.browser_version = _major_version(groups[0]) if groups else ""
            break
    else:
        info.browser_family = "unknown"

    for family, pattern in _OS_RULES:
        match = pattern.search(ua)
        if match:
            info.os_family = family
            version = next((g for g in match.groups() if g), "")
            version = version.replace("_", ".")
            if family == "Windows":
                version = _WINDOWS_NT_MAP.get(version, version)
            info.os_version = _major_version(version)
            break
    else:
        info.os_family = "unknown"

    info.device_category = _device_category(ua)
    return info


def _major_version(value: str) -> str:
    """Keep the major version only - '120.0.6099.109' becomes '120'."""
    if not value:
        return ""
    return value.split(".")[0][:12]


def _device_category(ua: str) -> str:
    lowered = ua.lower()
    # iPad and Android tablets report 'Mobile' inconsistently, so check first.
    if "ipad" in lowered or "tablet" in lowered or "silk" in lowered:
        return "tablet"
    if "android" in lowered and "mobile" not in lowered:
        return "tablet"
    if any(hint in lowered for hint in _CELLULAR_HINTS):
        return "mobile"
    if any(hint in lowered for hint in _TABLET_HINTS):
        return "tablet"
    if lowered in {"", "unknown"}:
        return "unknown"
    return "desktop"


# ---------------------------------------------------------------------------
# Event recording
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class VisitContext:
    """Everything the HTTP layer knows about a request, before policy is applied."""

    tracking_id: str
    remote_addr: str = ""
    forwarded_for: str | None = None
    user_agent: str = ""
    referer: str = ""
    visitor_token: str = ""
    consent_granted: bool = False


@dataclass(slots=True)
class RecordOutcome:
    recorded: bool
    reason: str = ""
    event: AnalyticsEvent | None = None


def new_event_uid() -> str:
    return secrets.token_hex(12)


def referrer_host(referer: str | None) -> str:
    """Reduce a Referer header to its hostname; the full path is not needed."""
    if not referer or not isinstance(referer, str):
        return ""
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(referer)
    except ValueError:
        return ""
    host = (parts.hostname or "").lower()
    if not host or len(host) > 253:
        return ""
    return host


class AnalyticsService:
    """Records permitted events and answers reporting queries."""

    def __init__(
        self,
        config: Config,
        db: Database,
        geo: GeoResolver | None = None,
    ) -> None:
        self.config = config
        self.db = db
        self.geo = geo or GeoResolver()

    # -- write path ----------------------------------------------------
    def record_visit(self, link, ctx: VisitContext) -> RecordOutcome:
        """Record one visit, enforcing consent and the configured IP policy.

        Returns RecordOutcome(recorded=False, reason=...) when nothing was
        stored, so the caller can be honest with the visitor and the operator.
        """
        if not ctx.consent_granted:
            return RecordOutcome(False, "no consent given; nothing was recorded")

        ua = parse_user_agent(ctx.user_agent)
        ip = client_ip(
            ctx.remote_addr, ctx.forwarded_for, self.config.trust_proxy_headers
        )
        stored_ip, ip_hash = apply_ip_policy(
            ip, self.config.ip_storage_mode, self.config.ip_hash_salt
        )

        # Geolocation only where an IP was actually retained for that purpose.
        geo_result = None
        if ip and self.config.geo_provider != "none":
            geo_result = self.geo.lookup(ip)
        geo_fields = (
            geo_result.as_event_fields()
            if geo_result is not None
            else {"country": "", "region": "", "city": "", "geo_source": "none"}
        )

        reference = unique_visitor_reference(ctx.visitor_token, ip, self.config)
        is_unique = self.db.visitor_event_count(reference, ctx.tracking_id) == 0

        event_uid = new_event_uid()
        payload = {
            "event_uid": event_uid,
            "tracking_id": ctx.tracking_id,
            "campaign_id": link.campaign_id if link else None,
            "created_at": utc_now(),
            "consent_status": "granted",
            "visitor_token": reference,
            "ip_address": stored_ip,
            "ip_hash": ip_hash,
            "browser_family": ua.browser_family,
            "browser_version": ua.browser_version,
            "os_family": ua.os_family,
            "os_version": ua.os_version,
            "device_category": ua.device_category,
            "referrer_host": referrer_host(ctx.referer),
            "is_unique": is_unique,
        }
        payload.update(geo_fields)

        self.db.insert_event(payload)
        event = self.db.list_events(limit=1, tracking_id=ctx.tracking_id, order="desc")
        return RecordOutcome(
            True,
            "recorded" if is_unique else "recorded (repeat visit)",
            event[0] if event else None,
        )

    # -- read path -----------------------------------------------------
    def totals(self) -> DashboardTotals:
        return self.db.dashboard_totals()

    def recent_events(self, limit: int = 25) -> list[AnalyticsEvent]:
        return self.db.list_events(limit=limit, order="desc")

    def new_events_since(self, last_id: int, limit: int = 100) -> list[AnalyticsEvent]:
        """Events newer than ``last_id`` - the SSE feed's polling primitive."""
        return self.db.list_events(limit=limit, after_id=last_id, order="asc")

    def breakdown(self, field: str, limit: int = 10, since: str | None = None) -> list[Breakdown]:
        return self.db.breakdown(field, limit=limit, since=since)

    def series(self, hours: int = 24) -> list[tuple[str, int]]:
        return self.db.traffic_series(hours=hours)

    def search(
        self,
        query: str = "",
        device: str = "",
        consent: str = "",
        since: str = "",
        page: int = 1,
        per_page: int = 25,
    ) -> tuple[list[AnalyticsEvent], int]:
        """Validated, paginated event search shared by web and terminal."""
        page = max(1, int(page or 1))
        per_page = max(5, min(int(per_page or 25), 200))
        clean_query = sanitize_single_line(query, max_length=64)
        clean_device = device if device in {"mobile", "tablet", "desktop", "unknown"} else ""
        clean_consent = consent if consent in {"granted", "declined"} else ""
        clean_since = since if re.fullmatch(r"\d{4}-\d{2}-\d{2}", since or "") else ""
        since_iso = f"{clean_since}T00:00:00Z" if clean_since else ""

        events = self.db.list_events(
            limit=per_page,
            offset=(page - 1) * per_page,
            search=clean_query or None,
            device=clean_device or None,
            consent=clean_consent or None,
            since=since_iso or None,
        )
        total = self.db.count_events(
            search=clean_query or None,
            device=clean_device or None,
            consent=clean_consent or None,
            since=since_iso or None,
        )
        return events, total

    def export(self, fmt: str = "csv", since: str | None = None,
               tracking_id: str | None = None) -> str:
        return self.db.export_events(fmt=fmt, since=since, tracking_id=tracking_id)


CELLULAR_REFERENCE_PREFIX = "ip-"


def unique_visitor_reference(visitor_token: str, ip: str, config: Config) -> str:
    """Build the opaque reference used to count unique visitors.

    Preference order:
      1. the first-party cookie token (stable while cookies persist)
      2. a keyed hash of the IP (when an IP was retained)
      3. a random value (this visit is then counted as unique, which is the
         honest fallback when nothing links two visits)
    """
    if visitor_token:
        return visitor_token[:64]
    if ip and config.ip_storage_mode != "none":
        from security import hash_ip

        digest = hash_ip(ip, config.ip_hash_salt or config.secret_key)
        return f"{CELLULAR_REFERENCE_PREFIX}{digest}"[:64]
    return secrets.token_urlsafe(12)


CONSENT_SCOPE_ANALYTICS = "analytics"
CONSENT_SCOPE_PRECISE_LOCATION = "precise_location"


def build_notice_summary(config: Config) -> dict[str, Any]:
    """Machine-readable summary of what this deployment collects.

    The consent page and the README render this, so the notice cannot drift
    away from the code that actually stores the data.
    """
    ip_text = {
        "full": "Your IP address is stored as received.",
        "truncated": "Your IP address is stored with the last part removed.",
        "hashed": "Your IP address is stored only as a one-way hash.",
        "none": "Your IP address is not stored at all.",
    }[config.ip_storage_mode]

    geo_text = {
        "none": "No geographic information is recorded.",
        "maxmind": (
            "An approximate country/region is derived from your IP using a local "
            "database; your IP is not sent to any third party."
        ),
        "http": (
            "An approximate country/region is derived from your IP by sending it "
            "to an external geolocation service."
        ),
    }[config.geo_provider]

    return {
        "ip_policy": config.ip_storage_mode,
        "ip_notice": ip_text,
        "geo_provider": config.geo_provider,
        "geo_notice": geo_text,
        "records": [
            "the time of your visit",
            "which link you arrived through",
            "your browser family and version (major number only)",
            "your operating system family and version (major number only)",
            "whether your device is a phone, tablet or computer",
            "the website that referred you, if your browser sent one",
        ],
        "never_collects": [
            "passwords or login credentials",
            "private messages or files",
            "your contacts",
            "your precise GPS position",
            "your camera or microphone",
            "your name, unless you type it yourself",
        ],
        "retention_days": config.default_retention_days,
        "policy_version": config.policy_version,
    }
