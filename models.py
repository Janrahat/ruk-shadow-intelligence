"""Typed data models mirroring the SQLite schema.

These are plain dataclasses - no ORM - so the persistence layer stays obvious
and every SQL statement remains visible and auditable in database.py.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Administrator:
    id: int
    username: str
    password_hash: str
    role: str = "admin"
    created_at: str = ""
    last_login_at: str | None = None
    is_active: bool = True
    failed_attempts: int = 0

    @property
    def is_superadmin(self) -> bool:
        return self.role == "superadmin"

    @classmethod
    def from_row(cls, row: Any) -> "Administrator":
        data = dict(row)
        return cls(
            id=data["id"],
            username=data["username"],
            password_hash=data["password_hash"],
            role=data.get("role", "admin"),
            created_at=data.get("created_at", ""),
            last_login_at=data.get("last_login_at"),
            is_active=bool(data.get("is_active", 1)),
            failed_attempts=data.get("failed_attempts", 0),
        )


@dataclass(slots=True)
class Campaign:
    id: int
    name: str
    slug: str
    description: str = ""
    created_at: str = ""
    is_archived: bool = False
    link_count: int = 0
    total_events: int = 0

    @classmethod
    def from_row(cls, row: Any) -> "Campaign":
        data = dict(row)
        return cls(
            id=data["id"],
            name=data["name"],
            slug=data["slug"],
            description=data.get("description", "") or "",
            created_at=data.get("created_at", ""),
            is_archived=bool(data.get("is_archived", 0)),
            link_count=data.get("link_count", 0) or 0,
            total_events=data.get("total_events", 0) or 0,
        )


@dataclass(slots=True)
class TrackingLink:
    """A shareable analytics link pointing at a validated destination URL."""

    id: int
    tracking_id: str
    campaign_id: int | None
    campaign_name: str
    destination_url: str
    label: str = ""
    created_at: str = ""
    expires_at: str | None = None
    revoked_at: str | None = None
    require_consent: bool = True
    retention_days: int = 90
    click_count: int = 0
    unique_count: int = 0
    last_click_at: str | None = None

    @property
    def is_revoked(self) -> bool:
        return bool(self.revoked_at)

    def is_expired(self, now_iso: str) -> bool:
        return bool(self.expires_at and self.expires_at <= now_iso)

    @classmethod
    def from_row(cls, row: Any) -> "TrackingLink":
        data = dict(row)
        return cls(
            id=data["id"],
            tracking_id=data["tracking_id"],
            campaign_id=data.get("campaign_id"),
            campaign_name=data.get("campaign_name") or "",
            destination_url=data["destination_url"],
            label=data.get("label", "") or "",
            created_at=data.get("created_at", ""),
            expires_at=data.get("expires_at"),
            revoked_at=data.get("revoked_at"),
            require_consent=bool(data.get("require_consent", 1)),
            retention_days=data.get("retention_days", 90),
            click_count=data.get("click_count", 0) or 0,
            unique_count=data.get("unique_count", 0) or 0,
            last_click_at=data.get("last_click_at"),
        )


@dataclass(slots=True)
class ConsentRecord:
    """Immutable record of what a visitor agreed to, and when."""

    id: int
    tracking_id: str
    visitor_token: str
    granted: bool
    policy_version: str
    scope: str = "analytics"
    created_at: str = ""
    withdrawn_at: str | None = None
    notice_sha256: str = ""

    @classmethod
    def from_row(cls, row: Any) -> "ConsentRecord":
        data = dict(row)
        return cls(
            id=data["id"],
            tracking_id=data["tracking_id"],
            visitor_token=data["visitor_token"],
            granted=bool(data["granted"]),
            policy_version=data.get("policy_version", ""),
            scope=data.get("scope", "analytics"),
            created_at=data.get("created_at", ""),
            withdrawn_at=data.get("withdrawn_at"),
            notice_sha256=data.get("notice_sha256", "") or "",
        )


@dataclass(slots=True)
class AnalyticsEvent:
    """One recorded visit. Every field is optional by design: an empty string
    means the value was not technically available, not that it was suppressed.
    """

    id: int
    event_uid: str
    tracking_id: str
    campaign_id: int | None
    campaign_name: str
    created_at: str
    consent_status: str = "granted"
    visitor_token: str = ""
    ip_address: str = ""
    ip_hash: str = ""
    country: str = ""
    region: str = ""
    city: str = ""
    geo_source: str = ""
    browser_family: str = ""
    browser_version: str = ""
    os_family: str = ""
    os_version: str = ""
    device_category: str = ""
    referrer_host: str = ""
    is_unique: bool = True

    @property
    def has_geo(self) -> bool:
        return bool(self.country)

    @property
    def location_label(self) -> str:
        """Honest display label - never pretends to know a precise position."""
        if not self.country:
            return "-"
        parts = [p for p in (self.city, self.region, self.country) if p]
        return ", ".join(parts)

    @classmethod
    def from_row(cls, row: Any) -> "AnalyticsEvent":
        data = dict(row)
        return cls(
            id=data["id"],
            event_uid=data.get("event_uid", ""),
            tracking_id=data.get("tracking_id", ""),
            campaign_id=data.get("campaign_id"),
            campaign_name=data.get("campaign_name") or "",
            created_at=data.get("created_at", ""),
            consent_status=data.get("consent_status", ""),
            visitor_token=data.get("visitor_token", "") or "",
            ip_address=data.get("ip_address", "") or "",
            ip_hash=data.get("ip_hash", "") or "",
            country=data.get("country", "") or "",
            region=data.get("region", "") or "",
            city=data.get("city", "") or "",
            geo_source=data.get("geo_source", "") or "",
            browser_family=data.get("browser_family", "") or "",
            browser_version=data.get("browser_version", "") or "",
            os_family=data.get("os_family", "") or "",
            os_version=data.get("os_version", "") or "",
            device_category=data.get("device_category", "") or "",
            referrer_host=data.get("referrer_host", "") or "",
            is_unique=bool(data.get("is_unique", 1)),
        )


@dataclass(slots=True)
class AuditEntry:
    id: int
    created_at: str
    actor: str
    action: str
    detail: str = ""
    ip_address: str = ""

    @classmethod
    def from_row(cls, row: Any) -> "AuditEntry":
        data = dict(row)
        return cls(
            id=data["id"],
            created_at=data.get("created_at", ""),
            actor=data.get("actor", ""),
            action=data.get("action", ""),
            detail=data.get("detail", "") or "",
            ip_address=data.get("ip_address", "") or "",
        )


@dataclass(slots=True)
class DashboardTotals:
    """Aggregate numbers for the overview cards."""

    total_events: int = 0
    unique_events: int = 0
    active_links: int = 0
    total_links: int = 0
    campaigns: int = 0
    consent_granted: int = 0
    consent_declined: int = 0
    events_24h: int = 0
    events_7d: int = 0

    @property
    def consent_rate(self) -> float:
        total = self.consent_granted + self.consent_declined
        if total == 0:
            return 0.0
        return round(100.0 * self.consent_granted / total, 1)


@dataclass(slots=True)
class Breakdown:
    """A single row of any grouped report (browser, device, country...)."""

    label: str
    count: int
    share: float = 0.0

    @classmethod
    def from_row(cls, row: Any) -> "Breakdown":
        data = dict(row)
        return cls(
            label=data.get("label") or "unknown",
            count=data.get("count", 0) or 0,
            share=float(data.get("share", 0) or 0),
        )


@dataclass(slots=True)
class LinkStats:
    tracking_id: str
    label: str = ""
    campaign_name: str = ""
    clicks: int = 0
    uniques: int = 0
    ctr: float = 0.0
    last_click_at: str | None = None
    first_click_at: str | None = None


EVENT_FIELD_LIMITS = {
    "country": 64,
    "region": 96,
    "city": 96,
    "browser_family": 48,
    "browser_version": 24,
    "os_family": 48,
    "os_version": 24,
    "device_category": 16,
    "referrer_host": 253,
}
