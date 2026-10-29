"""Tracking-link creation, validation and lifecycle rules."""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from config import Config
from database import Database, utc_now
from security import (
    DestinationValidationError,
    generate_tracking_id,
    sanitize_campaign_name,
    sanitize_single_line,
    validate_alias,
    validate_destination_url,
)

MAX_RETENTION_DAYS = 3650
MIN_RETENTION_DAYS = 1
MAX_EXPIRY_DAYS = 3650
# Longest alias accepted. Matches validate_alias() in security.py so an
# over-long alias is REJECTED rather than silently shortened into a
# different link than the operator asked for.
MAX_ALIAS_LENGTH = 32


class LinkCreationError(ValueError):
    """Raised when a link cannot be created; message is safe to display."""


@dataclass(slots=True)
class LinkRequest:
    """Raw, untrusted input from a form or CLI prompt."""

    destination_url: str
    campaign_name: str = ""
    campaign_id: int | None = None
    label: str = ""
    alias: str = ""
    expires_in_days: int | None = None
    require_consent: bool = True
    retention_days: int | None = None


@dataclass(slots=True)
class CreatedLink:
    tracking_id: str
    share_url: str
    qr_url: str
    destination_url: str
    campaign_id: int | None
    campaign_name: str
    label: str
    expires_at: str | None
    require_consent: bool
    retention_days: int

    def as_dict(self) -> dict:
        return {
            "tracking_id": self.tracking_id,
            "share_url": self.share_url,
            "qr_url": self.qr_url,
            "destination_url": self.destination_url,
            "campaign_id": self.campaign_id,
            "campaign_name": self.campaign_name,
            "label": self.label,
            "expires_at": self.expires_at,
            "require_consent": self.require_consent,
            "retention_days": self.retention_days,
        }


SLUG_SAFE_RE = re.compile(r"[^a-z0-9]+")


def slugify(value: str, max_length: int = 48) -> str:
    """Turn a campaign name into a URL-safe slug."""
    lowered = (value or "").strip().lower()
    slug = SLUG_SAFE_RE.sub("-", lowered).strip("-")
    return slug[:max_length] or "campaign"


def unique_campaign_slug(db: Database, base: str) -> str:
    """Return a slug that is not already taken, appending a counter if needed."""
    slug = slugify(base)
    if db.get_campaign_by_slug(slug) is None:
        return slug
    for i in range(2, 1000):
        candidate = f"{slug}-{i}"
        if db.get_campaign_by_slug(candidate) is None:
            return candidate
    return f"{slug}-{secrets.token_hex(3)}"


def _validate_retention(days: int | None, default: int) -> int:
    if days is None:
        days = default
    try:
        days = int(days)
    except (TypeError, ValueError) as exc:
        raise LinkCreationError("retention days must be a whole number") from exc
    if not MIN_RETENTION_DAYS <= days <= MAX_RETENTION_DAYS:
        raise LinkCreationError(
            f"retention must be between {MIN_RETENTION_DAYS} and "
            f"{MAX_RETENTION_DAYS} days"
        )
    return days


def _validate_expiry(days: int | None) -> str | None:
    if days in (None, "", 0, "0"):
        return None
    try:
        days = int(days)
    except (TypeError, ValueError) as exc:
        raise LinkCreationError("expiry must be a whole number of days") from exc
    if not 1 <= days <= MAX_EXPIRY_DAYS:
        raise LinkCreationError(
            f"expiry must be between 1 and {MAX_EXPIRY_DAYS} days "
            "(0 or empty for never)"
        )
    return (
        (datetime.now(timezone.utc) + timedelta(days=days))
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def resolve_campaign(
    db: Database,
    campaign_name: str,
    campaign_id: int | None,
) -> tuple[int | None, str]:
    """Resolve a campaign by id, or find/create one by name."""
    if campaign_id is not None:
        campaign = db.get_campaign(int(campaign_id))
        if campaign is None:
            raise LinkCreationError(f"campaign {campaign_id} does not exist")
        return campaign.id, campaign.name

    name = sanitize_campaign_name(campaign_name)
    if not name:
        return None, ""

    existing = db.get_campaign_by_slug(slugify(name))
    if existing is not None and existing.name.lower() == name.lower():
        return existing.id, existing.name

    slug = unique_campaign_slug(db, name)
    new_id = db.create_campaign(name=name, slug=slug, description="")
    return new_id, name


def create_tracking_link(
    db: Database,
    config: Config,
    request: LinkRequest,
) -> CreatedLink:
    """Create a validated tracking link.

    Validation order matters: the destination is validated first because the
    remaining fields are meaningless if the target is unsafe.
    """
    try:
        destination = validate_destination_url(
            request.destination_url,
            require_https=config.require_https_links,
            resolve_dns=True,
        )
    except DestinationValidationError as exc:
        raise LinkCreationError(str(exc)) from exc

    # Strip control characters only. The bound here is deliberately far larger
    # than MAX_ALIAS_LENGTH: sanitising must never silently shorten the alias,
    # because that would hand the operator a different link than they asked
    # for. Length and charset are then enforced by validate_alias, which
    # REJECTS rather than truncates.
    alias = sanitize_single_line(request.alias, max_length=512).lower()
    if alias:
        ok, reason = validate_alias(alias)
        if not ok:
            raise LinkCreationError(reason)
        if db.tracking_id_exists(alias):
            raise LinkCreationError(f"alias {alias!r} is already in use")

    campaign_id, campaign_name = resolve_campaign(
        db, request.campaign_name, request.campaign_id
    )

    expires_at = _validate_expiry(request.expires_in_days)
    retention_days = _validate_retention(
        request.retention_days, config.default_retention_days
    )
    label = sanitize_single_line(request.label, max_length=120)
    tracking_id = alias or _generate_unique_tracking_id(db)

    db.create_link(
        tracking_id=tracking_id,
        destination_url=destination,
        campaign_id=campaign_id,
        label=label,
        expires_at=expires_at,
        require_consent=bool(request.require_consent),
        retention_days=retention_days,
    )

    return CreatedLink(
        tracking_id=tracking_id,
        share_url=config.share_url(tracking_id),
        qr_url=config.qr_url(tracking_id),
        destination_url=destination,
        campaign_id=campaign_id,
        campaign_name=campaign_name,
        label=label,
        expires_at=expires_at,
        require_consent=bool(request.require_consent),
        retention_days=retention_days,
    )


def _generate_unique_tracking_id(db: Database, attempts: int = 12) -> str:
    for _ in range(attempts):
        candidate = generate_tracking_id()
        if len(candidate) >= 8 and not db.tracking_id_exists(candidate):
            return candidate
    raise LinkCreationError("could not allocate a unique tracking id; please retry")


def link_status(link, now_iso: str | None = None) -> tuple[str, str]:
    """Return (status_code, human_label) for a tracking link.

    Status codes: active | revoked | expired
    """
    now_iso = now_iso or utc_now()
    if link.is_revoked:
        return "revoked", "Revoked"
    if link.is_expired(now_iso):
        return "expired", "Expired"
    return "active", "Active"


def destination_is_reachable(url: str, timeout: float = 5.0) -> tuple[bool, str]:
    """Best-effort reachability probe used by the CLI after link creation.

    Never blocks link creation and never claims more than it measured.
    """
    try:
        import requests
    except ImportError:  # pragma: no cover
        return False, "requests is not installed; reachability not checked"
    try:
        response = requests.head(url, timeout=timeout, allow_redirects=True)
        if response.status_code >= 400:
            response = requests.get(
                url, timeout=timeout, allow_redirects=True, stream=True
            )
        return True, f"HTTP {response.status_code}"
    except Exception as exc:  # broad: network stack raises many types
        return False, f"unreachable ({type(exc).__name__})"
