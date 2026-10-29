"""Link generation tests: token properties, aliases, campaign resolution,
expiry, retention and destination validation integration."""
from __future__ import annotations

import re

import pytest

from link_generator import (
    LinkCreationError,
    LinkRequest,
    create_tracking_link,
    link_status,
    resolve_campaign,
    slugify,
    unique_campaign_slug,
)


class TestSlugify:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("Autumn Promo", "autumn-promo"),
            ("Autumn Promo !! 2026", "autumn-promo-2026"),
            ("  spaced  ", "spaced"),
            ("UPPER", "upper"),
            ("a--b", "a-b"),
            ("---", "campaign"),
            ("", "campaign"),
            ("!!!", "campaign"),
        ],
    )
    def test_slug_generation(self, raw, expected):
        assert slugify(raw) == expected

    def test_slug_respects_max_length(self):
        assert len(slugify("x" * 200)) <= 48


class TestCampaignSlugUniqueness:
    def test_returns_base_when_free(self, db):
        assert unique_campaign_slug(db, "Free Name") == "free-name"

    def test_appends_counter_on_collision(self, db):
        db.create_campaign("Taken", "taken")
        assert unique_campaign_slug(db, "Taken") == "taken-2"

    def test_increments_past_multiple_collisions(self, db):
        db.create_campaign("Taken", "taken")
        db.create_campaign("Taken 2", "taken-2")
        assert unique_campaign_slug(db, "Taken") == "taken-3"


class TestCampaignResolution:
    def test_blank_name_returns_no_campaign(self, db):
        campaign_id, name = resolve_campaign(db, "", None)
        assert campaign_id is None
        assert name == ""

    def test_whitespace_name_returns_no_campaign(self, db):
        campaign_id, _ = resolve_campaign(db, "   ", None)
        assert campaign_id is None

    def test_creates_campaign_from_name(self, db):
        campaign_id, name = resolve_campaign(db, "New Campaign", None)
        assert campaign_id is not None
        assert name == "New Campaign"
        assert db.get_campaign(campaign_id).slug == "new-campaign"

    def test_reuses_existing_campaign_by_name(self, db):
        first, _ = resolve_campaign(db, "Reuse Me", None)
        second, _ = resolve_campaign(db, "Reuse Me", None)
        assert first == second

    def test_reuse_is_case_insensitive(self, db):
        first, _ = resolve_campaign(db, "Case Test", None)
        second, _ = resolve_campaign(db, "case test", None)
        assert first == second

    def test_explicit_campaign_id_used(self, db):
        created = db.create_campaign("By Id", "by-id")
        campaign_id, name = resolve_campaign(db, "ignored", created)
        assert campaign_id == created
        assert name == "By Id"

    def test_unknown_campaign_id_raises(self, db):
        with pytest.raises(LinkCreationError):
            resolve_campaign(db, "", 9999)


class TestCreateTrackingLink:
    def test_basic_creation(self, db, config):
        link = create_tracking_link(
            db, config, LinkRequest(destination_url="https://example.com/landing")
        )
        assert link.tracking_id
        assert link.destination_url == "https://example.com/landing"
        assert link.share_url == f"{config.public_base}/l/{link.tracking_id}"
        assert db.get_link(link.tracking_id) is not None

    def test_tracking_id_is_url_safe(self, db, config):
        link = create_tracking_link(
            db, config, LinkRequest(destination_url="https://example.com/")
        )
        assert re.fullmatch(r"[A-Za-z0-9_-]+", link.tracking_id)

    def test_tracking_ids_are_unique_across_links(self, db, config):
        ids = {
            create_tracking_link(
                db, config, LinkRequest(destination_url="https://example.com/")
            ).tracking_id
            for _ in range(25)
        }
        assert len(ids) == 25

    def test_invalid_destination_rejected(self, db, config):
        for bad in [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "http://127.0.0.1/",
            "example.com",
        ]:
            with pytest.raises(LinkCreationError):
                create_tracking_link(
                    db, config, LinkRequest(destination_url=bad)
                )

    def test_nothing_stored_when_destination_invalid(self, db, config):
        with pytest.raises(LinkCreationError):
            create_tracking_link(
                db, config, LinkRequest(destination_url="http://10.0.0.1/")
            )
        assert db.list_links() == []

    def test_custom_alias_used_verbatim(self, db, config):
        link = create_tracking_link(
            db, config,
            LinkRequest(destination_url="https://example.com/", alias="my-promo"),
        )
        assert link.tracking_id == "my-promo"

    def test_alias_is_lowercased(self, db, config):
        link = create_tracking_link(
            db, config,
            LinkRequest(destination_url="https://example.com/", alias="MY-PROMO"),
        )
        assert link.tracking_id == "my-promo"

    def test_duplicate_alias_rejected(self, db, config):
        create_tracking_link(
            db, config,
            LinkRequest(destination_url="https://example.com/", alias="dup"),
        )
        with pytest.raises(LinkCreationError, match="already in use"):
            create_tracking_link(
                db, config,
                LinkRequest(destination_url="https://example.com/", alias="dup"),
            )

    @pytest.mark.parametrize("alias", ["has space", "-lead", "UPPER!", "a" * 40])
    def test_invalid_alias_rejected(self, db, config, alias):
        with pytest.raises(LinkCreationError):
            create_tracking_link(
                db, config,
                LinkRequest(destination_url="https://example.com/", alias=alias),
            )

    def test_campaign_created_alongside_link(self, db, config):
        link = create_tracking_link(
            db, config,
            LinkRequest(destination_url="https://example.com/", campaign_name="Launch"),
        )
        assert link.campaign_id is not None
        assert link.campaign_name == "Launch"

    def test_two_links_share_one_campaign(self, db, config):
        first = create_tracking_link(
            db, config,
            LinkRequest(destination_url="https://example.com/", campaign_name="Shared"),
        )
        second = create_tracking_link(
            db, config,
            LinkRequest(destination_url="https://example.com/", campaign_name="Shared"),
        )
        assert first.campaign_id == second.campaign_id

    def test_expiry_in_days_is_stored(self, db, config):
        link = create_tracking_link(
            db, config,
            LinkRequest(destination_url="https://example.com/", expires_in_days=7),
        )
        assert link.expires_at is not None
        assert link.expires_at.endswith("Z")
        assert db.get_link(link.tracking_id).expires_at == link.expires_at

    def test_zero_expiry_means_never(self, db, config):
        link = create_tracking_link(
            db, config,
            LinkRequest(destination_url="https://example.com/", expires_in_days=0),
        )
        assert link.expires_at is None

    @pytest.mark.parametrize("days", [-1, 4000])
    def test_out_of_range_expiry_rejected(self, db, config, days):
        with pytest.raises(LinkCreationError):
            create_tracking_link(
                db, config,
                LinkRequest(destination_url="https://example.com/", expires_in_days=days),
            )

    def test_default_retention_used(self, db, config):
        link = create_tracking_link(
            db, config, LinkRequest(destination_url="https://example.com/")
        )
        assert link.retention_days == config.default_retention_days

    def test_custom_retention_stored(self, db, config):
        link = create_tracking_link(
            db, config,
            LinkRequest(destination_url="https://example.com/", retention_days=14),
        )
        assert link.retention_days == 14

    @pytest.mark.parametrize("days", [0, -5, 5000])
    def test_out_of_range_retention_rejected(self, db, config, days):
        with pytest.raises(LinkCreationError):
            create_tracking_link(
                db, config,
                LinkRequest(destination_url="https://example.com/", retention_days=days),
            )

    def test_consent_flag_stored(self, db, config):
        link = create_tracking_link(
            db, config,
            LinkRequest(destination_url="https://example.com/", require_consent=False),
        )
        assert link.require_consent is False
        assert db.get_link(link.tracking_id).require_consent is False

    def test_label_stored_and_trimmed(self, db, config):
        link = create_tracking_link(
            db, config,
            LinkRequest(destination_url="https://example.com/", label="  a label  "),
        )
        assert link.label == "a label"

    def test_qr_url_points_at_public_endpoint(self, db, config):
        link = create_tracking_link(
            db, config, LinkRequest(destination_url="https://example.com/")
        )
        assert link.qr_url.endswith(f"/l/{link.tracking_id}.png")

    def test_as_dict_roundtrip(self, db, config):
        link = create_tracking_link(
            db, config, LinkRequest(destination_url="https://example.com/")
        )
        as_dict = link.as_dict()
        assert as_dict["tracking_id"] == link.tracking_id
        assert as_dict["share_url"] == link.share_url

    def test_https_required_mode_rejects_http(self, db, config):
        import dataclasses

        strict = dataclasses.replace(config, require_https_links=True)
        with pytest.raises(LinkCreationError):
            create_tracking_link(
                db, strict, LinkRequest(destination_url="http://example.com/")
            )

    def test_https_required_mode_accepts_https(self, db, config):
        import dataclasses

        strict = dataclasses.replace(config, require_https_links=True)
        link = create_tracking_link(
            db, strict, LinkRequest(destination_url="https://example.com/")
        )
        assert link.destination_url.startswith("https://")


class TestLinkStatus:
    def test_active_link(self, db, config):
        link = create_tracking_link(
            db, config, LinkRequest(destination_url="https://example.com/")
        )
        code, label = link_status(db.get_link(link.tracking_id))
        assert code == "active"
        assert label == "Active"

    def test_revoked_link(self, db, config):
        link = create_tracking_link(
            db, config, LinkRequest(destination_url="https://example.com/")
        )
        db.revoke_link(link.tracking_id)
        code, label = link_status(db.get_link(link.tracking_id))
        assert code == "revoked"
        assert label == "Revoked"

    def test_expired_link(self, db, config):
        from database import utc_now_plus

        link = create_tracking_link(
            db, config, LinkRequest(destination_url="https://example.com/")
        )
        db.connection().execute(
            "UPDATE tracking_links SET expires_at = ? WHERE tracking_id = ?",
            (utc_now_plus(-1), link.tracking_id),
        )
        db.connection().commit()
        code, label = link_status(db.get_link(link.tracking_id))
        assert code == "expired"
        assert label == "Expired"

    def test_revoked_takes_precedence_over_expired(self, db, config):
        from database import utc_now_plus

        link = create_tracking_link(
            db, config, LinkRequest(destination_url="https://example.com/")
        )
        db.connection().execute(
            "UPDATE tracking_links SET expires_at = ?, revoked_at = ? WHERE tracking_id = ?",
            (utc_now_plus(-1), utc_now_plus(-1), link.tracking_id),
        )
        db.connection().commit()
        assert link_status(db.get_link(link.tracking_id))[0] == "revoked"
