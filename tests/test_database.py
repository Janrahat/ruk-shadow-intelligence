"""Database layer tests: schema, CRUD, SQL-injection resistance, aggregates,
retention and export."""
from __future__ import annotations

import json

import pytest

from database import Database, utc_now, utc_now_plus


class TestSchema:
    def test_schema_version_recorded(self, db):
        assert db.schema_version() == 1

    def test_all_tables_exist(self, db):
        names = {
            row[0]
            for row in db.connection().execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        for table in (
            "administrators", "campaigns", "tracking_links",
            "consent_records", "analytics_events", "audit_log", "schema_meta",
        ):
            assert table in names, f"missing table {table}"

    def test_integrity_check_passes(self, db):
        assert db.integrity_check() == "ok"

    def test_bootstrap_is_idempotent(self):
        database = Database(":memory:")
        database._bootstrap()
        database._bootstrap()
        assert database.schema_version() == 1
        database.close()

    def test_events_table_has_no_tracking_columns(self, db):
        """A guard against scope creep: no hidden identifiers may be added."""
        columns = {
            row[1]
            for row in db.connection().execute("PRAGMA table_info(analytics_events)")
        }
        forbidden = {
            "device_id", "imei", "mac_address", "phone_number", "gps_lat",
            "gps_lng", "latitude", "longitude", "precise_lat", "precise_lng",
            "contacts", "cookies", "session_cookie", "password",
        }
        assert not (columns & forbidden), f"forbidden columns present: {columns & forbidden}"


class TestAdministrators:
    def test_create_and_fetch(self, db):
        db.create_admin("alice", "$argon2id$hash", "admin")
        found = db.get_admin("alice")
        assert found is not None
        assert found.username == "alice"
        assert found.role == "admin"
        assert found.is_active is True

    def test_duplicate_username_rejected(self, db):
        db.create_admin("alice", "hash1")
        with pytest.raises(Exception):
            db.create_admin("alice", "hash2")

    def test_missing_user_returns_none(self, db):
        assert db.get_admin("nobody") is None

    def test_admin_exists_flag(self, db):
        assert db.admin_exists() is False
        db.create_admin("alice", "hash")
        assert db.admin_exists() is True

    def test_login_failure_counter_increments(self, db):
        db.create_admin("alice", "hash")
        db.record_login_failure("alice")
        db.record_login_failure("alice")
        assert db.get_admin("alice").failed_attempts == 2

    def test_login_success_resets_counter(self, db):
        db.create_admin("alice", "hash")
        db.record_login_failure("alice")
        db.record_login_success(1)
        admin = db.get_admin("alice")
        assert admin.failed_attempts == 0
        assert admin.last_login_at is not None

    def test_unknown_user_failure_does_not_crash(self, db):
        db.record_login_failure("ghost")

    def test_role_constraint_enforced(self, db):
        with pytest.raises(Exception):
            db.create_admin("bob", "hash", "superuser")

    def test_deactivate_admin(self, db):
        admin_id = db.create_admin("alice", "hash")
        db.set_admin_active(admin_id, False)
        assert db.get_admin("alice").is_active is False

    def test_password_update(self, db):
        admin_id = db.create_admin("alice", "old-hash")
        db.update_admin_password(admin_id, "new-hash")
        assert db.get_admin("alice").password_hash == "new-hash"


class TestCampaigns:
    def test_create_and_fetch(self, db):
        campaign_id = db.create_campaign("Launch", "launch", "desc")
        campaign = db.get_campaign(campaign_id)
        assert campaign.name == "Launch"
        assert campaign.slug == "launch"
        assert campaign.link_count == 0

    def test_slug_is_unique(self, db):
        db.create_campaign("A", "shared")
        with pytest.raises(Exception):
            db.create_campaign("B", "shared")

    def test_list_excludes_archived_by_default(self, db):
        live = db.create_campaign("Live", "live")
        archived = db.create_campaign("Old", "old")
        db.archive_campaign(archived)
        assert [c.id for c in db.list_campaigns()] == [live]
        assert len(db.list_campaigns(include_archived=True)) == 2

    def test_link_and_event_counts_are_independent(self, db):
        campaign_id = db.create_campaign("C", "c")
        db.create_link("t1", "https://example.com/", campaign_id=campaign_id)
        db.create_link("t2", "https://example.com/", campaign_id=campaign_id)
        campaign = db.get_campaign(campaign_id)
        assert campaign.link_count == 2
        assert campaign.total_events == 0


class TestTrackingLinks:
    def test_create_and_fetch(self, db):
        db.create_link("abc123", "https://example.com/x", label="lbl", retention_days=30)
        link = db.get_link("abc123")
        assert link.destination_url == "https://example.com/x"
        assert link.label == "lbl"
        assert link.retention_days == 30
        assert link.require_consent is True
        assert link.revoked_at is None

    def test_missing_link_returns_none(self, db):
        assert db.get_link("nope") is None

    def test_tracking_id_unique(self, db):
        db.create_link("dup", "https://example.com/")
        with pytest.raises(Exception):
            db.create_link("dup", "https://example.com/")

    def test_revoke_sets_timestamp(self, db):
        db.create_link("abc", "https://example.com/")
        assert db.revoke_link("abc") is True
        link = db.get_link("abc")
        assert link.revoked_at is not None
        assert link.is_revoked is True

    def test_revoke_is_idempotent(self, db):
        db.create_link("abc", "https://example.com/")
        assert db.revoke_link("abc") is True
        assert db.revoke_link("abc") is False

    def test_restore_clears_revocation(self, db):
        db.create_link("abc", "https://example.com/")
        db.revoke_link("abc")
        assert db.restore_link("abc") is True
        assert db.get_link("abc").is_revoked is False

    def test_expired_link_detected(self, db):
        past = utc_now_plus(-1)
        db.create_link("old", "https://example.com/", expires_at=past)
        assert db.get_link("old").is_expired(utc_now()) is True

    def test_unexpired_link_not_expired(self, db):
        future = utc_now_plus(5)
        db.create_link("new", "https://example.com/", expires_at=future)
        assert db.get_link("new").is_expired(utc_now()) is False

    def test_link_without_expiry_never_expires(self, db):
        db.create_link("forever", "https://example.com/")
        assert db.get_link("forever").is_expired(utc_now()) is False

    def test_delete_cascades_to_events_and_consent(self, db):
        db.create_link("gone", "https://example.com/")
        db.record_consent("gone", "visitor1", True, "1.0")
        db.insert_event(_event(tracking_id="gone"))
        assert db.count_events() == 1
        assert db.delete_link("gone") is True
        assert db.get_link("gone") is None
        assert db.count_events() == 0
        assert db.list_consent() == []

    def test_click_count_reflects_events(self, db):
        db.create_link("counted", "https://example.com/")
        for _ in range(3):
            db.insert_event(_event(tracking_id="counted"))
        assert db.get_link("counted").click_count == 3


class TestConsent:
    def test_record_and_read(self, db):
        db.record_consent("t1", "v1", True, "1.0", notice_sha256="abc")
        record = db.latest_consent("v1", "t1")
        assert record.granted is True
        assert record.policy_version == "1.0"
        assert record.notice_sha256 == "abc"

    def test_has_valid_consent_true(self, db):
        db.record_consent("t1", "v1", True, "1.0")
        assert db.has_valid_consent("v1", "t1", "1.0") is True

    def test_has_valid_consent_false_when_declined(self, db):
        db.record_consent("t1", "v1", False, "1.0")
        assert db.has_valid_consent("v1", "t1", "1.0") is False

    def test_has_valid_consent_false_after_policy_change(self, db):
        db.record_consent("t1", "v1", True, "1.0")
        assert db.has_valid_consent("v1", "t1", "2.0") is False

    def test_has_valid_consent_false_when_none(self, db):
        assert db.has_valid_consent("nobody", "t1", "1.0") is False

    def test_withdraw_deletes_events(self, db):
        db.create_link("t1", "https://example.com/")
        db.record_consent("t1", "v1", True, "1.0")
        db.insert_event(_event(tracking_id="t1", visitor_token="v1"))
        db.insert_event(_event(tracking_id="t1", visitor_token="v1"))
        removed = db.withdraw_consent("v1", "t1")
        assert removed == 2
        assert db.count_events() == 0

    def test_withdraw_marks_record(self, db):
        db.record_consent("t1", "v1", True, "1.0")
        db.withdraw_consent("v1", "t1")
        assert db.latest_consent("v1", "t1").withdrawn_at is not None

    def test_consent_stats(self, db):
        db.record_consent("t", "v1", True, "1.0")
        db.record_consent("t", "v2", True, "1.0")
        db.record_consent("t", "v3", False, "1.0")
        stats = db.consent_stats()
        assert stats == {"granted": 2, "declined": 1}


class TestEvents:
    def test_insert_and_read_back(self, db):
        db.insert_event(_event(tracking_id="t1", country="NL"))
        events = db.list_events()
        assert len(events) == 1
        assert events[0].country == "NL"

    def test_ordering_desc_by_default(self, db):
        for index in range(3):
            db.insert_event(_event(tracking_id=f"t{index}"))
        events = db.list_events()
        assert [e.tracking_id for e in events] == ["t2", "t1", "t0"]

    def test_ordering_asc(self, db):
        for index in range(3):
            db.insert_event(_event(tracking_id=f"t{index}"))
        events = db.list_events(order="asc")
        assert [e.tracking_id for e in events] == ["t0", "t1", "t2"]

    def test_filter_by_tracking_id(self, db):
        db.insert_event(_event(tracking_id="a"))
        db.insert_event(_event(tracking_id="b"))
        assert len(db.list_events(tracking_id="a")) == 1

    def test_filter_by_device(self, db):
        db.insert_event(_event(tracking_id="a", device_category="mobile"))
        db.insert_event(_event(tracking_id="b", device_category="desktop"))
        assert len(db.list_events(device="mobile")) == 1

    def test_filter_after_id(self, db):
        first = db.insert_event(_event(tracking_id="a"))
        db.insert_event(_event(tracking_id="b"))
        newer = db.list_events(after_id=first)
        assert len(newer) == 1 and newer[0].tracking_id == "b"

    def test_pagination(self, db):
        for index in range(10):
            db.insert_event(_event(tracking_id=f"t{index}"))
        page1 = db.list_events(limit=4, offset=0)
        page2 = db.list_events(limit=4, offset=4)
        assert len(page1) == 4 and len(page2) == 4
        assert not ({e.id for e in page1} & {e.id for e in page2})

    def test_search_matches_country(self, db):
        db.insert_event(_event(tracking_id="a", country="Netherlands"))
        db.insert_event(_event(tracking_id="b", country="Germany"))
        assert len(db.list_events(search="Nether")) == 1

    def test_search_wildcard_is_literal(self, db):
        """A '%' in the query must not match everything."""
        db.insert_event(_event(tracking_id="alpha", country="X"))
        assert db.list_events(search="%") == []

    def test_count_matches_list(self, db):
        for _ in range(5):
            db.insert_event(_event(tracking_id="t"))
        assert db.count_events() == 5

    def test_unknown_visitor_count_zero(self, db):
        assert db.visitor_event_count("nobody", "nothing") == 0


class TestSQLInjection:
    """Every value is a bound parameter, so these must be treated as data."""

    PAYLOADS = [
        "'; DROP TABLE analytics_events; --",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "'; DELETE FROM tracking_links WHERE 1=1; --",
        "1' UNION SELECT password_hash FROM administrators --",
    ]

    @pytest.mark.parametrize("payload", PAYLOADS)
    def test_tracking_id_payload_is_inert(self, db, payload):
        db.create_link(payload[:64], "https://example.com/")
        assert db.get_link(payload[:64]) is not None
        assert db.integrity_check() == "ok"

    @pytest.mark.parametrize("payload", PAYLOADS)
    def test_search_payload_is_inert(self, db, payload):
        db.insert_event(_event(tracking_id="safe", country="NL"))
        db.list_events(search=payload)
        assert db.count_events() == 1
        assert db.integrity_check() == "ok"

    @pytest.mark.parametrize("payload", PAYLOADS)
    def test_campaign_name_payload_is_inert(self, db, payload):
        db.create_campaign(payload[:80], f"slug-{abs(hash(payload)) % 10000}")
        assert db.integrity_check() == "ok"
        assert db.list_campaigns()

    def test_administrator_table_survives_payloads(self, db):
        db.create_admin("victim", "hash")
        db.list_events(search="1' UNION SELECT password_hash FROM administrators --")
        assert db.get_admin("victim") is not None

    def test_breakdown_column_is_allow_listed(self, db):
        with pytest.raises(ValueError):
            db.breakdown("id; DROP TABLE analytics_events")
        assert db.integrity_check() == "ok"


class TestAggregates:
    def test_totals_on_empty_database(self, db):
        totals = db.dashboard_totals()
        assert totals.total_events == 0
        assert totals.consent_rate == 0.0

    def test_totals_count_events(self, db):
        db.create_link("t", "https://example.com/")
        db.insert_event(_event(tracking_id="t", is_unique=True))
        db.insert_event(_event(tracking_id="t", is_unique=False))
        totals = db.dashboard_totals()
        assert totals.total_events == 2
        assert totals.unique_events == 1
        assert totals.active_links == 1

    def test_consent_rate_calculation(self, db):
        db.record_consent("t", "v1", True, "1.0")
        db.record_consent("t", "v2", True, "1.0")
        db.record_consent("t", "v3", False, "1.0")
        db.record_consent("t", "v4", False, "1.0")
        assert db.dashboard_totals().consent_rate == 50.0

    def test_breakdown_shares_sum_to_100(self, db):
        for index in range(4):
            db.insert_event(_event(tracking_id="t", device_category="mobile"))
            db.insert_event(_event(tracking_id="t", device_category="desktop"))
        rows = db.breakdown("device_category")
        assert sum(r.count for r in rows) == 8
        assert abs(sum(r.share for r in rows) - 100.0) < 0.2

    def test_breakdown_empty_label_becomes_unknown(self, db):
        db.insert_event(_event(tracking_id="t", country=""))
        assert db.breakdown("country")[0].label == "unknown"

    def test_traffic_series_has_24_buckets(self, db):
        series = db.traffic_series(hours=24)
        assert len(series) == 25  # inclusive endpoints
        assert all(isinstance(label, str) for label, _ in series)

    def test_traffic_series_counts_today(self, db):
        db.insert_event(_event(tracking_id="t"))
        series = db.traffic_series(hours=24)
        assert sum(count for _, count in series) >= 1

    def test_campaign_performance_lists_campaign(self, db):
        db.create_campaign("Perf", "perf")
        rows = db.campaign_performance()
        assert any(row["name"] == "Perf" for row in rows)


class TestExport:
    def test_csv_has_header_and_rows(self, db):
        db.insert_event(_event(tracking_id="t"))
        text = db.export_events(fmt="csv")
        lines = [line for line in text.strip().splitlines() if line]
        assert len(lines) == 2
        assert "event_uid" in lines[0]

    def test_csv_with_no_events_is_header_only(self, db):
        text = db.export_events(fmt="csv")
        assert len([line for line in text.strip().splitlines() if line]) == 1

    def test_json_is_valid_and_counts(self, db):
        db.insert_event(_event(tracking_id="a"))
        db.insert_event(_event(tracking_id="b"))
        payload = json.loads(db.export_events(fmt="json"))
        assert payload["record_count"] == 2
        assert len(payload["events"]) == 2
        assert "generated_at" in payload

    def test_export_excludes_internal_columns(self, db):
        db.insert_event(_event(tracking_id="t", ip_hash="secret-hash"))
        payload = json.loads(db.export_events(fmt="json"))
        row = payload["events"][0]
        assert "visitor_token" not in row


class TestRetention:
    def test_purge_removes_events_for_expired_links(self, db):
        db.create_link("old", "https://example.com/", expires_at=utc_now_plus(-1))
        db.insert_event(_event(tracking_id="old"))
        db.insert_event(_event(tracking_id="keep"))
        removed = db.purge_expired(90)
        assert removed["expired_link_events"] == 1
        assert db.count_events() == 1

    def test_purge_removes_aged_events(self, db):
        db.create_link("t", "https://example.com/", retention_days=30)
        db.insert_event(_event(tracking_id="t", created_at=utc_now_plus(-100)))
        db.insert_event(_event(tracking_id="t"))
        removed = db.purge_expired(90)
        assert removed["aged_events"] == 1
        assert db.count_events() == 1

    def test_delete_all_events(self, db):
        for _ in range(3):
            db.insert_event(_event(tracking_id="t"))
        assert db.delete_all_events() == 3
        assert db.count_events() == 0

    def test_delete_events_for_one_link_only(self, db):
        db.insert_event(_event(tracking_id="a"))
        db.insert_event(_event(tracking_id="b"))
        assert db.delete_all_events("a") == 1
        assert db.count_events() == 1

    def test_erase_visitor_deletes_and_withdraws(self, db):
        db.record_consent("t", "v1", True, "1.0")
        db.insert_event(_event(tracking_id="t", visitor_token="v1"))
        db.insert_event(_event(tracking_id="t", visitor_token="v2"))
        assert db.delete_events_for_visitor("v1") == 1
        assert db.count_events() == 1
        assert db.latest_consent("v1", "t").withdrawn_at is not None


class TestAudit:
    def test_log_and_list(self, db):
        db.log_audit("alice", "login_success", "detail", "203.0.113.1")
        entries = db.list_audit()
        assert entries[0].actor == "alice"
        assert entries[0].action == "login_success"

    def test_newest_first(self, db):
        db.log_audit("a", "first")
        db.log_audit("b", "second")
        assert db.list_audit()[0].action == "second"


class TestDiagnostics:
    def test_table_counts_cover_all_tables(self, db):
        counts = db.table_counts()
        assert set(counts) == {
            "administrators", "campaigns", "tracking_links",
            "consent_records", "analytics_events", "audit_log",
        }

    def test_counts_are_accurate(self, db):
        db.create_admin("a", "h")
        db.create_campaign("C", "c")
        db.create_link("t", "https://example.com/")
        counts = db.table_counts()
        assert counts["administrators"] == 1
        assert counts["campaigns"] == 1
        assert counts["tracking_links"] == 1


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
def _event(**overrides) -> dict:
    import uuid

    base = {
        "event_uid": overrides.pop("event_uid", uuid.uuid4().hex),
        "tracking_id": "t",
        "campaign_id": None,
        "created_at": utc_now(),
        "consent_status": "granted",
        "visitor_token": "",
        "ip_address": "",
        "ip_hash": "",
        "country": "",
        "region": "",
        "city": "",
        "geo_source": "none",
        "browser_family": "Chrome",
        "browser_version": "120",
        "os_family": "Linux",
        "os_version": "6",
        "device_category": "desktop",
        "referrer_host": "",
        "is_unique": True,
    }
    base.update(overrides)
    return base
