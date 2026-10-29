"""Analytics tests: user-agent parsing, consent enforcement on the write
path, uniqueness, IP policy and the notice summary."""
from __future__ import annotations

import pytest

from analytics import (
    AnalyticsService,
    UserAgentInfo,
    VisitContext,
    build_notice_summary,
    parse_user_agent,
    referrer_host,
)
from database import utc_now
from geolocation import GeoResolver

CHROME_LINUX = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.6099.109 Safari/537.36"
)
CHROME_WINDOWS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
)
FIREFOX_WINDOWS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0"
)
SAFARI_MAC = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.2 Safari/605.1.15"
)
IPHONE_SAFARI = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
)
IPAD_SAFARI = (
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
)
ANDROID_CHROME = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.6099.144 Mobile Safari/537.36"
)
ANDROID_TABLET = (
    "Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
OPERA = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0"
SAMSUNG = (
    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/118.0.0.0 "
    "Mobile Safari/537.36 SamsungBrowser/23.0"
)


class TestUserAgentParsing:
    @pytest.mark.parametrize(
        "ua,browser,os_family,device",
        [
            (CHROME_LINUX, "Chrome", "Linux", "desktop"),
            (CHROME_WINDOWS, "Edge", "Windows", "desktop"),
            (FIREFOX_WINDOWS, "Firefox", "Windows", "desktop"),
            (SAFARI_MAC, "Safari", "macOS", "desktop"),
            (IPHONE_SAFARI, "Safari", "iOS", "mobile"),
            (IPAD_SAFARI, "Safari", "iOS", "tablet"),
            (ANDROID_CHROME, "Chrome", "Android", "mobile"),
            (ANDROID_TABLET, "Chrome", "Android", "tablet"),
            (OPERA, "Opera", "Windows", "desktop"),
            (SAMSUNG, "Samsung Internet", "Android", "mobile"),
        ],
    )
    def test_classification(self, ua, browser, os_family, device):
        info = parse_user_agent(ua)
        assert info.browser_family == browser
        assert info.os_family == os_family
        assert info.device_category == device

    def test_edge_is_not_reported_as_chrome(self):
        """Edge's UA contains 'Chrome/' so ordering in the rule table matters."""
        assert parse_user_agent(CHROME_WINDOWS).browser_family == "Edge"

    def test_ios_chrome_is_not_reported_as_safari(self):
        ua = (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) "
            "AppleWebKit/605.1.15 CriOS/120.0.6099.119 Mobile/15E148 Safari/604.1"
        )
        assert parse_user_agent(ua).browser_family == "Chrome"

    def test_version_is_major_only(self):
        assert parse_user_agent(CHROME_LINUX).browser_version == "120"

    def test_os_version_is_major_only(self):
        assert parse_user_agent(ANDROID_CHROME).os_version == "14"

    def test_ios_version_dots_from_underscores(self):
        assert parse_user_agent(IPHONE_SAFARI).os_version == "17"

    def test_windows_nt_mapped_to_marketing_version(self):
        assert parse_user_agent(FIREFOX_WINDOWS).os_version == "10/11"

    @pytest.mark.parametrize("ua", [None, "", "garbage-agent-string"])
    def test_unknown_agent_is_labelled_unknown(self, ua):
        info = parse_user_agent(ua)
        assert info.browser_family == "unknown"
        assert info.os_family == "unknown"

    def test_overlong_agent_truncated_without_error(self):
        info = parse_user_agent("A" * 5000)
        assert isinstance(info, UserAgentInfo)

    def test_android_without_mobile_is_tablet(self):
        assert parse_user_agent(ANDROID_TABLET).device_category == "tablet"


class TestReferrerHost:
    @pytest.mark.parametrize(
        "referer,expected",
        [
            ("https://news.example.com/article?id=1", "news.example.com"),
            ("http://EXAMPLE.COM/x", "example.com"),
            ("", ""),
            (None, ""),
            ("not a url", ""),
            ("javascript:alert(1)", ""),
        ],
    )
    def test_host_extraction(self, referer, expected):
        assert referrer_host(referer) == expected

    def test_path_is_not_retained(self):
        assert "/article" not in referrer_host("https://example.com/article")


class TestConsentEnforcement:
    """The most important guarantee in the system: no consent, no storage."""

    def _service(self, config, db):
        return AnalyticsService(config, db, GeoResolver("none"))

    def _link(self, db):
        db.create_link("t1", "https://example.com/")
        return db.get_link("t1")

    def test_no_consent_records_nothing(self, config, db):
        service = self._service(config, db)
        outcome = service.record_visit(
            self._link(db),
            VisitContext(tracking_id="t1", user_agent=CHROME_LINUX,
                         remote_addr="203.0.113.5", consent_granted=False),
        )
        assert outcome.recorded is False
        assert "consent" in outcome.reason.lower()
        assert db.count_events() == 0

    def test_consent_records_event(self, config, db):
        service = self._service(config, db)
        outcome = service.record_visit(
            self._link(db),
            VisitContext(tracking_id="t1", user_agent=CHROME_LINUX,
                         remote_addr="203.0.113.5", consent_granted=True),
        )
        assert outcome.recorded is True
        assert db.count_events() == 1

    def test_declined_visit_leaves_no_row_at_all(self, config, db):
        """A decline must not be logged as a shadow event."""
        service = self._service(config, db)
        link = self._link(db)
        for _ in range(3):
            service.record_visit(
                link,
                VisitContext(tracking_id="t1", user_agent=CHROME_LINUX,
                             consent_granted=False),
            )
        assert db.count_events() == 0

    def test_event_fields_populated(self, config, db):
        service = self._service(config, db)
        service.record_visit(
            self._link(db),
            VisitContext(
                tracking_id="t1", user_agent=ANDROID_CHROME,
                remote_addr="203.0.113.5", referer="https://news.example.com/x",
                consent_granted=True,
            ),
        )
        event = db.list_events()[0]
        assert event.browser_family == "Chrome"
        assert event.os_family == "Android"
        assert event.device_category == "mobile"
        assert event.referrer_host == "news.example.com"
        assert event.consent_status == "granted"
        assert event.created_at.endswith("Z")

    def test_first_visit_is_unique(self, config, db):
        service = self._service(config, db)
        link = self._link(db)
        service.record_visit(
            link,
            VisitContext(tracking_id="t1", remote_addr="203.0.113.5",
                         user_agent=CHROME_LINUX, consent_granted=True),
        )
        assert db.list_events()[0].is_unique is True

    def test_repeat_visit_with_cookie_is_not_unique(self, config, db):
        service = self._service(config, db)
        link = self._link(db)
        for _ in range(2):
            service.record_visit(
                link,
                VisitContext(
                    tracking_id="t1", remote_addr="203.0.113.5",
                    user_agent=CHROME_LINUX, consent_granted=True,
                    visitor_token="stable-cookie-token",
                ),
            )
        events = db.list_events()
        assert sum(1 for e in events if e.is_unique) == 1
        assert len(events) == 2

    def test_different_visitors_both_unique(self, config, db):
        service = self._service(config, db)
        link = self._link(db)
        for token in ("visitor-a", "visitor-b"):
            service.record_visit(
                link,
                VisitContext(tracking_id="t1", user_agent=CHROME_LINUX,
                             visitor_token=token, consent_granted=True),
            )
        assert sum(1 for e in db.list_events() if e.is_unique) == 2

    def test_event_uid_is_unique(self, config, db):
        service = self._service(config, db)
        link = self._link(db)
        for _ in range(5):
            service.record_visit(
                link,
                VisitContext(tracking_id="t1", user_agent=CHROME_LINUX,
                             consent_granted=True),
            )
        uids = [e.event_uid for e in db.list_events()]
        assert len(set(uids)) == 5

    def test_new_events_since_returns_only_newer(self, config, db):
        service = self._service(config, db)
        link = self._link(db)
        service.record_visit(
            link,
            VisitContext(tracking_id="t1", user_agent=CHROME_LINUX, consent_granted=True),
        )
        newest = db.list_events()[0].id
        service.record_visit(
            link,
            VisitContext(tracking_id="t1", user_agent=FIREFOX_WINDOWS, consent_granted=True),
        )
        newer = service.new_events_since(newest)
        assert len(newer) == 1
        assert newer[0].browser_family == "Firefox"

    def test_new_events_since_zero_returns_all(self, config, db):
        service = self._service(config, db)
        link = self._link(db)
        service.record_visit(
            link,
            VisitContext(tracking_id="t1", user_agent=CHROME_LINUX, consent_granted=True),
        )
        assert len(service.new_events_since(0)) == 1


class TestIPPolicy:
    def test_full_mode_stores_ip(self, config, db):
        import dataclasses

        service = AnalyticsService(
            dataclasses.replace(config, ip_storage_mode="full"),
            db,
            GeoResolver("none"),
        )
        db.create_link("t1", "https://example.com/")
        service.record_visit(
            db.get_link("t1"),
            VisitContext(tracking_id="t1", remote_addr="203.0.113.5",
                         user_agent=CHROME_LINUX, consent_granted=True),
        )
        assert db.list_events()[0].ip_address == "203.0.113.5"

    def test_truncated_mode_masks_last_octet(self, config, db):
        import dataclasses

        service = AnalyticsService(
            dataclasses.replace(config, ip_storage_mode="truncated"),
            db,
            GeoResolver("none"),
        )
        db.create_link("t1", "https://example.com/")
        service.record_visit(
            db.get_link("t1"),
            VisitContext(tracking_id="t1", remote_addr="203.0.113.5",
                         user_agent=CHROME_LINUX, consent_granted=True),
        )
        assert db.list_events()[0].ip_address == "203.0.113.0"

    def test_hashed_mode_stores_no_plaintext(self, config, db):
        import dataclasses

        service = AnalyticsService(
            dataclasses.replace(config, ip_storage_mode="hashed", ip_hash_salt="salt"),
            db,
            GeoResolver("none"),
        )
        db.create_link("t1", "https://example.com/")
        service.record_visit(
            db.get_link("t1"),
            VisitContext(tracking_id="t1", remote_addr="203.0.113.5",
                         user_agent=CHROME_LINUX, consent_granted=True),
        )
        event = db.list_events()[0]
        assert event.ip_address == ""
        assert event.ip_hash
        assert "203.0.113.5" not in event.ip_hash

    def test_none_mode_stores_nothing(self, config, db):
        import dataclasses

        service = AnalyticsService(
            dataclasses.replace(config, ip_storage_mode="none"),
            db,
            GeoResolver("none"),
        )
        db.create_link("t1", "https://example.com/")
        service.record_visit(
            db.get_link("t1"),
            VisitContext(tracking_id="t1", remote_addr="203.0.113.5",
                         user_agent=CHROME_LINUX, consent_granted=True),
        )
        event = db.list_events()[0]
        assert event.ip_address == ""
        assert event.ip_hash == ""

    def test_geo_disabled_records_no_location(self, config, db):
        service = AnalyticsService(config, db, GeoResolver("none"))
        db.create_link("t1", "https://example.com/")
        service.record_visit(
            db.get_link("t1"),
            VisitContext(tracking_id="t1", remote_addr="203.0.113.5",
                         user_agent=CHROME_LINUX, consent_granted=True),
        )
        event = db.list_events()[0]
        assert event.country == ""
        assert event.geo_source == "none"


class TestSearch:
    def test_search_returns_events_and_total(self, config, db):
        service = AnalyticsService(config, db, GeoResolver("none"))
        db.create_link("t1", "https://example.com/")
        for _ in range(3):
            service.record_visit(
                db.get_link("t1"),
                VisitContext(tracking_id="t1", user_agent=CHROME_LINUX,
                             consent_granted=True),
            )
        events, total = service.search()
        assert total == 3
        assert len(events) == 3

    def test_search_pagination(self, config, db):
        service = AnalyticsService(config, db, GeoResolver("none"))
        db.create_link("t1", "https://example.com/")
        for _ in range(10):
            service.record_visit(
                db.get_link("t1"),
                VisitContext(tracking_id="t1", user_agent=CHROME_LINUX,
                             consent_granted=True),
            )
        page1, total = service.search(page=1, per_page=5)
        page2, _ = service.search(page=2, per_page=5)
        assert total == 10
        assert len(page1) == 5 and len(page2) == 5
        assert not ({e.id for e in page1} & {e.id for e in page2})
        assert len(page1) + len(page2) == total

    def test_invalid_device_filter_ignored(self, config, db):
        service = AnalyticsService(config, db, GeoResolver("none"))
        db.create_link("t1", "https://example.com/")
        service.record_visit(
            db.get_link("t1"),
            VisitContext(tracking_id="t1", user_agent=CHROME_LINUX, consent_granted=True),
        )
        events, total = service.search(device="'; DROP TABLE--")
        assert total == 1

    def test_invalid_since_filter_ignored(self, config, db):
        service = AnalyticsService(config, db, GeoResolver("none"))
        events, total = service.search(since="not-a-date")
        assert total == 0

    def test_per_page_is_clamped_to_maximum(self, config, db):
        service = AnalyticsService(config, db, GeoResolver("none"))
        events, _ = service.search(per_page=100000)
        assert len(events) <= 200

    def test_per_page_is_clamped_to_minimum(self, config, db):
        """A per_page below 5 is raised to 5 rather than returning nothing."""
        service = AnalyticsService(config, db, GeoResolver("none"))
        db.create_link("t1", "https://example.com/")
        for _ in range(3):
            service.record_visit(
                db.get_link("t1"),
                VisitContext(tracking_id="t1", user_agent=CHROME_LINUX,
                             consent_granted=True),
            )
        events, total = service.search(per_page=1)
        assert total == 3
        assert len(events) == 3


class TestNoticeSummary:
    def test_describes_ip_policy(self, config):
        notice = build_notice_summary(config)
        assert notice["ip_policy"] == "full"
        assert notice["ip_notice"]

    def test_lists_records_collected(self, config):
        notice = build_notice_summary(config)
        assert len(notice["records"]) >= 5

    def test_lists_what_is_never_collected(self, config):
        notice = build_notice_summary(config)
        joined = " ".join(notice["never_collects"]).lower()
        for forbidden in ["password", "contacts", "gps", "camera", "microphone"]:
            assert forbidden in joined

    def test_retention_days_included(self, config):
        assert build_notice_summary(config)["retention_days"] == 90

    def test_policy_version_included(self, config):
        assert build_notice_summary(config)["policy_version"] == "1.0"

    def test_notice_reflects_hashed_mode(self, config):
        import dataclasses

        notice = build_notice_summary(dataclasses.replace(config, ip_storage_mode="hashed"))
        assert "hash" in notice["ip_notice"].lower()

    def test_notice_reflects_geo_disabled(self, config):
        notice = build_notice_summary(config)
        assert "No geographic" in notice["geo_notice"]
