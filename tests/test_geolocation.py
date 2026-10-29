"""Geolocation resolver tests.

These verify the honesty contract: a disabled or failed lookup must report
``available=False`` rather than returning an empty location that looks real.
"""
from __future__ import annotations

import pytest

from geolocation import GeoResolver, GeoResult, describe_limitation


class TestDisabledProvider:
    def test_default_is_disabled(self):
        resolver = GeoResolver()
        assert resolver.provider == "none"
        assert resolver.is_available is False

    def test_lookup_returns_unavailable(self):
        result = GeoResolver("none").lookup("203.0.113.5")
        assert result.available is False
        assert result.country == ""
        assert result.source == "none"

    def test_status_string_is_explicit(self):
        status = GeoResolver("none").status
        assert "disabled" in status.lower()

    def test_event_fields_are_empty_strings(self):
        fields = GeoResolver("none").lookup("203.0.113.5").as_event_fields()
        assert fields == {
            "country": "", "region": "", "city": "", "geo_source": "none"
        }


# A genuinely public address. TEST-NET ranges (203.0.113.0/24 etc.) are
# classified as private by ipaddress, so they cannot be used to test lookups
# that are supposed to reach a provider.
PUBLIC_IP = "8.8.8.8"


class TestUnknownProvider:
    def test_unknown_provider_falls_back_to_none(self):
        resolver = GeoResolver("made-up-provider")
        assert resolver.provider == "none"

    def test_unknown_provider_reports_the_problem(self):
        """A typo must be reported, not silently passed off as 'disabled'."""
        status = GeoResolver("made-up-provider").status.lower()
        assert "unknown" in status
        assert "unavailable" in status


class TestMaxmindProvider:
    def test_missing_database_reports_error(self):
        resolver = GeoResolver("maxmind", db_path="/nonexistent/path.mmdb")
        assert resolver.is_available is False
        assert "could not open" in resolver.status.lower() or "geoip2" in resolver.status.lower()

    def test_lookup_with_missing_database_is_unavailable(self):
        resolver = GeoResolver("maxmind", db_path="/nonexistent/path.mmdb")
        result = resolver.lookup("203.0.113.5")
        assert result.available is False
        assert result.error

    def test_status_is_not_silently_positive(self):
        resolver = GeoResolver("maxmind", db_path="/nonexistent/path.mmdb")
        assert "unavailable" in resolver.status.lower()


class TestHttpProvider:
    def test_missing_endpoint_reports_error(self):
        resolver = GeoResolver("http", http_endpoint="")
        result = resolver.lookup(PUBLIC_IP)
        assert result.available is False
        assert "endpoint" in result.error.lower()

    def test_status_warns_about_empty_endpoint(self):
        status = GeoResolver("http", http_endpoint="").status.lower()
        assert "unavailable" in status
        assert "endpoint" in status

    def test_status_warns_ip_leaves_host(self):
        resolver = GeoResolver("http", http_endpoint="https://example.com/{ip}")
        assert "leaves this host" in resolver.status

    def test_rejected_endpoint_scheme(self):
        resolver = GeoResolver("http", http_endpoint="file:///etc/passwd")
        result = resolver.lookup(PUBLIC_IP)
        assert result.available is False
        assert "http" in result.error.lower()

    def test_unreachable_endpoint_returns_error_not_fake_data(self):
        resolver = GeoResolver(
            "http", http_endpoint="https://127.0.0.1:9/{ip}", timeout=0.4
        )
        result = resolver.lookup(PUBLIC_IP)
        assert result.available is False
        assert result.error


class TestPrivateAddresses:
    @pytest.mark.parametrize(
        "ip",
        ["127.0.0.1", "10.0.0.1", "192.168.1.5", "172.16.0.1", "::1", "169.254.1.1"],
    )
    def test_private_addresses_never_looked_up(self, ip):
        resolver = GeoResolver("http", http_endpoint="https://example.com/{ip}")
        result = resolver.lookup(ip)
        assert result.available is False
        assert "private" in (result.error or "").lower()

    def test_invalid_ip_is_unavailable(self):
        resolver = GeoResolver("http", http_endpoint="https://example.com/{ip}")
        assert resolver.lookup("not-an-ip").available is False

    def test_empty_ip_is_unavailable(self):
        resolver = GeoResolver("http", http_endpoint="https://example.com/{ip}")
        assert resolver.lookup("").available is False

    def test_documentation_ranges_are_not_looked_up(self):
        """203.0.113.0/24 is reserved for documentation and is not routable."""
        resolver = GeoResolver("http", http_endpoint="https://example.com/{ip}")
        assert resolver.lookup("203.0.113.5").available is False


class TestCaching:
    def test_disabled_provider_does_not_cache_into_success(self):
        resolver = GeoResolver("none")
        resolver.lookup("203.0.113.5")
        assert resolver.lookup("203.0.113.5").available is False

    def test_close_is_safe_to_call_twice(self):
        resolver = GeoResolver("none")
        resolver.close()
        resolver.close()


class TestLimitationText:
    def test_text_mentions_approximation(self):
        text = describe_limitation()
        assert "approximate" in text.lower()

    def test_text_denies_precise_position(self):
        text = describe_limitation().lower()
        assert "precise" in text
        assert "person" in text

    def test_text_does_not_claim_identification(self):
        assert "identify" in describe_limitation().lower()


class TestGeoResult:
    def test_defaults_are_unavailable(self):
        result = GeoResult()
        assert result.available is False
        assert result.country == ""

    def test_fields_are_truncated(self):
        result = GeoResult(country="X" * 200, region="Y" * 200, city="Z" * 200)
        fields = result.as_event_fields()
        assert len(fields["country"]) <= 64
        assert len(fields["region"]) <= 96
        assert len(fields["city"]) <= 96
