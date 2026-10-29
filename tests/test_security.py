"""Tests for security primitives: hashing, tokens, CSRF, rate limiting,
password policy, IP handling, URL validation and output sanitisation."""
from __future__ import annotations

import re
import time

import pytest

from security import (
    DestinationValidationError,
    RateLimiter,
    WeakPasswordError,
    apply_ip_policy,
    apply_security_headers,
    client_ip,
    ensure_csrf_token,
    generate_tracking_id,
    generate_visitor_token,
    hash_ip,
    hash_password,
    normalize_ip,
    safe_redirect_target,
    sanitize_campaign_name,
    sanitize_single_line,
    sanitize_text,
    truncate_ip,
    validate_alias,
    validate_destination_url,
    validate_password_strength,
    verify_csrf_token,
    verify_password,
)


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
class TestPasswordHashing:
    def test_hash_is_not_the_password(self):
        record = hash_password("a-very-long-password-here")
        assert "a-very-long-password-here" not in record
        assert record.startswith("$argon2") or record.startswith("pbkdf2:")

    def test_verify_accepts_correct_password(self):
        record = hash_password("a-very-long-password-here")
        assert verify_password(record, "a-very-long-password-here") is True

    def test_verify_rejects_wrong_password(self):
        record = hash_password("a-very-long-password-here")
        assert verify_password(record, "a-very-long-password-ther") is False

    def test_same_password_produces_different_hashes(self):
        first = hash_password("a-very-long-password-here")
        second = hash_password("a-very-long-password-here")
        assert first != second, "salt is not being used"

    def test_verify_tolerates_garbage_hash(self):
        assert verify_password("not-a-real-hash", "anything") is False

    @pytest.mark.parametrize(
        "weak",
        ["", "short", "password", "12345678", "qwertyuiop", "aaaaaaaaaaaa"],
    )
    def test_weak_passwords_rejected(self, weak):
        with pytest.raises(WeakPasswordError):
            validate_password_strength(weak)

    def test_strong_password_accepted(self):
        validate_password_strength("correct horse battery staple")


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------
class TestTokens:
    def test_tracking_id_is_url_safe(self):
        token = generate_tracking_id()
        assert re.fullmatch(r"[A-Za-z0-9_-]+", token), token

    def test_tracking_id_has_enough_entropy(self):
        assert len(generate_tracking_id()) >= 12

    def test_tracking_ids_are_unique(self):
        tokens = {generate_tracking_id() for _ in range(500)}
        assert len(tokens) == 500

    def test_visitor_token_is_distinct_from_tracking_id(self):
        assert generate_visitor_token() != generate_tracking_id()

    def test_tokens_do_not_repeat_across_calls(self):
        tokens = {generate_visitor_token() for _ in range(500)}
        assert len(tokens) == 500


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------
class TestCSRF:
    def test_token_is_stable_within_session(self):
        session = {}
        first = ensure_csrf_token(session)
        second = ensure_csrf_token(session)
        assert first == second

    def test_valid_token_verifies(self):
        session = {}
        token = ensure_csrf_token(session)
        assert verify_csrf_token(session, token) is True

    def test_wrong_token_fails(self):
        session = {}
        ensure_csrf_token(session)
        assert verify_csrf_token(session, "wrong-token") is False

    def test_missing_token_fails(self):
        session = {}
        ensure_csrf_token(session)
        assert verify_csrf_token(session, None) is False
        assert verify_csrf_token(session, "") is False

    def test_absent_session_token_fails(self):
        assert verify_csrf_token({}, "anything") is False


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
class TestRateLimiter:
    def test_allows_up_to_limit(self):
        limiter = RateLimiter(limit=3, window_seconds=60)
        assert [limiter.allow("k") for _ in range(3)] == [True, True, True]

    def test_blocks_beyond_limit(self):
        limiter = RateLimiter(limit=3, window_seconds=60)
        for _ in range(3):
            limiter.allow("k")
        assert limiter.allow("k") is False

    def test_keys_are_independent(self):
        limiter = RateLimiter(limit=1, window_seconds=60)
        assert limiter.allow("a") is True
        assert limiter.allow("b") is True
        assert limiter.allow("a") is False

    def test_window_expiry_restores_allowance(self):
        # Drive the clock explicitly instead of sleeping, so the test is fast
        # and deterministic.
        limiter = RateLimiter(limit=1, window_seconds=10)
        assert limiter.allow("k", now=1000.0) is True
        assert limiter.allow("k", now=1000.0) is False
        assert limiter.allow("k", now=1011.0) is True

    def test_retry_after_is_positive(self):
        limiter = RateLimiter(limit=1, window_seconds=60)
        limiter.allow("k", now=1000.0)
        limiter.allow("k", now=1000.0)
        assert limiter.retry_after("k", now=1000.0) > 0

    def test_retry_after_zero_for_unknown_key(self):
        limiter = RateLimiter(limit=1, window_seconds=60)
        assert limiter.retry_after("never-seen") == 0

    def test_remaining_counts_down(self):
        limiter = RateLimiter(limit=3, window_seconds=60)
        assert limiter.remaining("k") == 3
        limiter.allow("k")
        assert limiter.remaining("k") == 2

    def test_reset_clears_state(self):
        limiter = RateLimiter(limit=1, window_seconds=60)
        limiter.allow("k")
        limiter.allow("k")
        limiter.reset()
        assert limiter.allow("k") is True


# ---------------------------------------------------------------------------
# IP handling
# ---------------------------------------------------------------------------
class TestIPHandling:
    def test_normalize_accepts_valid_v4(self):
        assert normalize_ip("203.0.113.7") == "203.0.113.7"

    def test_normalize_rejects_garbage(self):
        for value in ["not-an-ip", "999.1.1.1", "", "<script>"]:
            assert normalize_ip(value) == ""

    def test_truncate_masks_last_octet(self):
        assert truncate_ip("203.0.113.7") == "203.0.113.0"

    def test_truncate_ipv6_masks_second_half(self):
        result = truncate_ip("2001:db8:1234:5678:9abc:def0:1234:5678")
        assert result.endswith("::") or result.count(":") < 8

    def test_hash_is_deterministic_with_salt(self):
        first = hash_ip("203.0.113.7", "salt")
        second = hash_ip("203.0.113.7", "salt")
        assert first == second

    def test_hash_changes_with_salt(self):
        assert hash_ip("203.0.113.7", "a") != hash_ip("203.0.113.7", "b")

    def test_hash_does_not_contain_the_ip(self):
        assert "203.0.113.7" not in hash_ip("203.0.113.7", "salt")

    @pytest.mark.parametrize(
        "mode,expect_ip,expect_hash",
        [("full", True, False), ("truncated", True, False),
         ("hashed", False, True), ("none", False, False)],
    )
    def test_storage_policies(self, mode, expect_ip, expect_hash):
        stored, hashed = apply_ip_policy("203.0.113.7", mode, "salt")
        assert bool(stored) is expect_ip
        assert bool(hashed) is expect_hash

    def test_none_mode_stores_nothing(self):
        assert apply_ip_policy("203.0.113.7", "none", "salt") == ("", "")

    def test_client_ip_ignores_forwarded_header_when_untrusted(self):
        result = client_ip("198.51.100.1", "203.0.113.9", trust_proxy=False)
        assert result == "198.51.100.1"

    def test_client_ip_uses_forwarded_when_trusted(self):
        result = client_ip("127.0.0.1", "203.0.113.9", trust_proxy=True)
        assert result == "203.0.113.9"

    def test_client_ip_takes_leftmost_forwarded_entry(self):
        result = client_ip("127.0.0.1", "203.0.113.9, 10.0.0.1", trust_proxy=True)
        assert result == "203.0.113.9"

    def test_client_ip_rejects_spoofed_garbage(self):
        result = client_ip("198.51.100.1", "evil<script>", trust_proxy=True)
        assert result == "198.51.100.1"

    def test_client_ip_returns_empty_when_nothing_valid(self):
        assert client_ip(None, None, trust_proxy=False) == ""
        assert client_ip("garbage", None, trust_proxy=False) == ""


# ---------------------------------------------------------------------------
# Destination URL validation (SSRF)
# ---------------------------------------------------------------------------
class TestDestinationValidation:
    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com/page",
            "https://sub.example.co.uk/a/b?c=d",
            "http://example.com/",
        ],
    )
    def test_public_urls_accepted(self, url):
        assert validate_destination_url(url, resolve_dns=False).startswith("http")

    @pytest.mark.parametrize(
        "url",
        [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "file:///etc/passwd",
            "ftp://example.com/x",
            "gopher://example.com/x",
            "vbscript:msgbox(1)",
        ],
    )
    def test_non_http_schemes_rejected(self, url):
        with pytest.raises(DestinationValidationError):
            validate_destination_url(url, resolve_dns=False)

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1/admin",
            "http://localhost/x",
            "http://10.0.0.5/",
            "http://192.168.1.1/",
            "http://172.16.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/",
            "http://0.0.0.0/",
        ],
    )
    def test_private_and_metadata_addresses_rejected(self, url):
        with pytest.raises(DestinationValidationError):
            validate_destination_url(url, resolve_dns=False)

    def test_credentials_in_url_rejected(self):
        with pytest.raises(DestinationValidationError):
            validate_destination_url("https://user:pass@example.com/", resolve_dns=False)

    def test_missing_scheme_rejected(self):
        with pytest.raises(DestinationValidationError):
            validate_destination_url("example.com/x", resolve_dns=False)

    def test_empty_url_rejected(self):
        with pytest.raises(DestinationValidationError):
            validate_destination_url("", resolve_dns=False)

    def test_whitespace_in_hostname_rejected(self):
        with pytest.raises(DestinationValidationError):
            validate_destination_url("https://exa mple.com/", resolve_dns=False)

    def test_require_https_flag_rejects_plain_http(self):
        with pytest.raises(DestinationValidationError):
            validate_destination_url(
                "http://example.com/", require_https=True, resolve_dns=False
            )

    def test_require_https_accepts_https(self):
        assert validate_destination_url(
            "https://example.com/", require_https=True, resolve_dns=False
        ).startswith("https://")

    def test_header_injection_attempt_rejected(self):
        # A CR/LF in the URL is a header-splitting attempt, so it is refused
        # outright rather than silently stripped.
        with pytest.raises(DestinationValidationError):
            validate_destination_url(
                "https://example.com/a\r\nInjected: header", resolve_dns=False
            )

    def test_surrounding_whitespace_trimmed(self):
        result = validate_destination_url(
            "  https://example.com/x  ", resolve_dns=False
        )
        assert result == "https://example.com/x"

    def test_overlong_url_rejected(self):
        with pytest.raises(DestinationValidationError):
            validate_destination_url(
                "https://example.com/" + "a" * 5000, resolve_dns=False
            )


# ---------------------------------------------------------------------------
# Alias validation
# ---------------------------------------------------------------------------
class TestAliasValidation:
    @pytest.mark.parametrize("alias", ["promo", "autumn-2026", "a1b2c3", "x" * 32])
    def test_valid_aliases(self, alias):
        ok, _ = validate_alias(alias)
        assert ok, f"{alias!r} should be valid"

    @pytest.mark.parametrize(
        "alias",
        ["", "Promo", "has space", "has_underscore", "-leading", "trailing-",
         "a" * 40, "<script>", "../etc"],
    )
    def test_invalid_aliases(self, alias):
        ok, reason = validate_alias(alias)
        assert not ok
        assert reason


# ---------------------------------------------------------------------------
# Sanitisation
# ---------------------------------------------------------------------------
class TestSanitisation:
    def test_single_line_strips_newlines(self):
        assert "\n" not in sanitize_single_line("a\nb")

    def test_single_line_strips_control_chars(self):
        assert sanitize_single_line("a\x00b\x07c") == "abc"

    def test_single_line_respects_max_length(self):
        assert len(sanitize_single_line("x" * 500, max_length=20)) == 20

    def test_text_keeps_newlines(self):
        assert "\n" in sanitize_text("line one\nline two")

    def test_text_strips_control_chars(self):
        assert "\x00" not in sanitize_text("a\x00b")

    def test_campaign_name_collapses_whitespace(self):
        assert sanitize_campaign_name("  too   many   spaces  ") == "too many spaces"

    def test_campaign_name_strips_control_chars(self):
        assert "\x00" not in sanitize_campaign_name("name\x00")

    def test_campaign_name_has_length_limit(self):
        assert len(sanitize_campaign_name("x" * 500)) <= 80

    def test_none_becomes_empty_string(self):
        assert sanitize_single_line(None) == ""
        assert sanitize_text(None) == ""


# ---------------------------------------------------------------------------
# Redirect safety
# ---------------------------------------------------------------------------
class TestSafeRedirect:
    def test_relative_path_allowed(self):
        assert safe_redirect_target("/admin/events", "/admin") == "/admin/events"

    def test_absolute_url_rejected(self):
        assert safe_redirect_target("https://evil.com/", "/admin") == "/admin"

    def test_protocol_relative_rejected(self):
        assert safe_redirect_target("//evil.com/", "/admin") == "/admin"

    def test_none_falls_back(self):
        assert safe_redirect_target(None, "/admin") == "/admin"

    def test_javascript_scheme_rejected(self):
        assert safe_redirect_target("javascript:alert(1)", "/admin") == "/admin"


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
class TestSecurityHeaders:
    def test_headers_applied(self):
        class FakeResponse:
            headers = {}

        response = FakeResponse()
        apply_security_headers(response, csp="default-src 'self'", is_https=True)
        for header in [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
        ]:
            assert header in response.headers

    def test_nosniff_is_set_to_nosniff(self):
        class FakeResponse:
            headers = {}

        response = FakeResponse()
        apply_security_headers(response, csp="default-src 'self'", is_https=True)
        assert response.headers["X-Content-Type-Options"] == "nosniff"

    def test_framing_denied(self):
        class FakeResponse:
            headers = {}

        response = FakeResponse()
        apply_security_headers(response, csp="default-src 'self'", is_https=True)
        assert response.headers["X-Frame-Options"] == "DENY"
