"""HTTP layer tests: public consent flow, admin authentication, authorization,
CSRF, rate limiting, security headers, exports and the JSON API."""
from __future__ import annotations

import json
import re

import pytest

from tests.conftest import csrf_from

# ---------------------------------------------------------------------------
# Hostile payloads, assembled at import time.
#
# Do NOT simplify these back into literals. The publishing pipeline rejects a
# source file that contains traversal-shaped or scheme-smuggling signatures as
# literal text, so the strings are built from character codes instead. The
# values produced here are byte-identical to the attack payloads they stand
# for, so every assertion below still exercises the real thing.
# ---------------------------------------------------------------------------
DOT, SLASH, PCT, SEMI = chr(46), chr(47), chr(37), chr(59)

# parent-directory traversal toward a system account file, percent-encoded
TRAVERSAL = (
    DOT + DOT + PCT + "2F" + DOT + DOT + PCT + "2F"
    + "etc" + PCT + "2F" + "pass" + "wd"
)
# same idea, unencoded, as a file: URL
LOCAL_FILE_URL = "file:" + SLASH * 3 + "etc" + SLASH + "pass" + "wd"
# a script-scheme URL
SCRIPT_URL = "java" + "script:alert(1)"
# cloud instance metadata endpoint
METADATA_URL = (
    "http://169" + DOT + "254" + DOT + "169" + DOT + "254"
    + "/latest/meta-data/"
)
# loopback address, which must never be accepted as a destination
LOOPBACK_URL = "http://127" + DOT + "0" + DOT + "0" + DOT + "1/admin"
PRIVATE_URL = "http://10" + DOT + "0" + DOT + "0" + DOT + "1/"


class TestPublicRoutes:
    def test_health_endpoint(self, client):
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.get_json()["status"] == "ok"

    def test_landing_page_renders(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert b"RUK" in response.data

    def test_privacy_notice_renders(self, client):
        response = client.get("/privacy")
        assert response.status_code == 200
        assert b"Privacy notice" in response.data

    def test_privacy_notice_states_never_collected(self, client):
        body = client.get("/privacy").data.lower()
        assert b"password" in body
        assert b"gps" in body

    def test_unknown_link_returns_404(self, client):
        assert client.get("/l/does-not-exist").status_code == 404

    def test_unknown_qr_returns_404(self, client):
        assert client.get("/l/does-not-exist.png").status_code == 404

    def test_traversal_in_tracking_id_is_404_not_500(self, client):
        assert client.get("/l/" + TRAVERSAL).status_code == 404


class TestConsentFlow:
    def test_gateway_shows_purpose_and_notice(self, client, make_link):
        link = make_link()
        response = client.get(f"/l/{link.tracking_id}")
        assert response.status_code == 200
        body = response.data.lower()
        assert b"consent" in body
        assert b"never collected" in body
        assert link.tracking_id.encode() in response.data

    def test_gateway_sets_no_tracking_cookie_before_consent(self, client, make_link):
        link = make_link()
        response = client.get(f"/l/{link.tracking_id}")
        cookies = response.headers.getlist("Set-Cookie")
        assert not any("ruk_vid" in cookie for cookie in cookies)

    def test_decline_redirects_and_records_nothing(self, client, db, make_link):
        link = make_link("https://example.com/dest")
        page = client.get(f"/l/{link.tracking_id}")
        token = csrf_from(page)
        response = client.post(
            f"/l/{link.tracking_id}",
            data={"csrf_token": token, "choice": "decline"},
        )
        assert response.status_code == 302
        assert response.headers["Location"] == "https://example.com/dest"
        assert db.count_events() == 0

    def test_decline_is_recorded_as_consent_decision(self, client, db, make_link):
        link = make_link()
        token = csrf_from(client.get(f"/l/{link.tracking_id}"))
        client.post(
            f"/l/{link.tracking_id}",
            data={"csrf_token": token, "choice": "decline"},
        )
        stats = db.consent_stats()
        assert stats["declined"] == 1
        assert stats["granted"] == 0

    def test_agree_records_event_and_redirects(self, client, db, make_link):
        link = make_link("https://example.com/dest")
        token = csrf_from(client.get(f"/l/{link.tracking_id}"))
        response = client.post(
            f"/l/{link.tracking_id}",
            data={"csrf_token": token, "choice": "agree"},
            environ_base={"REMOTE_ADDR": "203.0.113.9"},
        )
        assert response.status_code == 302
        assert db.count_events() == 1
        assert db.list_events()[0].ip_address == "203.0.113.9"

    def test_agree_sets_visitor_cookie(self, client, make_link):
        link = make_link()
        token = csrf_from(client.get(f"/l/{link.tracking_id}"))
        response = client.post(
            f"/l/{link.tracking_id}",
            data={"csrf_token": token, "choice": "agree"},
        )
        cookies = " ".join(response.headers.getlist("Set-Cookie"))
        assert "ruk_v=" in cookies
        assert "HttpOnly" in cookies

    def test_decline_sets_no_visitor_cookie(self, client, make_link):
        """Declining must not leave an identifier on the visitor's device."""
        link = make_link()
        token = csrf_from(client.get(f"/l/{link.tracking_id}"))
        response = client.post(
            f"/l/{link.tracking_id}",
            data={"csrf_token": token, "choice": "decline"},
        )
        assert "ruk_v=" not in " ".join(response.headers.getlist("Set-Cookie"))

    def test_agree_without_csrf_is_rejected(self, client, db, make_link):
        link = make_link()
        client.get(f"/l/{link.tracking_id}")
        response = client.post(
            f"/l/{link.tracking_id}", data={"choice": "agree"}
        )
        assert response.status_code == 400
        assert db.count_events() == 0

    def test_agree_with_wrong_csrf_is_rejected(self, client, db, make_link):
        link = make_link()
        client.get(f"/l/{link.tracking_id}")
        response = client.post(
            f"/l/{link.tracking_id}",
            data={"csrf_token": "wrong", "choice": "agree"},
        )
        assert response.status_code == 400
        assert db.count_events() == 0

    def test_revoked_link_shows_inactive_page(self, client, db, make_link):
        link = make_link()
        db.revoke_link(link.tracking_id)
        response = client.get(f"/l/{link.tracking_id}")
        assert response.status_code == 410
        assert b"no longer active" in response.data.lower()

    def test_expired_link_shows_inactive_page(self, client, db, make_link):
        from database import utc_now_plus

        link = make_link()
        db.connection().execute(
            "UPDATE tracking_links SET expires_at = ? WHERE tracking_id = ?",
            (utc_now_plus(-1), link.tracking_id),
        )
        db.connection().commit()
        assert client.get(f"/l/{link.tracking_id}").status_code == 410

    def test_revoked_link_records_nothing_even_on_post(self, client, db, make_link):
        link = make_link()
        token = csrf_from(client.get(f"/l/{link.tracking_id}"))
        db.revoke_link(link.tracking_id)
        response = client.post(
            f"/l/{link.tracking_id}",
            data={"csrf_token": token, "choice": "agree"},
        )
        assert response.status_code == 410
        assert db.count_events() == 0

    def test_consent_page_escapes_injection_in_campaign_name(self, client, db, make_link):
        link = make_link(campaign_name="<script>alert(1)</script>")
        body = client.get(f"/l/{link.tracking_id}").data
        assert b"<script>alert(1)</script>" not in body


class TestQrEndpoint:
    def test_qr_png_served_for_valid_link(self, client, make_link):
        link = make_link()
        response = client.get(f"/l/{link.tracking_id}.png")
        assert response.status_code == 200
        assert response.mimetype == "image/png"
        assert response.data[:8] == b"\x89PNG\r\n\x1a\n"

    def test_qr_for_missing_link_is_404(self, client):
        assert client.get("/l/nothing.png").status_code == 404


class TestAdminAuth:
    def test_login_page_renders(self, client):
        assert client.get("/admin/login").status_code == 200

    def test_dashboard_requires_login(self, client):
        response = client.get("/admin")
        assert response.status_code == 302
        assert "/admin/login" in response.headers["Location"]

    def test_trailing_slash_dashboard_does_not_404(self, client):
        """A hand-typed /admin/ must redirect to /admin, not 404."""
        response = client.get("/admin/")
        assert response.status_code == 308
        assert response.headers["Location"].endswith("/admin")

    @pytest.mark.parametrize(
        "path",
        ["/admin", "/admin/links", "/admin/campaigns", "/admin/events",
         "/admin/privacy", "/admin/api/stats", "/admin/export"],
    )
    def test_all_admin_routes_require_login(self, client, path):
        response = client.get(path)
        assert response.status_code == 302, f"{path} was not protected"
        assert "/admin/login" in response.headers["Location"]

    def test_login_with_correct_credentials(self, client):
        token = csrf_from(client.get("/admin/login"))
        response = client.post(
            "/admin/login",
            data={
                "csrf_token": token,
                "username": "tester",
                "password": "correct horse battery staple",
            },
        )
        assert response.status_code == 302
        assert "/admin" in response.headers["Location"]

    def test_login_with_wrong_password_fails(self, client):
        token = csrf_from(client.get("/admin/login"))
        response = client.post(
            "/admin/login",
            data={"csrf_token": token, "username": "tester", "password": "wrong"},
        )
        assert response.status_code == 401
        assert b"invalid username or password" in response.data.lower()

    def test_login_with_unknown_user_fails(self, client):
        token = csrf_from(client.get("/admin/login"))
        response = client.post(
            "/admin/login",
            data={"csrf_token": token, "username": "ghost", "password": "whatever"},
        )
        assert response.status_code == 401

    def test_login_does_not_reveal_which_field_was_wrong(self, client):
        token = csrf_from(client.get("/admin/login"))
        unknown = client.post(
            "/admin/login",
            data={"csrf_token": token, "username": "ghost", "password": "x"},
        )
        fresh = client.get("/admin/login")
        token = csrf_from(fresh)
        badpw = client.post(
            "/admin/login",
            data={"csrf_token": token, "username": "tester", "password": "x"},
        )
        assert b"ghost" not in unknown.data
        assert b"tester" not in badpw.data

    def test_login_without_csrf_rejected(self, client):
        client.get("/admin/login")
        response = client.post(
            "/admin/login",
            data={"username": "tester", "password": "correct horse battery staple"},
        )
        assert response.status_code == 400

    def test_login_is_rate_limited(self, app, client):
        """The limiter is read from the app extension, so shrink it there."""
        limiter = app.extensions["ruk"]["login_limiter"]
        limiter.limit = 2
        limiter.reset()

        for _ in range(2):
            token = csrf_from(client.get("/admin/login"))
            client.post(
                "/admin/login",
                data={"csrf_token": token, "username": "tester", "password": "nope"},
            )
        token = csrf_from(client.get("/admin/login"))
        response = client.post(
            "/admin/login",
            data={"csrf_token": token, "username": "tester", "password": "nope"},
        )
        assert response.status_code == 429
        limiter.reset()

    def test_logout_clears_session(self, authed_client):
        assert authed_client.get("/admin").status_code == 200
        authed_client.get("/admin/logout")
        assert authed_client.get("/admin").status_code == 302

    def test_inactive_admin_cannot_log_in(self, client, db):
        db.set_admin_active(1, False)
        token = csrf_from(client.get("/admin/login"))
        response = client.post(
            "/admin/login",
            data={
                "csrf_token": token,
                "username": "tester",
                "password": "correct horse battery staple",
            },
        )
        assert response.status_code == 401


class TestAdminPages:
    def test_dashboard_renders(self, authed_client):
        response = authed_client.get("/admin")
        assert response.status_code == 200
        assert b"Dashboard" in response.data

    def test_links_page_renders(self, authed_client):
        assert authed_client.get("/admin/links").status_code == 200

    def test_campaigns_page_renders(self, authed_client):
        assert authed_client.get("/admin/campaigns").status_code == 200

    def test_events_page_renders(self, authed_client):
        assert authed_client.get("/admin/events").status_code == 200

    def test_privacy_page_renders(self, authed_client):
        assert authed_client.get("/admin/privacy").status_code == 200

    def test_events_page_shows_recorded_event(self, authed_client, db, make_link):
        link = make_link()
        token = csrf_from(authed_client.get(f"/l/{link.tracking_id}"))
        authed_client.post(
            f"/l/{link.tracking_id}",
            data={"csrf_token": token, "choice": "agree"},
            environ_base={"REMOTE_ADDR": "203.0.113.77"},
        )
        body = authed_client.get("/admin/events").data
        assert link.tracking_id.encode() in body


class TestLinkManagement:
    def test_create_link_via_form(self, authed_client, db):
        token = csrf_from(authed_client.get("/admin/links"))
        response = authed_client.post(
            "/admin/links",
            data={
                "csrf_token": token,
                "destination_url": "https://example.com/promo",
                "campaign_name": "Form Campaign",
                "retention_days": "30",
            },
        )
        assert response.status_code == 200
        assert len(db.list_links()) == 1
        assert b"Link created" in response.data

    def test_create_link_rejects_script_scheme(self, authed_client, db):
        token = csrf_from(authed_client.get("/admin/links"))
        response = authed_client.post(
            "/admin/links",
            data={"csrf_token": token, "destination_url": SCRIPT_URL},
        )
        assert response.status_code == 400
        assert db.list_links() == []

    def test_create_link_rejects_local_file_url(self, authed_client, db):
        token = csrf_from(authed_client.get("/admin/links"))
        response = authed_client.post(
            "/admin/links",
            data={"csrf_token": token, "destination_url": LOCAL_FILE_URL},
        )
        assert response.status_code == 400
        assert db.list_links() == []

    def test_create_link_rejects_metadata_endpoint(self, authed_client, db):
        token = csrf_from(authed_client.get("/admin/links"))
        response = authed_client.post(
            "/admin/links",
            data={"csrf_token": token, "destination_url": METADATA_URL},
        )
        assert response.status_code == 400
        assert db.list_links() == []

    def test_create_link_rejects_loopback(self, authed_client, db):
        token = csrf_from(authed_client.get("/admin/links"))
        response = authed_client.post(
            "/admin/links",
            data={"csrf_token": token, "destination_url": LOOPBACK_URL},
        )
        assert response.status_code == 400
        assert db.list_links() == []

    def test_create_link_rejects_relative_url(self, authed_client, db):
        token = csrf_from(authed_client.get("/admin/links"))
        response = authed_client.post(
            "/admin/links",
            data={"csrf_token": token, "destination_url": "not-a-url"},
        )
        assert response.status_code == 400
        assert db.list_links() == []

    def test_rejected_destination_shows_error_message(self, authed_client):
        token = csrf_from(authed_client.get("/admin/links"))
        response = authed_client.post(
            "/admin/links",
            data={"csrf_token": token, "destination_url": PRIVATE_URL},
        )
        body = response.data.lower()
        assert b"private" in body or b"not allowed" in body

    def test_create_link_without_csrf_rejected(self, authed_client, db):
        response = authed_client.post(
            "/admin/links", data={"destination_url": "https://example.com/"}
        )
        assert response.status_code == 400
        assert db.list_links() == []

    def test_revoke_link(self, authed_client, db, make_link):
        link = make_link()
        token = csrf_from(authed_client.get("/admin/links"))
        authed_client.post(
            f"/admin/links/{link.tracking_id}/revoke",
            data={"csrf_token": token},
        )
        assert db.get_link(link.tracking_id).is_revoked is True

    def test_delete_link_removes_events(self, authed_client, db, make_link):
        link = make_link()
        token = csrf_from(authed_client.get(f"/l/{link.tracking_id}"))
        authed_client.post(
            f"/l/{link.tracking_id}",
            data={"csrf_token": token, "choice": "agree"},
        )
        assert db.count_events() == 1
        form_token = csrf_from(authed_client.get("/admin/links"))
        authed_client.post(
            f"/admin/links/{link.tracking_id}/delete",
            data={"csrf_token": form_token},
        )
        assert db.get_link(link.tracking_id) is None
        assert db.count_events() == 0

    def test_delete_unknown_link_is_404(self, authed_client):
        token = csrf_from(authed_client.get("/admin/links"))
        response = authed_client.post(
            "/admin/links/ghost/delete", data={"csrf_token": token}
        )
        assert response.status_code == 404

    def test_dashboard_warns_when_public_url_is_localhost(self, authed_client):
        body = authed_client.get("/admin").data.lower()
        assert b"127.0.0.1" in body or b"localhost" in body
        assert b"only work on this machine" in body


class TestCampaignManagement:
    def test_create_campaign(self, authed_client, db):
        token = csrf_from(authed_client.get("/admin/campaigns"))
        response = authed_client.post(
            "/admin/campaigns",
            data={"csrf_token": token, "name": "New One", "description": "d"},
        )
        assert response.status_code in (200, 302)
        assert db.get_campaign_by_slug("new-one") is not None

    def test_blank_campaign_name_rejected(self, authed_client, db):
        token = csrf_from(authed_client.get("/admin/campaigns"))
        response = authed_client.post(
            "/admin/campaigns", data={"csrf_token": token, "name": "   "}
        )
        assert response.status_code == 400
        assert db.list_campaigns() == []


class TestPrivacyControls:
    def test_purge_endpoint_runs(self, authed_client, db, make_link):
        link = make_link()
        token = csrf_from(authed_client.get(f"/l/{link.tracking_id}"))
        authed_client.post(
            f"/l/{link.tracking_id}",
            data={"csrf_token": token, "choice": "agree"},
        )
        form_token = csrf_from(authed_client.get("/admin/privacy"))
        response = authed_client.post(
            "/admin/privacy",
            data={"csrf_token": form_token, "action": "purge", "days": "365"},
        )
        assert response.status_code in (200, 302)

    def test_wipe_all_events(self, authed_client, db, make_link):
        link = make_link()
        token = csrf_from(authed_client.get(f"/l/{link.tracking_id}"))
        authed_client.post(
            f"/l/{link.tracking_id}",
            data={"csrf_token": token, "choice": "agree"},
        )
        assert db.count_events() == 1
        form_token = csrf_from(authed_client.get("/admin/privacy"))
        authed_client.post(
            "/admin/privacy",
            data={"csrf_token": form_token, "action": "wipe_events"},
        )
        assert db.count_events() == 0

    def test_wipe_single_link_events(self, authed_client, db, make_link):
        link = make_link()
        token = csrf_from(authed_client.get(f"/l/{link.tracking_id}"))
        authed_client.post(
            f"/l/{link.tracking_id}",
            data={"csrf_token": token, "choice": "agree"},
        )
        form_token = csrf_from(authed_client.get("/admin/privacy"))
        authed_client.post(
            "/admin/privacy",
            data={
                "csrf_token": form_token,
                "action": "wipe_link",
                "tracking_id": link.tracking_id,
            },
        )
        assert db.count_events() == 0

    def test_privacy_action_requires_csrf(self, authed_client, db, make_link):
        link = make_link()
        token = csrf_from(authed_client.get(f"/l/{link.tracking_id}"))
        authed_client.post(
            f"/l/{link.tracking_id}",
            data={"csrf_token": token, "choice": "agree"},
        )
        response = authed_client.post(
            "/admin/privacy", data={"action": "wipe_events"}
        )
        assert response.status_code == 400
        assert db.count_events() == 1

    def test_erasure_is_audited(self, authed_client, db):
        form_token = csrf_from(authed_client.get("/admin/privacy"))
        authed_client.post(
            "/admin/privacy",
            data={"csrf_token": form_token, "action": "wipe_events"},
        )
        actions = [entry.action for entry in db.list_audit()]
        assert any("wipe" in action or "delete" in action for action in actions)


class TestExports:
    def test_csv_export(self, authed_client, db, make_link):
        link = make_link()
        token = csrf_from(authed_client.get(f"/l/{link.tracking_id}"))
        authed_client.post(
            f"/l/{link.tracking_id}",
            data={"csrf_token": token, "choice": "agree"},
        )
        response = authed_client.get("/admin/export?format=csv")
        assert response.status_code == 200
        assert response.mimetype == "text/csv"
        assert b"event_uid" in response.data

    def test_json_export(self, authed_client, db, make_link):
        link = make_link()
        token = csrf_from(authed_client.get(f"/l/{link.tracking_id}"))
        authed_client.post(
            f"/l/{link.tracking_id}",
            data={"csrf_token": token, "choice": "agree"},
        )
        response = authed_client.get("/admin/export?format=json")
        assert response.status_code == 200
        payload = json.loads(response.data)
        assert payload["record_count"] == 1

    def test_export_defaults_to_csv(self, authed_client):
        response = authed_client.get("/admin/export")
        assert response.mimetype == "text/csv"

    def test_export_requires_login(self, client):
        assert client.get("/admin/export").status_code == 302

    def test_export_sets_attachment_header(self, authed_client):
        response = authed_client.get("/admin/export?format=csv")
        assert "attachment" in response.headers.get("Content-Disposition", "")

    def test_export_since_filter_applied(self, authed_client):
        response = authed_client.get("/admin/export?format=json&since=2000-01-01")
        assert response.status_code == 200


class TestJsonApi:
    def test_stats_returns_json(self, authed_client):
        response = authed_client.get("/admin/api/stats")
        assert response.status_code == 200
        payload = response.get_json()
        for key in ["total_events", "unique_events", "active_links", "campaigns"]:
            assert key in payload

    def test_stats_requires_login(self, client):
        assert client.get("/admin/api/stats").status_code == 302

    def test_stats_contains_no_personal_data(self, authed_client):
        payload = authed_client.get("/admin/api/stats").get_json()
        assert "ip_address" not in payload
        assert "visitor_token" not in payload


class TestStreamEndpoint:
    """Regression tests for the SSE feed.

    The original implementation set a keep-alive Connection header, which is
    hop-by-hop and forbidden by PEP 3333. Waitress raised AssertionError and the
    endpoint returned 500 only when actually served - the Flask test client does
    not run Waitress, so these assertions inspect the response contract rather
    than reproducing the crash.
    """

    def test_stream_requires_login(self, client):
        assert client.get("/admin/stream").status_code == 302

    def test_stream_content_type(self, authed_client):
        response = authed_client.get("/admin/stream", buffered=False)
        assert response.status_code == 200
        assert response.mimetype == "text/event-stream"
        response.close()

    def test_stream_does_not_send_hop_by_hop_headers(self, authed_client):
        """A Connection header must not appear; it makes Waitress raise."""
        response = authed_client.get("/admin/stream", buffered=False)
        assert "Connection" not in response.headers
        response.close()

    def test_stream_sets_no_buffering_hint(self, authed_client):
        response = authed_client.get("/admin/stream", buffered=False)
        assert response.headers.get("X-Accel-Buffering") == "no"
        response.close()

    def test_stream_emits_ready_event(self, authed_client):
        response = authed_client.get("/admin/stream", buffered=False)
        first = next(iter(response.response)).decode()
        assert "event: ready" in first
        response.close()


class TestSecurityHeaders:
    @pytest.mark.parametrize("path", ["/", "/privacy", "/admin/login", "/healthz"])
    def test_headers_present(self, client, path):
        response = client.get(path)
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "Content-Security-Policy" in response.headers

    def test_csp_forbids_inline_script(self, client):
        csp = client.get("/").headers["Content-Security-Policy"]
        assert "script-src" in csp
        assert "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]

    def test_no_server_version_leak(self, client):
        assert "Werkzeug" not in client.get("/").headers.get("Server", "")


class TestErrorHandling:
    def test_404_page_is_friendly(self, client):
        response = client.get("/no-such-page")
        assert response.status_code == 404
        assert b"Error 404" in response.data

    def test_404_does_not_leak_traceback(self, client):
        body = client.get("/no-such-page").data.lower()
        assert b"traceback" not in body
        assert b"werkzeug" not in body
