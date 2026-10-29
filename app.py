"""RUK SHADOW INTELLIGENCE - Flask application.

Two clearly separated surfaces:

  Public  (unauthenticated)
    /                      short product/landing page
    /l/<tracking_id>       consent gateway -> records event -> redirects
    /l/<tracking_id>.png   QR code for the share link
    /privacy               privacy notice
    /healthz               liveness probe

  Admin   (session + CSRF protected)
    /admin/login           login form
    /admin                 dashboard with live SSE feed
    /admin/links           link management
    /admin/campaigns       campaign management
    /admin/events          searchable event table
    /admin/export          CSV / JSON download
    /admin/privacy         retention and erasure controls
    /admin/logout          session teardown

The admin surface is never linked from the public pages and every admin route
checks the session before doing any work.
"""
from __future__ import annotations

import io
import json
import os
import secrets
import time
from datetime import datetime, timezone
from functools import wraps
from typing import Any

from flask import (
    Flask,
    Response,
    abort,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    stream_with_context,
    url_for,
)

from analytics import (
    AnalyticsService,
    VisitContext,
    build_notice_summary,
)
from config import Config, ConfigError
from database import Database, utc_now, utc_now_plus
from geolocation import GeoResolver, describe_limitation
from link_generator import (
    LinkCreationError,
    LinkRequest,
    create_tracking_link,
    link_status,
    slugify,
    unique_campaign_slug,
)
from security import (
    ADMIN_CSP,
    PUBLIC_CSP,
    RateLimiter,
    apply_security_headers,
    client_ip,
    ensure_csrf_token,
    generate_visitor_token,
    hash_password,
    safe_redirect_target,
    sanitize_single_line,
    sanitize_text,
    verify_csrf_token,
    verify_password,
)

VISITOR_COOKIE = "ruk_v"
VISITOR_COOKIE_MAX_AGE = 60 * 60 * 24 * 90

ADMIN_SESSION_KEY = "admin_id"
ADMIN_NAME_KEY = "admin_name"
ADMIN_ROLE_KEY = "admin_role"
ADMIN_SEEN_KEY = "admin_seen"


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------
def create_app(config: Config | None = None, db: Database | None = None) -> Flask:
    """Build a fully wired Flask app. Safe to call repeatedly (tests)."""
    config = config or Config.from_env()
    db = db or Database(config.database_file)

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config.update(
        SECRET_KEY=config.secret_key,
        SESSION_COOKIE_NAME="ruk_admin_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=config.session_cookie_secure,
        PERMANENT_SESSION_LIFETIME=config.session_lifetime_seconds,
        MAX_CONTENT_LENGTH=1024 * 1024,  # 1 MiB - forms here are tiny
        JSON_SORT_KEYS=False,
        TEMPLATES_AUTO_RELOAD=not config.is_production,
    )

    geo = GeoResolver(
        provider=config.geo_provider,
        db_path=config.geo_db_path,
        http_endpoint=config.geo_http_endpoint,
    )
    analytics = AnalyticsService(config, db, geo)

    app.extensions["ruk"] = {
        "config": config,
        "db": db,
        "geo": geo,
        "analytics": analytics,
        "login_limiter": RateLimiter(
            config.login_rate_limit, config.login_rate_window
        ),
        "public_limiter": RateLimiter(
            config.public_rate_limit, config.public_rate_window
        ),
        "started_at": time.time(),
    }

    _register_hooks(app)
    _register_public_routes(app)
    _register_admin_routes(app)
    _register_error_handlers(app)
    return app


def _ext(app: Flask) -> dict[str, Any]:
    return app.extensions["ruk"]


# ---------------------------------------------------------------------------
# Request hooks
# ---------------------------------------------------------------------------
def _register_hooks(app: Flask) -> None:
    @app.before_request
    def _load_state() -> None:
        ext = _ext(app)
        cfg: Config = ext["config"]
        g.analytics = ext["analytics"]
        g.db = ext["db"]
        g.cfg = cfg

        # Idle-timeout the admin session.
        if session.get(ADMIN_SESSION_KEY):
            seen = session.get(ADMIN_SEEN_KEY, 0)
            if time.time() - float(seen) > cfg.session_lifetime_seconds:
                session.clear()
            else:
                session[ADMIN_SEEN_KEY] = time.time()

    @app.after_request
    def _headers(response):
        ext = _ext(app)
        cfg: Config = ext["config"]
        is_public = request.path.startswith(("/l/", "/privacy", "/healthz"))
        csp = PUBLIC_CSP if is_public else ADMIN_CSP
        is_https = (
            request.is_secure
            or (cfg.trust_proxy_headers
                and request.headers.get("X-Forwarded-Proto", "") == "https")
        )
        return apply_security_headers(response, csp=csp, is_https=is_https)

    @app.context_processor
    def _inject_globals():
        cfg: Config = _ext(app)["config"]
        return {
            "product_name": "RUK SHADOW INTELLIGENCE",
            "cfg": cfg,
            "is_admin": bool(session.get(ADMIN_SESSION_KEY)),
            "admin_name": session.get(ADMIN_NAME_KEY, ""),
            "csrf_token": ensure_csrf_token(session),
            "now_iso": utc_now(),
        }


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get(ADMIN_SESSION_KEY):
            if request.method in {"GET", "HEAD"}:
                return redirect(
                    url_for("admin_login", next=request.path)
                )
            return jsonify({"error": "authentication required"}), 401
        return view(*args, **kwargs)

    return wrapper


def _current_admin():
    admin_id = session.get(ADMIN_SESSION_KEY)
    if not admin_id:
        return None
    return g.db.get_admin_by_id(int(admin_id))


def _require_csrf() -> None:
    token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not verify_csrf_token(session, token):
        abort(400, description="CSRF token missing or invalid")


def _rate_limit(limiter: RateLimiter, key: str) -> None:
    if not limiter.allow(key):
        retry = limiter.retry_after(key)
        abort(429, description=f"rate limit exceeded; retry in {retry}s")


def _public_ip_for_limits() -> str:
    return (
        client_ip(
            request.remote_addr,
            request.headers.get("X-Forwarded-For"),
            g.cfg.trust_proxy_headers,
        )
        or "unknown"
    )


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------
def _register_public_routes(app: Flask) -> None:
    @app.get("/healthz")
    def healthz():
        return jsonify(
            {
                "status": "ok",
                "product": "ruk-shadow-intelligence",
                "time": utc_now(),
                "version": 1,
            }
        )

    @app.get("/")
    def index():
        return render_template(
            "index.html",
            notice=build_notice_summary(g.cfg),
            geo_note=describe_limitation(),
        )

    @app.get("/privacy")
    def privacy():
        return render_template(
            "privacy.html",
            notice=build_notice_summary(g.cfg),
            geo_note=describe_limitation(),
        )

    @app.get("/l/<tracking_id>")
    def public_link(tracking_id: str):
        """Consent gateway. Records nothing until the visitor agrees."""
        _rate_limit(_ext(app)["public_limiter"], f"link:{_public_ip_for_limits()}")
        tracking_id = sanitize_single_line(tracking_id, max_length=64)
        link = g.db.get_link(tracking_id)
        if link is None:
            abort(404, description="this link does not exist")

        status_code, status_label = link_status(link)
        if status_code != "active":
            return (
                render_template(
                    "link_inactive.html",
                    status=status_label,
                    link=link,
                ),
                410,
            )

        # A link without consent required redirects straight through, but the
        # visitor still sees a disclosure page first so the analytics is not
        # hidden from them.
        visitor_token = request.cookies.get(VISITOR_COOKIE, "")
        if not visitor_token:
            visitor_token = generate_visitor_token()

        return render_template(
            "consent_gateway.html",
            link=link,
            notice=build_notice_summary(g.cfg),
            geo_note=describe_limitation(),
            visitor_token=visitor_token,
            destination_host=_host_of(link.destination_url),
        )

    @app.post("/l/<tracking_id>")
    def public_link_submit(tracking_id: str):
        """Handle the visitor's choice: agree (record) or decline (skip)."""
        _rate_limit(_ext(app)["public_limiter"], f"submit:{_public_ip_for_limits()}")
        tracking_id = sanitize_single_line(tracking_id, max_length=64)
        link = g.db.get_link(tracking_id)
        if link is None:
            abort(404, description="this link does not exist")

        status_code, _ = link_status(link)
        if status_code != "active":
            abort(410, description="this link is no longer active")

        if not verify_csrf_token(session, request.form.get("csrf_token")):
            abort(400, description="CSRF token missing or invalid")

        choice = (request.form.get("choice") or "").strip().lower()
        visitor_token = request.cookies.get(VISITOR_COOKIE, "") or generate_visitor_token()

        if choice == "decline":
            # Record the refusal in aggregate so the operator can see the
            # decline rate, but store no analytics event AND leave nothing on
            # the visitor's device. Departed from the earlier behaviour, which
            # still set the visitor cookie on decline - that would have left an
            # identifier on the device of someone who just said no.
            g.db.record_consent(
                tracking_id=tracking_id,
                visitor_token="",
                granted=False,
                policy_version=g.cfg.policy_version,
                notice_sha256=_notice_fingerprint(g.cfg),
            )
            g.db.log_audit(
                actor="visitor",
                action="consent_declined",
                detail=f"tracking_id={tracking_id}",
            )
            return redirect(link.destination_url, code=302)

        if choice != "agree":
            abort(400, description="unrecognised choice")

        g.db.record_consent(
            tracking_id=tracking_id,
            visitor_token=visitor_token,
            granted=True,
            policy_version=g.cfg.policy_version,
            notice_sha256=_notice_fingerprint(g.cfg),
        )

        outcome = g.analytics.record_visit(
            link,
            VisitContext(
                tracking_id=tracking_id,
                remote_addr=request.remote_addr or "",
                forwarded_for=request.headers.get("X-Forwarded-For"),
                user_agent=request.headers.get("User-Agent", ""),
                referer=request.headers.get("Referer", ""),
                visitor_token=visitor_token,
                consent_granted=True,
            ),
        )

        g.db.log_audit(
            actor="visitor",
            action="consent_granted",
            detail=f"tracking_id={tracking_id} recorded={outcome.recorded}",
        )
        response = redirect(link.destination_url, code=302)
        _set_visitor_cookie(response, visitor_token)
        return response

    @app.get("/l/<tracking_id>.png")
    def public_qr(tracking_id: str):
        """QR code PNG for a share link."""
        tracking_id = sanitize_single_line(tracking_id.replace(".png", ""), max_length=64)
        link = g.db.get_link(tracking_id)
        if link is None:
            abort(404, description="this link does not exist")
        try:
            import qrcode
        except ImportError:
            abort(503, description="QR generation needs: pip install qrcode[pil]")

        img = qrcode.make(g.cfg.share_url(tracking_id))
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        return send_file(
            buffer,
            mimetype="image/png",
            download_name=f"{tracking_id}.png",
            max_age=0,
        )


def _set_visitor_cookie(response, token: str) -> None:
    response.set_cookie(
        VISITOR_COOKIE,
        token,
        max_age=VISITOR_COOKIE_MAX_AGE,
        httponly=True,
        samesite="Lax",
        secure=bool(g.cfg.session_cookie_secure),
    )


def _collection_warnings(cfg: Config) -> list[str]:
    """Honest, actionable warnings shown at the top of the dashboard.

    These describe real deployment problems rather than dressing the UI up:
    a localhost public base URL means links cannot work off-device, and a
    missing geolocation provider means the location columns stay empty.
    """
    warnings = list(cfg.warnings)

    base = cfg.public_base
    if "127.0.0.1" in base or "localhost" in base or base.startswith("http://[::1]"):
        warnings.append(
            "PUBLIC_BASE_URL points at localhost, so generated links only work on "
            "this machine. Set PUBLIC_BASE_URL to your reachable HTTPS address "
            "before sharing links."
        )
    elif base.startswith("http://"):
        warnings.append(
            "PUBLIC_BASE_URL uses plain http://. Visitor traffic and admin sessions "
            "should travel over HTTPS in any real deployment."
        )

    if cfg.geo_provider == "none":
        warnings.append(
            "Geolocation is disabled (GEO_PROVIDER=none), so country and city "
            "columns will stay empty. That is the privacy-preserving default."
        )
    return warnings


def _host_of(url: str) -> str:
    from urllib.parse import urlsplit

    try:
        return urlsplit(url).hostname or url
    except ValueError:
        return url


def _notice_fingerprint(cfg: Config) -> str:
    """Stable hash of the notice text, so a consent record proves *what* was shown."""
    import hashlib

    payload = json.dumps(build_notice_summary(cfg), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------
def _register_admin_routes(app: Flask) -> None:
    @app.route("/admin/login", methods=["GET", "POST"])
    def admin_login():
        ext = _ext(app)
        limiter: RateLimiter = ext["login_limiter"]
        error = ""

        if request.method == "POST":
            _rate_limit(limiter, f"login:{_public_ip_for_limits()}")
            _require_csrf()
            username = sanitize_single_line(request.form.get("username"), max_length=64)
            password = request.form.get("password") or ""

            admin = g.db.get_admin(username) if username else None
            if admin is None or not admin.is_active:
                g.db.log_audit("anonymous", "login_failed", f"unknown user {username!r}")
                error = "Invalid username or password."
            elif not verify_password(admin.password_hash, password):
                g.db.record_login_failure(username)
                g.db.log_audit(username, "login_failed", "bad password")
                error = "Invalid username or password."
            else:
                g.db.record_login_success(admin.id)
                session.clear()
                session.permanent = True
                session[ADMIN_SESSION_KEY] = admin.id
                session[ADMIN_NAME_KEY] = admin.username
                session[ADMIN_ROLE_KEY] = admin.role
                session[ADMIN_SEEN_KEY] = time.time()
                ensure_csrf_token(session)
                g.db.log_audit(admin.username, "login_success", "", _public_ip_for_limits())
                return redirect(safe_redirect_target(request.args.get("next"), "/admin"))

        return render_template(
            "login.html",
            error=error,
            has_admin=g.db.admin_exists(),
        ), (401 if error else 200)

    @app.get("/admin/logout")
    def admin_logout():
        if session.get(ADMIN_SESSION_KEY):
            g.db.log_audit(session.get(ADMIN_NAME_KEY, "admin"), "logout")
        session.clear()
        return redirect(url_for("admin_login"))

    @app.get("/admin")
    @admin_required
    def admin_dashboard():
        totals = g.analytics.totals()
        return render_template(
            "dashboard.html",
            totals=totals,
            events=g.analytics.recent_events(limit=20),
            series=g.analytics.series(hours=24),
            devices=g.analytics.breakdown("device_category"),
            browsers=g.analytics.breakdown("browser_family"),
            countries=g.analytics.breakdown("country"),
            links=g.db.list_links(limit=10),
            geo_status=_ext(app)["geo"].status,
            geo_note=describe_limitation(),
            warnings=_collection_warnings(g.cfg),
        )

    @app.get("/admin/")
    def admin_dashboard_trailing_slash():
        """Browsers and hand-typed URLs add a trailing slash; do not 404 them."""
        return redirect(url_for("admin_dashboard"), code=308)

    # -- links --------------------------------------------------------
    @app.route("/admin/links", methods=["GET", "POST"])
    @admin_required
    def admin_links():
        error = ""
        success = None

        if request.method == "POST":
            _require_csrf()
            try:
                link_request = LinkRequest(
                    destination_url=request.form.get("destination_url", ""),
                    campaign_name=request.form.get("campaign_name", ""),
                    label=request.form.get("label", ""),
                    alias=request.form.get("alias", ""),
                    expires_in_days=_int_or_none(request.form.get("expires_in_days")),
                    require_consent=request.form.get("require_consent") == "on",
                    retention_days=_int_or_none(request.form.get("retention_days")),
                )
                success = create_tracking_link(g.db, g.cfg, link_request)
                g.db.log_audit(
                    session.get(ADMIN_NAME_KEY, "admin"),
                    "link_created",
                    f"tracking_id={success.tracking_id} dest={success.destination_url}",
                )
            except LinkCreationError as exc:
                error = str(exc)

        return render_template(
            "links.html",
            links=g.db.list_links(limit=100),
            campaigns=g.db.list_campaigns(),
            error=error,
            success=success,
            csrf_token=ensure_csrf_token(session),
            default_retention=g.cfg.default_retention_days,
            cfg=g.cfg,
        ), (400 if error else 200)

    @app.post("/admin/links/<tracking_id>/revoke")
    @admin_required
    def admin_revoke_link(tracking_id: str):
        _require_csrf()
        changed = g.db.revoke_link(sanitize_single_line(tracking_id, max_length=64))
        g.db.log_audit(
            session.get(ADMIN_NAME_KEY, "admin"),
            "link_revoked" if changed else "link_revoke_noop",
            f"tracking_id={tracking_id}",
        )
        return redirect(url_for("admin_links"))

    @app.post("/admin/links/<tracking_id>/restore")
    @admin_required
    def admin_restore_link(tracking_id: str):
        _require_csrf()
        g.db.restore_link(sanitize_single_line(tracking_id, max_length=64))
        g.db.log_audit(
            session.get(ADMIN_NAME_KEY, "admin"),
            "link_restored",
            f"tracking_id={tracking_id}",
        )
        return redirect(url_for("admin_links"))

    @app.post("/admin/links/<tracking_id>/delete")
    @admin_required
    def admin_delete_link(tracking_id: str):
        _require_csrf()
        tracking_id = sanitize_single_line(tracking_id, max_length=64)
        if g.db.get_link(tracking_id) is None:
            abort(404, description="that link does not exist")
        g.db.delete_link(tracking_id)
        g.db.log_audit(
            session.get(ADMIN_NAME_KEY, "admin"),
            "link_deleted",
            f"tracking_id={tracking_id} (events and consents purged)",
        )
        return redirect(url_for("admin_links"))

    # -- campaigns ----------------------------------------------------
    @app.route("/admin/campaigns", methods=["GET", "POST"])
    @admin_required
    def admin_campaigns():
        error = ""
        if request.method == "POST":
            _require_csrf()
            name = sanitize_single_line(request.form.get("name"), max_length=80)
            description = sanitize_text(request.form.get("description"), max_length=500)
            if not name:
                error = "Campaign name is required."
            else:
                slug = unique_campaign_slug(g.db, name)
                g.db.create_campaign(name=name, slug=slug, description=description)
                g.db.log_audit(
                    session.get(ADMIN_NAME_KEY, "admin"),
                    "campaign_created",
                    f"name={name} slug={slug}",
                )
                return redirect(url_for("admin_campaigns"))

        return render_template(
            "campaigns.html",
            campaigns=g.db.list_campaigns(include_archived=True),
            performance=g.db.campaign_performance(),
            error=error,
        ), (400 if error else 200)

    @app.post("/admin/campaigns/<int:campaign_id>/archive")
    @admin_required
    def admin_archive_campaign(campaign_id: int):
        _require_csrf()
        g.db.archive_campaign(campaign_id, archived=True)
        g.db.log_audit(
            session.get(ADMIN_NAME_KEY, "admin"),
            "campaign_archived",
            f"id={campaign_id}",
        )
        return redirect(url_for("admin_campaigns"))

    # -- events -------------------------------------------------------
    @app.get("/admin/events")
    @admin_required
    def admin_events():
        page = max(1, _int_or_none(request.args.get("page")) or 1)
        events, total = g.analytics.search(
            query=request.args.get("q", ""),
            device=request.args.get("device", ""),
            consent=request.args.get("consent", ""),
            since=request.args.get("since", ""),
            page=page,
            per_page=25,
        )
        pages = max(1, (total + 24) // 25)
        return render_template(
            "events.html",
            events=events,
            total=total,
            page=page,
            pages=pages,
            filters={
                "q": request.args.get("q", ""),
                "device": request.args.get("device", ""),
                "consent": request.args.get("consent", ""),
                "since": request.args.get("since", ""),
            },
        )

    # -- live feed (SSE) ----------------------------------------------
    @app.get("/admin/stream")
    @admin_required
    def admin_stream():
        """Server-Sent Events: pushes new events as they are recorded."""
        last_id = _int_or_none(request.args.get("last_id")) or 0

        @stream_with_context
        def generate():
            nonlocal last_id
            yield _sse("ready", {"last_id": last_id})
            deadline = time.time() + 300  # recycle the connection after 5 min
            idle = 0
            while time.time() < deadline:
                events = g.analytics.new_events_since(last_id, limit=50)
                if events:
                    for event in events:
                        last_id = max(last_id, event.id)
                        yield _sse("event", _event_payload(event))
                    idle = 0
                else:
                    idle += 1
                    if idle % 15 == 0:
                        yield _sse("ping", {"time": utc_now()})
                time.sleep(1.0)
            yield _sse("bye", {})

        return Response(
            generate(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "X-Accel-Buffering": "no",
                # NB: do not set "Connection: keep-alive" here. Connection is a
                # hop-by-hop header and PEP 3333 forbids a WSGI application from
                # sending it - Waitress raises AssertionError and the stream 500s.
            },
        )

    @app.get("/admin/api/stats")
    @admin_required
    def admin_api_stats():
        totals = g.analytics.totals()
        return jsonify(
            {
                "total_events": totals.total_events,
                "unique_events": totals.unique_events,
                "active_links": totals.active_links,
                "campaigns": totals.campaigns,
                "consent_rate": totals.consent_rate,
                "events_24h": totals.events_24h,
                "series": g.analytics.series(hours=24),
                "devices": [
                    {"label": b.label, "count": b.count}
                    for b in g.analytics.breakdown("device_category")
                ],
            }
        )

    # -- export -------------------------------------------------------
    @app.get("/admin/export")
    @admin_required
    def admin_export():
        fmt = "json" if request.args.get("format") == "json" else "csv"
        since = request.args.get("since") or None
        if since and len(since) == 10:
            since = f"{since}T00:00:00Z"
        payload = g.analytics.export(fmt=fmt, since=since)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return Response(
            payload,
            mimetype="application/json" if fmt == "json" else "text/csv",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="ruk-events-{stamp}.{fmt}"'
                )
            },
        )

    # -- privacy / retention -----------------------------------------
    @app.route("/admin/privacy", methods=["GET", "POST"])
    @admin_required
    def admin_privacy():
        message = ""
        if request.method == "POST":
            _require_csrf()
            action = request.form.get("action", "")
            actor = session.get(ADMIN_NAME_KEY, "admin")

            if action == "purge":
                days = _int_or_none(request.form.get("days")) or g.cfg.default_retention_days
                removed = g.db.purge_expired(days)
                total = sum(removed.values())
                message = (
                    f"Retention purge completed: {total} row(s) removed "
                    f"({removed['expired_link_events']} from expired links, "
                    f"{removed['aged_events']} older than {days} days, "
                    f"{removed['aged_consent']} consent records)."
                )
                g.db.log_audit(actor, "retention_purge", f"days={days} removed={removed}")

            elif action == "wipe_events":
                removed = g.db.delete_all_events()
                message = f"All analytics events deleted ({removed} rows)."
                g.db.log_audit(actor, "wipe_events", f"removed={removed}")

            elif action == "wipe_link":
                target = sanitize_single_line(
                    request.form.get("tracking_id"), max_length=64
                )
                removed = g.db.delete_all_events(target)
                message = f"Events for {target} deleted ({removed} rows)."
                g.db.log_audit(actor, "wipe_link_events", f"tracking_id={target}")

            elif action == "erase_visitor":
                token = sanitize_single_line(
                    request.form.get("visitor_token"), max_length=64
                )
                removed = g.db.delete_events_for_visitor(token)
                message = (
                    f"Visitor erasure completed: {removed} event(s) deleted and "
                    "consent marked withdrawn."
                )
                g.db.log_audit(actor, "erase_visitor", f"token_prefix={token[:8]}")

            else:
                message = "Unknown action."

        counts = g.db.table_counts()
        return render_template(
            "privacy_admin.html",
            counts=counts,
            consent=g.db.consent_stats(),
            audit=g.db.list_audit(limit=25),
            message=message,
            default_retention=g.cfg.default_retention_days,
            retention_limits=dict(
                days=g.cfg.default_retention_days,
                sweep_seconds=g.cfg.retention_sweep_seconds,
            ),
            geo_status=_ext(app)["geo"].status,
            notice=build_notice_summary(g.cfg),
        )


def _int_or_none(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _event_payload(event) -> dict[str, Any]:
    """Only the fields the admin dashboard displays - no raw internal columns."""
    return {
        "id": event.id,
        "time": event.created_at,
        "tracking_id": event.tracking_id,
        "campaign": event.campaign_name,
        "country": event.country,
        "region": event.region,
        "city": event.city,
        "location": event.location_label,
        "browser": f"{event.browser_family} {event.browser_version}".strip(),
        "os": f"{event.os_family} {event.os_version}".strip(),
        "device": event.device_category,
        "consent": event.consent_status,
        "ip": event.ip_address,
        "referrer": event.referrer_host,
        "unique": event.is_unique,
    }


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
def _register_error_handlers(app: Flask) -> None:
    def _render(code: int, title: str, detail: str):
        return (
            render_template(
                "error.html",
                code=code,
                title=title,
                detail=detail,
            ),
            code,
        )

    @app.errorhandler(400)
    def _400(exc):
        return _render(400, "Bad request", getattr(exc, "description", "Invalid request."))

    @app.errorhandler(401)
    def _401(exc):
        return _render(401, "Not authorised", "Sign in to continue.")

    @app.errorhandler(403)
    def _403(exc):
        return _render(403, "Forbidden", "You do not have access to this resource.")

    @app.errorhandler(404)
    def _404(exc):
        return _render(404, "Not found", getattr(exc, "description", "Nothing here."))

    @app.errorhandler(410)
    def _410(exc):
        return _render(410, "Link inactive", getattr(exc, "description", "Gone."))

    @app.errorhandler(429)
    def _429(exc):
        return _render(429, "Too many requests", getattr(exc, "description", "Slow down."))

    @app.errorhandler(500)
    def _500(exc):  # pragma: no cover - exercised only on unexpected failure
        app.logger.exception("unhandled error")
        return _render(
            500,
            "Internal error",
            "Something went wrong. The error was logged, not shown, because "
            "details can leak configuration.",
        )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def _serve(app: Flask, config: Config | None = None) -> None:
    """Run the server with Waitress when available, else Flask's dev server."""
    cfg = config or _ext(app)["config"]
    try:
        from waitress import serve

        print(
            f"[RUK] Waitress serving on http://{cfg.bind_host}:{cfg.bind_port} "
            f"(env={cfg.env})"
        )
        serve(app, host=cfg.bind_host, port=cfg.bind_port, threads=8)
    except ImportError:
        print(
            f"[RUK] Waitress not installed; using the Flask development server on "
            f"http://{cfg.bind_host}:{cfg.bind_port}"
        )
        print("[RUK] The development server is NOT suitable for production.")
        app.run(host=cfg.bind_host, port=cfg.bind_port, debug=False, threaded=True)


if __name__ == "__main__":
    try:
        cfg = Config.from_env()
    except ConfigError as exc:
        print(f"[RUK] configuration error: {exc}")
        raise SystemExit(2)
    _serve(create_app(cfg), cfg)
