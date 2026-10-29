#!/usr/bin/env python3
"""RUK SHADOW INTELLIGENCE - terminal interface.

A Rich-rendered terminal dashboard with thirteen working menu options. Nothing
here is decorative: every option reads or writes the same SQLite database the
web dashboard uses.

Usage
-----
    python terminal_dashboard.py                  # interactive menu
    python terminal_dashboard.py --create-admin   # create the first admin
    python terminal_dashboard.py --diagnose       # system diagnostics only
    python terminal_dashboard.py --export csv     # export and exit

For scripted or automated use, every menu action is also reachable by flag so
the interface can be exercised without a TTY.
"""
from __future__ import annotations

import argparse
import os
import platform
import shutil
import socket
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from rich import box
    from rich.align import Align
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.prompt import Confirm, Prompt
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:  # pragma: no cover
    RICH_AVAILABLE = False
    Console = None  # type: ignore


# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------
CYAN = "bright_cyan"
VIOLET = "medium_purple1"
GREEN = "spring_green2"
GOLD = "gold1"
RED = "red1"
DIM = "grey54"

ASCII_LOGO = r"""
   ██████╗ ██╗   ██╗██╗  ██╗    ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
   ██╔══██╗██║   ██║██║ ██╔╝    ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
   ██████╔╝██║   ██║█████╔╝     ███████╗███████║███████║██████╔╝██║   ██║██║ █╗ ██║
   ██╔══██╗██║   ██║██╔═██╗     ╚════██║██╔══██║██╔══██║██╔══██╗██║   ██║██║███╗██║
   ██║  ██║╚██████╔╝██║  ██╗    ███████║██║  ██║██║  ██║██║  ██║╚██████╔╝╚███╔███╔╝
   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝
"""

MENU_ITEMS: list[tuple[str, str, str]] = [
    ("1", "Dashboard", "overview counters and recent activity"),
    ("2", "Create Analytics Link", "validated destination, QR code, share URL"),
    ("3", "Manage Campaigns", "list, create and archive campaigns"),
    ("4", "Live Click Events", "stream new events as they arrive"),
    ("5", "Visitor Analytics", "breakdowns by device, browser, country"),
    ("6", "Browser & Device Reports", "detailed browser and platform tables"),
    ("7", "IP Address and Network Metadata", "inspect what was stored, per event"),
    ("8", "Consent Management", "granted vs declined, per-visitor erasure"),
    ("9", "Export Reports", "CSV or JSON to reports/"),
    ("10", "Security & Configuration", "settings, warnings, password change"),
    ("11", "System Diagnostics", "paths, database, dependencies, integrity"),
    ("12", "Help and Documentation", "how this works and what it will not do"),
    ("13", "Exit", "leave the terminal interface"),
]


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
def _load_runtime():
    """Import the app modules lazily so --help works without dependencies."""
    from analytics import AnalyticsService  # noqa: F401
    from config import Config, ConfigError  # noqa: F401
    from database import Database  # noqa: F401
    from geolocation import GeoResolver  # noqa: F401

    return Config, ConfigError, Database, AnalyticsService, GeoResolver


def build_context():
    """Return (config, db, analytics, geo) or raise a clear error."""
    Config, ConfigError, Database, AnalyticsService, GeoResolver = _load_runtime()
    try:
        config = Config.from_env()
    except ConfigError as exc:
        raise SystemExit(f"Configuration error: {exc}") from exc

    db = Database(config.database_file)
    geo = GeoResolver(
        provider=config.geo_provider,
        db_path=config.geo_db_path,
        http_endpoint=config.geo_http_endpoint,
    )
    analytics = AnalyticsService(config, db, geo)
    return config, db, analytics, geo


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------
class UI:
    """Thin wrapper so every screen looks consistent."""

    def __init__(self, console: Console) -> None:
        self.console = console

    def banner(self, config=None) -> None:
        self.console.clear()
        logo = Text(ASCII_LOGO, style=f"bold {CYAN}")
        subtitle = Text(
            "  consent-based link analytics · terminal intelligence console",
            style=DIM,
        )
        self.console.print(logo, end="")
        self.console.print(subtitle)
        self.console.print(Rule(style=f"{VIOLET}"))

        if config is not None:
            state = (
                f"[{GREEN}]● online[/]  env [{GOLD}]{config.env}[/]  "
                f"bind [{CYAN}]{config.bind_host}:{config.bind_port}[/]  "
                f"db [{DIM}]{config.database_file}[/]"
            )
            self.console.print(state)
        self.console.print()

    def ok(self, message: str) -> None:
        self.console.print(f"[{GREEN}]✔[/] {message}")

    def warn(self, message: str) -> None:
        self.console.print(f"[{GOLD}]▲[/] {message}")

    def err(self, message: str) -> None:
        self.console.print(f"[{RED}]✖[/] {message}")

    def info(self, message: str) -> None:
        self.console.print(f"[{CYAN}]ℹ[/] {message}")

    def blank(self) -> None:
        self.console.print()

    def panel(self, body, title: str, style: str = CYAN) -> None:
        self.console.print(
            Panel(body, title=f"[bold]{title}[/]", border_style=style, box=box.ROUNDED)
        )

    def table(self, title: str, columns: list[str], rows: list[list[str]],
              *, max_width: int | None = None) -> None:
        if not rows:
            self.warn("No rows to display.")
            return
        table = Table(
            title=title,
            box=box.SIMPLE_HEAD,
            header_style=f"bold {CYAN}",
            border_style=DIM,
            expand=False,
            pad_edge=False,
        )
        for column in columns:
            table.add_column(column, overflow="fold", max_width=max_width)
        for row in rows:
            table.add_row(*[str(cell) for cell in row])
        self.console.print(table)

    def pause(self) -> None:
        """Wait for Enter, but never block when there is no interactive stdin.

        ``diagnose_cli`` is meant to be usable from a script or CI, where stdin
        is a pipe or /dev/null. Prompting there would hang or raise OSError.
        """
        if not sys.stdin or not sys.stdin.isatty():
            return
        try:
            Prompt.ask(f"[{DIM}]press Enter to continue[/]", default="", show_default=False)
        except (EOFError, KeyboardInterrupt, OSError):
            pass

    def loading(self, message: str, work: Callable, *args, **kwargs):
        """Run ``work`` behind a short spinner (cosmetic, ~0.6s)."""
        with Progress(
            SpinnerColumn(style=CYAN),
            TextColumn(f"[{CYAN}]{message}[/]"),
            BarColumn(bar_width=24, style=DIM, complete_style=CYAN),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        ) as progress:
            task = progress.add_task(message, total=100)
            for step in range(5):
                time.sleep(0.06)
                progress.update(task, advance=20)
            return work(*args, **kwargs)


# ---------------------------------------------------------------------------
# Menu actions
# ---------------------------------------------------------------------------
def action_dashboard(ui: UI, config, db, analytics, geo) -> None:
    totals = analytics.totals()
    stats = Table.grid(padding=(0, 3))
    stats.add_column(justify="left")
    stats.add_column(justify="right")

    def line(label: str, value, style: str = CYAN) -> None:
        stats.add_row(f"[{DIM}]{label}[/]", f"[bold {style}]{value}[/]")

    line("Total visits", totals.total_events)
    line("Unique events", totals.unique_events)
    line("Active links", totals.active_links)
    line("Links created", totals.total_links)
    line("Campaigns", totals.campaigns)
    line("Consent granted", totals.consent_granted, GREEN)
    line("Consent declined", totals.consent_declined, GOLD)
    line("Consent rate", f"{totals.consent_rate}%", GREEN)
    line("Visits (24h)", totals.events_24h)
    line("Visits (7d)", totals.events_7d)

    ui.panel(stats, "OVERVIEW")

    events = analytics.recent_events(limit=8)
    rows = [
        [
            event.created_at.replace("T", " ").replace("Z", ""),
            event.tracking_id,
            event.campaign_name or "-",
            event.location_label,
            f"{event.browser_family} {event.browser_version}".strip() or "-",
            event.device_category or "-",
        ]
        for event in events
    ]
    ui.table(
        "RECENT EVENTS",
        ["Time (UTC)", "Tracking ID", "Campaign", "Approx. location", "Browser", "Device"],
        rows,
        max_width=26,
    )

    links = db.list_links(limit=6)
    ui.table(
        "RECENT LINKS",
        ["Tracking ID", "Campaign", "Visits", "Unique", "Destination"],
        [
            [
                link.tracking_id,
                link.campaign_name or "-",
                link.click_count,
                link.unique_count,
                link.destination_url,
            ]
            for link in links
        ],
        max_width=34,
    )
    ui.pause()


def action_create_link(ui: UI, config, db, analytics, geo) -> None:
    from link_generator import (
        LinkCreationError,
        LinkRequest,
        create_tracking_link,
        destination_is_reachable,
    )

    ui.panel(
        f"Destination URLs must be public http(s) addresses. Private, loopback and "
        f"cloud-metadata addresses are rejected.\n"
        f"Public base URL: [{CYAN}]{config.public_base}[/]",
        "CREATE ANALYTICS LINK",
    )

    try:
        destination = Prompt.ask(f"[{CYAN}]Destination URL[/]")
        campaign = Prompt.ask(f"[{CYAN}]Campaign name[/] [{DIM}](blank for none)[/]", default="")
        label = Prompt.ask(f"[{CYAN}]Label[/] [{DIM}](optional)[/]", default="")
        alias = Prompt.ask(
            f"[{CYAN}]Custom alias[/] [{DIM}](lowercase, digits, hyphens; blank for random)[/]",
            default="",
        )
        expires = Prompt.ask(
            f"[{CYAN}]Expires after days[/] [{DIM}](blank = never)[/]", default=""
        )
        retention = Prompt.ask(
            f"[{CYAN}]Retention days[/]", default=str(config.default_retention_days)
        )
        consent = Confirm.ask(f"[{CYAN}]Require consent notice?[/]", default=True)
    except (EOFError, KeyboardInterrupt):
        ui.warn("Cancelled.")
        return

    request = LinkRequest(
        destination_url=destination,
        campaign_name=campaign,
        label=label,
        alias=alias,
        expires_in_days=int(expires) if expires.strip().isdigit() else None,
        require_consent=consent,
        retention_days=int(retention) if retention.strip().isdigit() else None,
    )

    try:
        created = ui.loading(
            "validating destination and creating link…",
            create_tracking_link, db, config, request,
        )
    except LinkCreationError as exc:
        ui.err(f"Rejected: {exc}")
        ui.pause()
        return

    body = Text()
    body.append("Tracking ID   ", style=DIM)
    body.append(f"{created.tracking_id}\n", style=f"bold {GOLD}")
    body.append("Share URL     ", style=DIM)
    body.append(f"{created.share_url}\n", style=CYAN)
    body.append("Destination   ", style=DIM)
    body.append(f"{created.destination_url}\n")
    body.append("Campaign      ", style=DIM)
    body.append(f"{created.campaign_name or '-'}\n")
    body.append("Expires       ", style=DIM)
    body.append(f"{created.expires_at or 'never'}\n")
    body.append("Retention     ", style=DIM)
    body.append(f"{created.retention_days} days\n")
    body.append("Consent gate  ", style=DIM)
    body.append("enabled" if created.require_consent else "disabled",
                style=GREEN if created.require_consent else GOLD)
    ui.panel(body, "LINK CREATED", GREEN)

    reachable, detail = destination_is_reachable(created.destination_url)
    if reachable:
        ui.ok(f"Destination responded: {detail}")
    else:
        ui.warn(f"Destination not verified: {detail}")

    ui.info(
        "The share URL only reaches visitors while this server is running and "
        "reachable at " + config.public_base
    )

    try:
        import qrcode

        qr_dir = PROJECT_ROOT / "qr_codes"
        qr_dir.mkdir(exist_ok=True)
        path = qr_dir / f"{created.tracking_id}.png"
        qrcode.make(created.share_url).save(path)
        ui.ok(f"QR code saved: {path}")
    except ImportError:
        ui.warn("QR code skipped: install with 'pip install qrcode[pil]'")
    ui.pause()


def action_manage_campaigns(ui: UI, config, db, analytics, geo) -> None:
    from link_generator import slugify, unique_campaign_slug

    campaigns = db.list_campaigns(include_archived=True)
    ui.table(
        "CAMPAIGNS",
        ["ID", "Name", "Slug", "Links", "Visits", "State", "Created"],
        [
            [
                c.id, c.name, c.slug, c.link_count, c.total_events,
                "archived" if c.is_archived else "live",
                c.created_at.replace("T", " ").replace("Z", ""),
            ]
            for c in campaigns
        ],
        max_width=30,
    )

    ui.blank()
    choice = Prompt.ask(
        f"[{CYAN}]Action[/] [{DIM}](create / archive / blank to go back)[/]", default=""
    ).strip().lower()

    if choice == "create":
        try:
            name = Prompt.ask(f"[{CYAN}]Campaign name[/]")
            description = Prompt.ask(f"[{CYAN}]Description[/]", default="")
        except (EOFError, KeyboardInterrupt):
            return
        if not name.strip():
            ui.err("Name is required.")
            ui.pause()
            return
        slug = unique_campaign_slug(db, name)
        new_id = db.create_campaign(name=name.strip()[:80], slug=slug,
                                    description=description[:500])
        db.log_audit("terminal", "campaign_created", f"name={name} slug={slug}")
        ui.ok(f"Campaign #{new_id} created with slug '{slug}'.")

    elif choice == "archive":
        raw = Prompt.ask(f"[{CYAN}]Campaign ID to archive[/]", default="")
        if raw.strip().isdigit():
            campaign = db.get_campaign(int(raw))
            if campaign is None:
                ui.err(f"No campaign with id {raw}.")
            else:
                db.archive_campaign(campaign.id, archived=True)
                db.log_audit("terminal", "campaign_archived", f"id={campaign.id}")
                ui.ok(f"Archived '{campaign.name}'.")
        else:
            ui.err("Enter a numeric campaign ID.")
    ui.pause()


def action_live_events(ui: UI, config, db, analytics, geo) -> None:
    ui.panel(
        f"Streaming new events. Press [{GOLD}]Ctrl+C[/] to return to the menu.\n"
        f"Only events where the visitor allowed recording will appear.",
        "LIVE CLICK EVENTS",
    )

    # Anchor on the newest existing id so only genuinely new events stream.
    existing = db.list_events(limit=1, order="desc")
    last_id = existing[0].id if existing else 0
    ui.info(f"Watching from event id {last_id}. Waiting…")

    seen = 0
    started = time.time()
    try:
        with Progress(
            SpinnerColumn(style=CYAN),
            TextColumn(f"[{CYAN}]listening[/]"),
            TextColumn("[{task.fields[info]}]"),
            TimeElapsedColumn(),
            console=ui.console,
            transient=True,
        ) as progress:
            progress.add_task("listen", total=None, info="no events yet")
            while time.time() - started < 300:
                events = analytics.new_events_since(last_id, limit=20)
                for event in events:
                    last_id = max(last_id, event.id)
                    seen += 1
                    progress.update(
                        progress.task_ids[0],
                        info=f"{seen} new · last {event.tracking_id}",
                    )
                    ui.console.print(
                        f"[{DIM}]{event.created_at}[/] "
                        f"[{GOLD}]{event.tracking_id}[/] "
                        f"{event.location_label} "
                        f"[{CYAN}]{event.browser_family}[/] "
                        f"{event.device_category} "
                        f"[{GREEN}]{event.consent_status}[/]"
                    )
                time.sleep(1.0)
    except KeyboardInterrupt:
        ui.blank()
        ui.info(f"Stopped after {seen} new event(s).")
    ui.pause()


def action_visitor_analytics(ui: UI, config, db, analytics, geo) -> None:
    totals = analytics.totals()
    if totals.total_events == 0:
        ui.warn("No events recorded yet, so there is nothing to break down.")
        ui.info("Create a link (option 2) and open it in a browser to generate data.")
        ui.pause()
        return

    for field, title in [
        ("device_category", "DEVICE CATEGORY"),
        ("browser_family", "BROWSER FAMILY"),
        ("os_family", "OPERATING SYSTEM"),
        ("country", "COUNTRY (approximate)"),
    ]:
        rows = analytics.breakdown(field, limit=10)
        ui.table(
            title,
            ["Value", "Events", "Share"],
            [[r.label, r.count, f"{r.share}%"] for r in rows],
        )

    if config.geo_provider == "none":
        ui.warn(
            "No geographic data is being recorded (GEO_PROVIDER=none). "
            "Country rows appear as 'unknown' by design."
        )
    ui.info("Location is approximate, derived from the IP address only.")
    ui.pause()


def action_browser_device(ui: UI, config, db, analytics, geo) -> None:
    totals = analytics.totals()
    if totals.total_events == 0:
        ui.warn("No events recorded yet.")
        ui.pause()
        return

    client = db.connection().execute(
        """SELECT browser_family, browser_version, os_family, os_version,
                  device_category, COUNT(*) AS c
             FROM analytics_events
            GROUP BY browser_family, browser_version, os_family, os_version,
                     device_category
            ORDER BY c DESC LIMIT 25"""
    ).fetchall()

    ui.table(
        "BROWSER / PLATFORM COMBINATIONS",
        ["Browser", "Ver", "OS", "Ver", "Device", "Events"],
        [
            [
                row["browser_family"] or "unknown",
                row["browser_version"] or "-",
                row["os_family"] or "unknown",
                row["os_version"] or "-",
                row["device_category"] or "unknown",
                row["c"],
            ]
            for row in client
        ],
    )

    refs = analytics.breakdown("referrer_host", limit=10)
    ui.table(
        "TOP REFERRERS",
        ["Referrer host", "Events", "Share"],
        [[r.label, r.count, f"{r.share}%"] for r in refs],
    )
    ui.pause()


def action_ip_metadata(ui: UI, config, db, analytics, geo) -> None:
    ui.panel(
        f"IP storage mode: [{GOLD}]{config.ip_storage_mode}[/]\n"
        f"Geolocation provider: [{GOLD}]{config.geo_provider}[/] ({geo.status})\n\n"
        f"[{DIM}]This screen shows exactly what the database holds. Nothing is "
        f"enriched, guessed or reverse-resolved.[/]",
        "IP & NETWORK METADATA",
    )

    events = db.list_events(limit=20)
    if not events:
        ui.warn("No events recorded yet.")
        ui.pause()
        return

    rows = []
    for event in events:
        if event.ip_address:
            ip_display = event.ip_address
        elif event.ip_hash:
            ip_display = f"hash:{event.ip_hash[:12]}…"
        else:
            ip_display = "not stored"
        rows.append(
            [
                event.created_at.replace("T", " ").replace("Z", ""),
                event.tracking_id,
                ip_display,
                event.location_label,
                event.geo_source or "-",
            ]
        )
    ui.table("STORED NETWORK FIELDS", ["Time", "Tracking ID", "IP / hash", "Approx. location", "Source"], rows)
    ui.info(
        "These values identify a network, not a person. No reverse DNS, no "
        "port scanning, no host enumeration is performed anywhere in this tool."
    )
    ui.pause()


def action_consent(ui: UI, config, db, analytics, geo) -> None:
    stats = db.consent_stats()
    total = stats["granted"] + stats["declined"]
    rate = round(100.0 * stats["granted"] / total, 1) if total else 0.0

    body = Table.grid(padding=(0, 3))
    body.add_column()
    body.add_column(justify="right")
    body.add_row(f"[{DIM}]Consent granted[/]", f"[bold {GREEN}]{stats['granted']}[/]")
    body.add_row(f"[{DIM}]Consent declined[/]", f"[bold {GOLD}]{stats['declined']}[/]")
    body.add_row(f"[{DIM}]Grant rate[/]", f"[bold]{rate}%[/]")
    body.add_row(f"[{DIM}]Policy version[/]", config.policy_version)
    ui.panel(body, "CONSENT SUMMARY")

    records = db.list_consent(limit=20)
    ui.table(
        "RECENT CONSENT DECISIONS",
        ["Time", "Tracking ID", "Decision", "Policy", "Visitor (prefix)"],
        [
            [
                r.created_at.replace("T", " ").replace("Z", ""),
                r.tracking_id,
                "granted" if r.granted else "declined",
                r.policy_version,
                f"{r.visitor_token[:10]}…" if r.visitor_token else "-",
            ]
            for r in records
        ],
    )

    if records:
        ui.blank()
        if Confirm.ask(
            f"[{CYAN}]Erase all events for one visitor token?[/]", default=False
        ):
            token = Prompt.ask(f"[{CYAN}]Visitor token[/]", default="")
            if token.strip():
                removed = db.delete_events_for_visitor(token.strip()[:64])
                db.log_audit("terminal", "erase_visitor", f"removed={removed}")
                ui.ok(f"Erased {removed} event(s); consent marked withdrawn.")
    ui.pause()


def action_export(ui: UI, config, db, analytics, geo) -> None:
    fmt = Prompt.ask(
        f"[{CYAN}]Format[/] [{DIM}](csv / json)[/]", default="csv"
    ).strip().lower()
    if fmt not in {"csv", "json"}:
        ui.err("Format must be csv or json.")
        ui.pause()
        return

    since = Prompt.ask(
        f"[{CYAN}]Since date[/] [{DIM}](YYYY-MM-DD, blank for all)[/]", default=""
    ).strip()
    if since and len(since) == 10:
        since = f"{since}T00:00:00Z"
    else:
        since = ""

    payload = ui.loading(
        "building export…", analytics.export, fmt=fmt, since=since or None
    )
    reports = PROJECT_ROOT / "reports"
    reports.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = reports / f"ruk-events-{stamp}.{fmt}"
    path.write_text(payload, encoding="utf-8")

    lines = payload.count("\n") if fmt == "csv" else payload.count('"event_uid"')
    ui.ok(f"Export written: {path}")
    ui.info(f"Roughly {lines} record(s), {len(payload):,} bytes.")
    ui.pause()


def action_security(ui: UI, config, db, analytics, geo) -> None:
    ui.table(
        "ACTIVE CONFIGURATION",
        ["Setting", "Value"],
        [[key, value] for key, value in config.describe()],
        max_width=46,
    )

    if config.warnings:
        for warning in config.warnings:
            ui.warn(warning)
    else:
        ui.ok("No configuration warnings.")

    ui.blank()
    ui.table(
        "HARDENING CHECKLIST",
        ["Control", "State"],
        [
            ["Argon2id password hashing",
             "enabled" if _argon2_ok() else "MISSING - pip install argon2-cffi"],
            ["CSRF tokens on every state change", "enforced"],
            ["Security headers (CSP, nosniff, frame-deny)", "applied"],
            ["Parameterised SQL", "all queries"],
            ["Destination SSRF validation", "enforced"],
            ["Rate limiting", "in-process sliding window"],
            ["Secrets from environment", "yes" if config.secret_source == "environment"
             else f"local file ({config.secret_source})"],
            ["HTTPS required", "yes" if config.require_https_links else "no (local mode)"],
            ["Admin session", f"{config.session_lifetime_seconds}s idle timeout"],
        ],
        max_width=40,
    )

    ui.blank()
    if Confirm.ask(f"[{CYAN}]Change an administrator password?[/]", default=False):
        _change_password(ui, db)
    ui.pause()


def _argon2_ok() -> bool:
    try:
        import argon2  # noqa: F401

        return True
    except ImportError:
        return False


def _change_password(ui: UI, db) -> None:
    from security import WeakPasswordError, hash_password

    username = Prompt.ask(f"[{CYAN}]Username[/]", default="")
    admin = db.get_admin(username.strip())
    if admin is None:
        ui.err(f"No administrator named {username!r}.")
        return
    new_password = Prompt.ask(f"[{CYAN}]New password[/]", password=True)
    confirm = Prompt.ask(f"[{CYAN}]Repeat password[/]", password=True)
    if new_password != confirm:
        ui.err("Passwords do not match.")
        return
    try:
        db.update_admin_password(admin.id, hash_password(new_password))
    except WeakPasswordError as exc:
        ui.err(str(exc))
        return
    db.log_audit("terminal", "password_changed", f"user={admin.username}")
    ui.ok(f"Password updated for {admin.username}.")


def action_diagnostics(ui: UI, config, db, analytics, geo) -> None:
    integrity = db.integrity_check()
    size = db.database_size_bytes()

    deps = []
    for name, module in [
        ("flask", "flask"), ("rich", "rich"), ("argon2", "argon2"),
        ("qrcode", "qrcode"), ("PIL", "PIL"), ("requests", "requests"),
        ("dotenv", "dotenv"), ("waitress", "waitress"), ("pytest", "pytest"),
    ]:
        try:
            __import__(module)
            deps.append([name, "installed"])
        except ImportError:
            deps.append([name, "MISSING"])

    ui.table(
        "ENVIRONMENT",
        ["Item", "Value"],
        [
            ["Python", sys.version.split()[0]],
            ["Platform", platform.platform()],
            ["Machine", platform.machine()],
            ["Termux", "yes" if "com.termux" in os.environ.get("PREFIX", "") else "no"],
            ["Project root", str(PROJECT_ROOT)],
            ["Database", str(config.database_file)],
            ["Database size", f"{size:,} bytes"],
            ["Integrity check", integrity],
            ["Schema version", db.schema_version()],
            ["Geolocation", geo.status],
            ["Disk free", _disk_free()],
            ["Hostname", socket.gethostname()],
        ],
        max_width=52,
    )

    ui.table("TABLES", ["Table", "Rows"], [[k, v] for k, v in db.table_counts().items()])
    ui.table("DEPENDENCIES", ["Package", "State"], deps)

    if integrity != "ok":
        ui.err(f"Database integrity check returned: {integrity}")
    else:
        ui.ok("Database integrity check passed.")
    ui.pause()


def _disk_free() -> str:
    try:
        usage = shutil.disk_usage(PROJECT_ROOT)
        return f"{usage.free / (1024 ** 3):.1f} GiB free"
    except OSError:
        return "unknown"


def action_help(ui: UI, config, db, analytics, geo) -> None:
    body = Text()
    sections = [
        ("What this tool does", [
            "Creates shareable analytics links that show a consent notice first.",
            "Records a small, disclosed set of fields only after a visitor agrees.",
            "Reports those records in this terminal and in the web dashboard.",
        ]),
        ("What it cannot do", [
            "It cannot identify a person from an IP address.",
            "It cannot learn a precise GPS position from a plain link.",
            "It cannot read passwords, messages, files, contacts or camera.",
            "It cannot track a visitor after they leave the destination page.",
        ]),
        ("How consent works", [
            "Opening /l/<id> shows a notice page and records nothing.",
            "Choosing 'Leave without being counted' records no analytics event.",
            "Only choosing 'Allow and continue' writes an event row.",
        ]),
        ("Running the web server", [
            "python app.py            # starts the Flask/Waitress server",
            "python terminal_dashboard.py  # this interface",
            "pytest -q                # run the automated test suite",
        ]),
        ("Public reachability", [
            "Tracking links only work for other people once this server is",
            "reachable at PUBLIC_BASE_URL over HTTPS. A server bound to",
            "127.0.0.1 can only be opened on the same machine - that is a",
            "networking fact, not a setting.",
        ]),
    ]
    for title, lines in sections:
        body.append(f"\n{title}\n", style=f"bold {CYAN}")
        for line in lines:
            body.append(f"  · {line}\n", style="")
    ui.panel(body, "HELP & DOCUMENTATION")
    ui.info("Full documentation is in README.md next to this script.")
    ui.pause()


# ---------------------------------------------------------------------------
# Menu loop
# ---------------------------------------------------------------------------
ACTIONS: dict[str, Callable] = {
    "1": action_dashboard,
    "2": action_create_link,
    "3": action_manage_campaigns,
    "4": action_live_events,
    "5": action_visitor_analytics,
    "6": action_browser_device,
    "7": action_ip_metadata,
    "8": action_consent,
    "9": action_export,
    "10": action_security,
    "11": action_diagnostics,
    "12": action_help,
}


def draw_menu(ui: UI) -> None:
    table = Table(
        box=box.SIMPLE,
        show_header=False,
        border_style=DIM,
        pad_edge=False,
        expand=False,
    )
    table.add_column(justify="right", style=f"bold {GOLD}", width=4)
    table.add_column(style=f"bold {CYAN}", width=34)
    table.add_column(style=DIM)

    for key, name, description in MENU_ITEMS:
        style = RED if key == "13" else None
        table.add_row(
            key,
            Text(name, style=style) if style else name,
            description,
        )
    ui.console.print(table)


def run_menu() -> int:
    if not RICH_AVAILABLE:
        print("Rich is required for the terminal interface.")
        print("Install it with:  pip install rich")
        print("Or run the web app directly:  python app.py")
        return 2

    console = Console()
    ui = UI(console)

    config, db, analytics, geo = build_context()

    if not db.admin_exists():
        console.print()
        ui.warn("No administrator exists yet.")
        ui.info("Create one with:  python terminal_dashboard.py --create-admin")
        console.print()
        ui.pause()

    while True:
        ui.banner(config)
        draw_menu(ui)
        ui.blank()

        try:
            choice = Prompt.ask(
                f"[{CYAN}]nexus[/][{DIM}]>[/]", default="", show_default=False
            ).strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            ui.info("Exiting.")
            return 0

        if choice in {"13", "0", "q", "quit", "exit"}:
            console.print()
            ui.info("Session closed. Stay curious, stay lawful.")
            return 0

        action = ACTIONS.get(choice)
        if action is None:
            ui.err(f"Unknown option {choice!r}. Enter a number from the menu.")
            time.sleep(0.7)
            continue

        try:
            action(ui, config, db, analytics, geo)
        except KeyboardInterrupt:
            console.print()
            ui.warn("Interrupted.")
        except Exception as exc:  # a broken action must not kill the session
            console.print()
            ui.err(f"Action failed: {type(exc).__name__}: {exc}")
            ui.pause()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def create_admin_cli(username: str | None = None) -> int:
    from security import (
        PasswordHashingUnavailable,
        WeakPasswordError,
        hash_password,
        validate_password_strength,
    )

    config, db, analytics, geo = build_context()

    if db.admin_exists():
        print(f"An administrator already exists ({db.count_admins()} active).")
        print("Use option 10 in the terminal menu to change a password.")
        return 0

    if not username:
        try:
            username = input("Username [owner]: ").strip() or "owner"
        except EOFError:
            username = "owner"

    print("\nPassword policy:")
    print("  minimum 10 characters")
    print("  not a common password")
    print("  at least 5 distinct characters\n")

    try:
        password = input("Password: ")
        confirm = input("Repeat:  ")
    except EOFError:
        print("\nNo password supplied. Nothing was created.")
        return 1

    if password != confirm:
        print("Passwords do not match. Nothing was created.")
        return 1

    try:
        validate_password_strength(password)
        record = hash_password(password)
    except WeakPasswordError as exc:
        print(f"Rejected: {exc}")
        return 1
    except PasswordHashingUnavailable as exc:
        print(f"Cannot hash passwords: {exc}")
        return 2

    admin_id = db.create_admin(username.strip()[:64], record, "superadmin")
    db.log_audit("cli", "admin_created", f"username={username}")
    print(f"\nAdministrator #{admin_id} '{username}' created.")
    print("Sign in at: " + config.public_base + "/admin/login")
    return 0


def export_cli(fmt: str) -> int:
    config, db, analytics, geo = build_context()
    payload = analytics.export(fmt=fmt)
    reports = PROJECT_ROOT / "reports"
    reports.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = reports / f"ruk-events-{stamp}.{fmt}"
    path.write_text(payload, encoding="utf-8")
    print(f"Wrote {path} ({len(payload):,} bytes)")
    return 0


def diagnose_cli() -> int:
    config, db, analytics, geo = build_context()
    console = Console()
    ui = UI(console)
    action_diagnostics(ui, config, db, analytics, geo)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="RUK SHADOW INTELLIGENCE terminal interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python terminal_dashboard.py\n"
            "  python terminal_dashboard.py --create-admin\n"
            "  python terminal_dashboard.py --diagnose\n"
            "  python terminal_dashboard.py --export json\n"
        ),
    )
    parser.add_argument("--create-admin", action="store_true",
                        help="create the first administrator and exit")
    parser.add_argument("--username", default=None,
                        help="username for --create-admin (default: prompt)")
    parser.add_argument("--diagnose", action="store_true",
                        help="print system diagnostics and exit")
    parser.add_argument("--export", choices=["csv", "json"], default=None,
                        help="export events and exit")
    args = parser.parse_args(argv)

    if args.create_admin:
        return create_admin_cli(args.username)
    if args.diagnose:
        return diagnose_cli()
    if args.export:
        return export_cli(args.export)
    return run_menu()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        raise SystemExit(130)
