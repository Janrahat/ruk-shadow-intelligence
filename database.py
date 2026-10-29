"""Persistence layer for RUK SHADOW INTELLIGENCE.

Design notes
------------
* Plain ``sqlite3`` with explicit SQL. No ORM, no string interpolation of
  values - every value travels as a bound parameter.
* One connection per thread (``threading.local``) because Flask's development
  server and Waitress both use thread pools.
* WAL mode for concurrent readers while a writer holds the lock.
* Row objects are converted to dataclasses at the boundary so callers never
  touch raw cursors.
"""
from __future__ import annotations

import csv
import io
import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from models import (
    Administrator,
    AnalyticsEvent,
    AuditEntry,
    Breakdown,
    Campaign,
    ConsentRecord,
    DashboardTotals,
    TrackingLink,
)

SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS administrators (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'admin'
                    CHECK (role IN ('admin', 'superadmin', 'viewer')),
    created_at      TEXT NOT NULL,
    last_login_at   TEXT,
    is_active       INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    failed_attempts INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS campaigns (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    is_archived INTEGER NOT NULL DEFAULT 0 CHECK (is_archived IN (0, 1))
);

CREATE TABLE IF NOT EXISTS tracking_links (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tracking_id     TEXT NOT NULL UNIQUE,
    campaign_id     INTEGER REFERENCES campaigns(id) ON DELETE SET NULL,
    destination_url TEXT NOT NULL,
    label           TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    expires_at      TEXT,
    revoked_at      TEXT,
    require_consent INTEGER NOT NULL DEFAULT 1 CHECK (require_consent IN (0, 1)),
    retention_days  INTEGER NOT NULL DEFAULT 90
);

CREATE TABLE IF NOT EXISTS consent_records (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    tracking_id    TEXT NOT NULL,
    visitor_token  TEXT NOT NULL,
    granted        INTEGER NOT NULL CHECK (granted IN (0, 1)),
    policy_version TEXT NOT NULL,
    scope          TEXT NOT NULL DEFAULT 'analytics',
    notice_sha256  TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL,
    withdrawn_at   TEXT
);

CREATE TABLE IF NOT EXISTS analytics_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_uid       TEXT NOT NULL UNIQUE,
    tracking_id     TEXT NOT NULL,
    campaign_id     INTEGER,
    created_at      TEXT NOT NULL,
    consent_status  TEXT NOT NULL DEFAULT 'granted',
    visitor_token   TEXT NOT NULL DEFAULT '',
    ip_address      TEXT NOT NULL DEFAULT '',
    ip_hash         TEXT NOT NULL DEFAULT '',
    country         TEXT NOT NULL DEFAULT '',
    region          TEXT NOT NULL DEFAULT '',
    city            TEXT NOT NULL DEFAULT '',
    geo_source      TEXT NOT NULL DEFAULT '',
    browser_family  TEXT NOT NULL DEFAULT '',
    browser_version TEXT NOT NULL DEFAULT '',
    os_family       TEXT NOT NULL DEFAULT '',
    os_version      TEXT NOT NULL DEFAULT '',
    device_category TEXT NOT NULL DEFAULT '',
    referrer_host   TEXT NOT NULL DEFAULT '',
    is_unique       INTEGER NOT NULL DEFAULT 1 CHECK (is_unique IN (0, 1))
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_events_tracking    ON analytics_events(tracking_id);
CREATE INDEX IF NOT EXISTS idx_events_created     ON analytics_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_campaign    ON analytics_events(campaign_id);
CREATE INDEX IF NOT EXISTS idx_events_consent     ON analytics_events(consent_status);
CREATE INDEX IF NOT EXISTS idx_events_visitor     ON analytics_events(visitor_token);
CREATE INDEX IF NOT EXISTS idx_events_device      ON analytics_events(device_category);
CREATE INDEX IF NOT EXISTS idx_events_country     ON analytics_events(country);
CREATE INDEX IF NOT EXISTS idx_links_tracking     ON tracking_links(tracking_id);
CREATE INDEX IF NOT EXISTS idx_links_campaign     ON tracking_links(campaign_id);
CREATE INDEX IF NOT EXISTS idx_consent_visitor    ON consent_records(visitor_token);
CREATE INDEX IF NOT EXISTS idx_consent_tracking   ON consent_records(tracking_id);
CREATE INDEX IF NOT EXISTS idx_audit_created      ON audit_log(created_at DESC);
"""


def utc_now() -> str:
    """ISO-8601 UTC timestamp, second precision, always with a Z suffix."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def utc_now_plus(days: int) -> str:
    return (
        (datetime.now(timezone.utc) + timedelta(days=days))
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class Database:
    """Thread-safe SQLite wrapper.

    ``db_path`` may be ``":memory:"`` for tests; in that case a single shared
    connection is used (an in-memory database is per-connection, so a pool
    would silently create empty databases).
    """

    def __init__(self, db_path: str | Path) -> None:
        self.path = str(db_path)
        self.is_memory = self.path == ":memory:"
        self._local = threading.local()
        self._shared: sqlite3.Connection | None = None
        self._shared_lock = threading.Lock()

        if not self.is_memory:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._bootstrap()

    # -- connection management ------------------------------------------
    def _new_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.path,
            timeout=30.0,
            check_same_thread=not self.is_memory,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        if not self.is_memory:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA busy_timeout = 30000")
        return conn

    def connection(self) -> sqlite3.Connection:
        if self.is_memory:
            with self._shared_lock:
                if self._shared is None:
                    self._shared = self._new_connection()
                return self._shared
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._new_connection()
            self._local.conn = conn
        return conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Explicit transaction; commits on success, rolls back on error."""
        conn = self.connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None
        with self._shared_lock:
            if self._shared is not None:
                self._shared.close()
                self._shared = None

    # -- schema ---------------------------------------------------------
    def _bootstrap(self) -> None:
        with self.transaction() as conn:
            conn.executescript(SCHEMA_SQL)
            conn.execute(
                "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(SCHEMA_VERSION),),
            )

    def schema_version(self) -> int:
        row = self.connection().execute(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        ).fetchone()
        return int(row["value"]) if row else 0

    # -- administrators -------------------------------------------------
    def create_admin(self, username: str, password_hash: str,
                     role: str = "admin") -> int:
        with self.transaction() as conn:
            cur = conn.execute(
                "INSERT INTO administrators(username, password_hash, role, created_at) "
                "VALUES (?, ?, ?, ?)",
                (username, password_hash, role, utc_now()),
            )
            return int(cur.lastrowid)

    def get_admin(self, username: str) -> Administrator | None:
        row = self.connection().execute(
            "SELECT * FROM administrators WHERE username = ?", (username,)
        ).fetchone()
        return Administrator.from_row(row) if row else None

    def get_admin_by_id(self, admin_id: int) -> Administrator | None:
        row = self.connection().execute(
            "SELECT * FROM administrators WHERE id = ?", (admin_id,)
        ).fetchone()
        return Administrator.from_row(row) if row else None

    def count_admins(self) -> int:
        row = self.connection().execute(
            "SELECT COUNT(*) AS c FROM administrators WHERE is_active = 1"
        ).fetchone()
        return int(row["c"])

    def admin_exists(self) -> bool:
        return self.count_admins() > 0

    def update_admin_password(self, admin_id: int, password_hash: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE administrators SET password_hash = ? WHERE id = ?",
                (password_hash, admin_id),
            )

    def record_login_success(self, admin_id: int) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE administrators SET last_login_at = ?, failed_attempts = 0 "
                "WHERE id = ?",
                (utc_now(), admin_id),
            )

    def record_login_failure(self, username: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE administrators SET failed_attempts = failed_attempts + 1 "
                "WHERE username = ?",
                (username,),
            )

    def set_admin_active(self, admin_id: int, active: bool) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE administrators SET is_active = ? WHERE id = ?",
                (1 if active else 0, admin_id),
            )

    def list_admins(self) -> list[Administrator]:
        rows = self.connection().execute(
            "SELECT * FROM administrators ORDER BY id"
        ).fetchall()
        return [Administrator.from_row(r) for r in rows]

    # -- campaigns ------------------------------------------------------
    def create_campaign(self, name: str, slug: str, description: str = "") -> int:
        with self.transaction() as conn:
            cur = conn.execute(
                "INSERT INTO campaigns(name, slug, description, created_at) "
                "VALUES (?, ?, ?, ?)",
                (name, slug, description, utc_now()),
            )
            return int(cur.lastrowid)

    def get_campaign(self, campaign_id: int) -> Campaign | None:
        row = self.connection().execute(
            """SELECT c.*,
                      (SELECT COUNT(*) FROM tracking_links l
                        WHERE l.campaign_id = c.id) AS link_count,
                      (SELECT COUNT(*) FROM analytics_events e
                        WHERE e.campaign_id = c.id) AS total_events
                 FROM campaigns c WHERE c.id = ?""",
            (campaign_id,),
        ).fetchone()
        return Campaign.from_row(row) if row else None

    def get_campaign_by_slug(self, slug: str) -> Campaign | None:
        row = self.connection().execute(
            "SELECT * FROM campaigns WHERE slug = ?", (slug,)
        ).fetchone()
        return Campaign.from_row(row) if row else None

    def list_campaigns(self, include_archived: bool = False) -> list[Campaign]:
        sql = """
            SELECT c.*,
                   (SELECT COUNT(*) FROM tracking_links l
                     WHERE l.campaign_id = c.id) AS link_count,
                   (SELECT COUNT(*) FROM analytics_events e
                     WHERE e.campaign_id = c.id) AS total_events
              FROM campaigns c
        """
        if not include_archived:
            sql += " WHERE c.is_archived = 0"
        sql += " ORDER BY c.id DESC"
        rows = self.connection().execute(sql).fetchall()
        return [Campaign.from_row(r) for r in rows]

    def archive_campaign(self, campaign_id: int, archived: bool = True) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE campaigns SET is_archived = ? WHERE id = ?",
                (1 if archived else 0, campaign_id),
            )

    # -- tracking links -------------------------------------------------
    def create_link(
        self,
        tracking_id: str,
        destination_url: str,
        campaign_id: int | None = None,
        label: str = "",
        expires_at: str | None = None,
        require_consent: bool = True,
        retention_days: int = 90,
    ) -> int:
        with self.transaction() as conn:
            cur = conn.execute(
                """INSERT INTO tracking_links
                   (tracking_id, campaign_id, destination_url, label, created_at,
                    expires_at, require_consent, retention_days)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    tracking_id,
                    campaign_id,
                    destination_url,
                    label,
                    utc_now(),
                    expires_at,
                    1 if require_consent else 0,
                    retention_days,
                ),
            )
            return int(cur.lastrowid)

    _LINK_SELECT = """
        SELECT l.*,
               COALESCE(c.name, '') AS campaign_name,
               (SELECT COUNT(*) FROM analytics_events e
                 WHERE e.tracking_id = l.tracking_id) AS click_count,
               (SELECT COUNT(*) FROM analytics_events e
                 WHERE e.tracking_id = l.tracking_id AND e.is_unique = 1) AS unique_count,
               (SELECT MAX(e.created_at) FROM analytics_events e
                 WHERE e.tracking_id = l.tracking_id) AS last_click_at
          FROM tracking_links l
          LEFT JOIN campaigns c ON c.id = l.campaign_id
    """

    def get_link(self, tracking_id: str) -> TrackingLink | None:
        row = self.connection().execute(
            self._LINK_SELECT + " WHERE l.tracking_id = ?", (tracking_id,)
        ).fetchone()
        return TrackingLink.from_row(row) if row else None

    def get_link_by_id(self, link_id: int) -> TrackingLink | None:
        row = self.connection().execute(
            self._LINK_SELECT + " WHERE l.id = ?", (link_id,)
        ).fetchone()
        return TrackingLink.from_row(row) if row else None

    def list_links(
        self,
        campaign_id: int | None = None,
        include_revoked: bool = True,
        limit: int = 200,
        offset: int = 0,
    ) -> list[TrackingLink]:
        sql = self._LINK_SELECT
        clauses: list[str] = []
        params: list[Any] = []
        if campaign_id is not None:
            clauses.append("l.campaign_id = ?")
            params.append(campaign_id)
        if not include_revoked:
            clauses.append("l.revoked_at IS NULL")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY l.id DESC LIMIT ? OFFSET ?"
        params.extend([max(1, limit), max(0, offset)])
        rows = self.connection().execute(sql, params).fetchall()
        return [TrackingLink.from_row(r) for r in rows]

    def revoke_link(self, tracking_id: str) -> bool:
        with self.transaction() as conn:
            cur = conn.execute(
                "UPDATE tracking_links SET revoked_at = ? "
                "WHERE tracking_id = ? AND revoked_at IS NULL",
                (utc_now(), tracking_id),
            )
            return cur.rowcount > 0

    def restore_link(self, tracking_id: str) -> bool:
        with self.transaction() as conn:
            cur = conn.execute(
                "UPDATE tracking_links SET revoked_at = NULL WHERE tracking_id = ?",
                (tracking_id,),
            )
            return cur.rowcount > 0

    def delete_link(self, tracking_id: str) -> bool:
        """Hard-delete a link and every event/consent row that belongs to it."""
        with self.transaction() as conn:
            conn.execute(
                "DELETE FROM analytics_events WHERE tracking_id = ?", (tracking_id,)
            )
            conn.execute(
                "DELETE FROM consent_records WHERE tracking_id = ?", (tracking_id,)
            )
            cur = conn.execute(
                "DELETE FROM tracking_links WHERE tracking_id = ?", (tracking_id,)
            )
            return cur.rowcount > 0

    def tracking_id_exists(self, tracking_id: str) -> bool:
        row = self.connection().execute(
            "SELECT 1 FROM tracking_links WHERE tracking_id = ?", (tracking_id,)
        ).fetchone()
        return row is not None

    # -- consent --------------------------------------------------------
    def record_consent(
        self,
        tracking_id: str,
        visitor_token: str,
        granted: bool,
        policy_version: str,
        scope: str = "analytics",
        notice_sha256: str = "",
    ) -> int:
        with self.transaction() as conn:
            cur = conn.execute(
                """INSERT INTO consent_records
                   (tracking_id, visitor_token, granted, policy_version, scope,
                    notice_sha256, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    tracking_id,
                    visitor_token,
                    1 if granted else 0,
                    policy_version,
                    scope,
                    notice_sha256,
                    utc_now(),
                ),
            )
            return int(cur.lastrowid)

    def latest_consent(self, visitor_token: str,
                       tracking_id: str) -> ConsentRecord | None:
        row = self.connection().execute(
            """SELECT * FROM consent_records
                WHERE visitor_token = ? AND tracking_id = ?
                ORDER BY id DESC LIMIT 1""",
            (visitor_token, tracking_id),
        ).fetchone()
        return ConsentRecord.from_row(row) if row else None

    def has_valid_consent(self, visitor_token: str, tracking_id: str,
                          policy_version: str) -> bool:
        record = self.latest_consent(visitor_token, tracking_id)
        if record is None:
            return False
        return (
            record.granted
            and record.withdrawn_at is None
            and record.policy_version == policy_version
        )

    def withdraw_consent(self, visitor_token: str, tracking_id: str) -> int:
        """Mark consent withdrawn AND purge the events it authorised.

        Withdrawing consent must actually stop the collection, so the events
        recorded under it are deleted rather than merely flagged.
        """
        now = utc_now()
        with self.transaction() as conn:
            conn.execute(
                """UPDATE consent_records SET withdrawn_at = ?
                    WHERE visitor_token = ? AND tracking_id = ?
                      AND withdrawn_at IS NULL""",
                (now, visitor_token, tracking_id),
            )
            deleted = conn.execute(
                "DELETE FROM analytics_events "
                "WHERE visitor_token = ? AND tracking_id = ?",
                (visitor_token, tracking_id),
            ).rowcount
            return int(deleted)

    def list_consent(self, limit: int = 200, offset: int = 0) -> list[ConsentRecord]:
        rows = self.connection().execute(
            "SELECT * FROM consent_records ORDER BY id DESC LIMIT ? OFFSET ?",
            (max(1, limit), max(0, offset)),
        ).fetchall()
        return [ConsentRecord.from_row(r) for r in rows]

    def consent_stats(self) -> dict[str, int]:
        rows = self.connection().execute(
            "SELECT granted, COUNT(*) AS c FROM consent_records GROUP BY granted"
        ).fetchall()
        out = {"granted": 0, "declined": 0}
        for row in rows:
            out["granted" if row["granted"] else "declined"] = int(row["c"])
        return out

    # -- analytics events ----------------------------------------------
    EVENT_COLUMNS = [
        "event_uid", "tracking_id", "campaign_id", "created_at",
        "consent_status", "visitor_token", "ip_address", "ip_hash",
        "country", "region", "city", "geo_source", "browser_family",
        "browser_version", "os_family", "os_version", "device_category",
        "referrer_host", "is_unique",
    ]

    def insert_event(self, event: dict[str, Any]) -> int:
        columns = self.EVENT_COLUMNS
        placeholders = ", ".join("?" for _ in columns)
        values = [event.get(col) for col in columns]
        values[columns.index("is_unique")] = 1 if event.get("is_unique", True) else 0
        with self.transaction() as conn:
            cur = conn.execute(
                f"INSERT INTO analytics_events ({', '.join(columns)}) "
                f"VALUES ({placeholders})",
                values,
            )
            return int(cur.lastrowid)

    _EVENT_SELECT = """
        SELECT e.*, COALESCE(c.name, '') AS campaign_name
          FROM analytics_events e
          LEFT JOIN campaigns c ON c.id = e.campaign_id
    """

    @staticmethod
    def _event_filters(
        tracking_id: str | None = None,
        campaign_id: int | None = None,
        search: str | None = None,
        device: str | None = None,
        consent: str | None = None,
        since: str | None = None,
        until: str | None = None,
        after_id: int | None = None,
    ) -> tuple[list[str], list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if tracking_id:
            clauses.append("e.tracking_id = ?")
            params.append(tracking_id)
        if campaign_id is not None:
            clauses.append("e.campaign_id = ?")
            params.append(campaign_id)
        if device:
            clauses.append("e.device_category = ?")
            params.append(device)
        if consent:
            clauses.append("e.consent_status = ?")
            params.append(consent)
        if since:
            clauses.append("e.created_at >= ?")
            params.append(since)
        if until:
            clauses.append("e.created_at <= ?")
            params.append(until)
        if after_id is not None:
            clauses.append("e.id > ?")
            params.append(after_id)
        if search:
            # LIKE with a bound parameter. Wildcards in user input are escaped
            # so a search for "100%" matches literally.
            escaped = (
                search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            )
            like = f"%{escaped}%"
            clauses.append(
                "(e.tracking_id LIKE ? ESCAPE '\\' OR e.country LIKE ? ESCAPE '\\' "
                "OR e.city LIKE ? ESCAPE '\\' OR e.browser_family LIKE ? ESCAPE '\\' "
                "OR e.device_category LIKE ? ESCAPE '\\' "
                "OR COALESCE(c.name,'') LIKE ? ESCAPE '\\')"
            )
            params.extend([like] * 6)
        return clauses, params

    def list_events(
        self,
        limit: int = 50,
        offset: int = 0,
        tracking_id: str | None = None,
        campaign_id: int | None = None,
        search: str | None = None,
        device: str | None = None,
        consent: str | None = None,
        since: str | None = None,
        until: str | None = None,
        order: str = "desc",
        after_id: int | None = None,
    ) -> list[AnalyticsEvent]:
        sql = self._EVENT_SELECT
        clauses, params = self._event_filters(
            tracking_id, campaign_id, search, device, consent, since, until, after_id
        )
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        direction = "ASC" if order.lower() == "asc" else "DESC"
        sql += f" ORDER BY e.id {direction} LIMIT ? OFFSET ?"
        params.extend([max(1, limit), max(0, offset)])
        rows = self.connection().execute(sql, params).fetchall()
        return [AnalyticsEvent.from_row(r) for r in rows]

    def count_events(
        self,
        tracking_id: str | None = None,
        campaign_id: int | None = None,
        search: str | None = None,
        device: str | None = None,
        consent: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> int:
        sql = (
            "SELECT COUNT(*) AS c FROM analytics_events e "
            "LEFT JOIN campaigns c ON c.id = e.campaign_id"
        )
        clauses, params = self._event_filters(
            tracking_id, campaign_id, search, device, consent, since, until
        )
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        row = self.connection().execute(sql, params).fetchone()
        return int(row["c"])

    def visitor_event_count(self, visitor_token: str, tracking_id: str) -> int:
        row = self.connection().execute(
            "SELECT COUNT(*) AS c FROM analytics_events "
            "WHERE visitor_token = ? AND tracking_id = ?",
            (visitor_token, tracking_id),
        ).fetchone()
        return int(row["c"])

    # -- aggregates -----------------------------------------------------
    def dashboard_totals(self) -> DashboardTotals:
        conn = self.connection()

        def scalar(sql: str, params: tuple = ()) -> int:
            row = conn.execute(sql, params).fetchone()
            return int(row["c"]) if row else 0

        consent = self.consent_stats()
        return DashboardTotals(
            total_events=scalar("SELECT COUNT(*) AS c FROM analytics_events"),
            unique_events=scalar(
                "SELECT COUNT(*) AS c FROM analytics_events WHERE is_unique = 1"
            ),
            active_links=scalar(
                "SELECT COUNT(*) AS c FROM tracking_links WHERE revoked_at IS NULL "
                "AND (expires_at IS NULL OR expires_at > ?)",
                (utc_now(),),
            ),
            total_links=scalar("SELECT COUNT(*) AS c FROM tracking_links"),
            campaigns=scalar(
                "SELECT COUNT(*) AS c FROM campaigns WHERE is_archived = 0"
            ),
            consent_granted=consent["granted"],
            consent_declined=consent["declined"],
            events_24h=scalar(
                "SELECT COUNT(*) AS c FROM analytics_events WHERE created_at >= ?",
                (utc_now_plus(-1),),
            ),
            events_7d=scalar(
                "SELECT COUNT(*) AS c FROM analytics_events WHERE created_at >= ?",
                (utc_now_plus(-7),),
            ),
        )

    GROUPABLE_FIELDS = {
        "browser_family", "os_family", "device_category", "country",
        "region", "city", "consent_status", "referrer_host", "campaign_name",
    }

    def breakdown(
        self,
        field: str,
        limit: int = 10,
        since: str | None = None,
        tracking_id: str | None = None,
    ) -> list[Breakdown]:
        """Group counts by one of a fixed allow-list of columns.

        The column name cannot be a bound parameter, so it is checked against
        an allow-list rather than being interpolated blindly.
        """
        if field not in self.GROUPABLE_FIELDS:
            raise ValueError(f"cannot group by {field!r}")

        expr = "COALESCE(c.name, '')" if field == "campaign_name" else f"e.{field}"
        sql = f"""
            SELECT CASE WHEN {expr} = '' THEN 'unknown' ELSE {expr} END AS label,
                   COUNT(*) AS count
              FROM analytics_events e
              LEFT JOIN campaigns c ON c.id = e.campaign_id
        """
        clauses: list[str] = []
        params: list[Any] = []
        if since:
            clauses.append("e.created_at >= ?")
            params.append(since)
        if tracking_id:
            clauses.append("e.tracking_id = ?")
            params.append(tracking_id)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " GROUP BY label ORDER BY count DESC LIMIT ?"
        params.append(max(1, limit))

        rows = self.connection().execute(sql, params).fetchall()
        total = sum(int(r["count"]) for r in rows) or 1
        return [
            Breakdown(
                label=r["label"] or "unknown",
                count=int(r["count"]),
                share=round(100.0 * int(r["count"]) / total, 1),
            )
            for r in rows
        ]

    def traffic_series(self, hours: int = 24, bucket_hours: int = 1) -> list[tuple[str, int]]:
        """Event counts bucketed into fixed time windows for the chart."""
        hours = max(1, min(hours, 24 * 30))
        step = max(1, min(bucket_hours, hours))
        since = utc_now_plus(-hours)
        rows = self.connection().execute(
            "SELECT created_at FROM analytics_events WHERE created_at >= ? "
            "ORDER BY created_at",
            (since,),
        ).fetchall()

        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        buckets: dict[str, int] = {}
        for i in range(hours, -1, -step):
            ts = now - timedelta(hours=i)
            buckets[ts.strftime("%Y-%m-%dT%H:00")] = 0

        for row in rows:
            dt = parse_iso(row["created_at"])
            if dt is None:
                continue
            key = dt.replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:00")
            if key in buckets:
                buckets[key] += 1
        return sorted(buckets.items())

    def campaign_performance(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.connection().execute(
            """SELECT c.id, c.name, c.slug, c.is_archived,
                      (SELECT COUNT(*) FROM tracking_links l
                        WHERE l.campaign_id = c.id) AS links,
                      (SELECT COUNT(*) FROM analytics_events e
                        WHERE e.campaign_id = c.id) AS events,
                      (SELECT COUNT(DISTINCT e.visitor_token) FROM analytics_events e
                        WHERE e.campaign_id = c.id AND e.visitor_token != '') AS visitors,
                      (SELECT MAX(e.created_at) FROM analytics_events e
                        WHERE e.campaign_id = c.id) AS last_event
                 FROM campaigns c ORDER BY events DESC LIMIT ?""",
            (max(1, limit),),
        ).fetchall()
        return [dict(r) for r in rows]

    # -- audit ----------------------------------------------------------
    def log_audit(self, actor: str, action: str, detail: str = "",
                  ip_address: str = "") -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO audit_log(created_at, actor, action, detail, ip_address) "
                "VALUES (?, ?, ?, ?, ?)",
                (utc_now(), actor, action, detail, ip_address),
            )

    def list_audit(self, limit: int = 100) -> list[AuditEntry]:
        rows = self.connection().execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (max(1, limit),)
        ).fetchall()
        return [AuditEntry.from_row(r) for r in rows]

    # -- retention ------------------------------------------------------
    def purge_expired(self, default_days: int = 90) -> dict[str, int]:
        """Delete events past their retention window, plus old consent rows.

        Returns a per-table count of removed rows so the caller can log what
        actually happened rather than assuming.
        """
        with self.transaction() as conn:
            expired = conn.execute(
                """DELETE FROM analytics_events
                    WHERE tracking_id IN (
                        SELECT tracking_id FROM tracking_links
                         WHERE expires_at IS NOT NULL AND expires_at <= ?)""",
                (utc_now(),),
            ).rowcount

            aged = conn.execute(
                "DELETE FROM analytics_events WHERE created_at < ?",
                (utc_now_plus(-default_days),),
            ).rowcount

            consent = conn.execute(
                "DELETE FROM consent_records WHERE created_at < ?",
                (utc_now_plus(-max(default_days * 2, 7)),),
            ).rowcount

            return {
                "expired_link_events": int(expired),
                "aged_events": int(aged),
                "aged_consent": int(consent),
            }

    def delete_all_events(self, tracking_id: str | None = None) -> int:
        """Right-to-erasure: wipe events (optionally for one link only)."""
        with self.transaction() as conn:
            if tracking_id:
                cur = conn.execute(
                    "DELETE FROM analytics_events WHERE tracking_id = ?",
                    (tracking_id,),
                )
            else:
                cur = conn.execute("DELETE FROM analytics_events")
            return int(cur.rowcount)

    def delete_events_for_visitor(self, visitor_token: str) -> int:
        with self.transaction() as conn:
            cur = conn.execute(
                "DELETE FROM analytics_events WHERE visitor_token = ?",
                (visitor_token,),
            )
            conn.execute(
                "UPDATE consent_records SET withdrawn_at = ? "
                "WHERE visitor_token = ? AND withdrawn_at IS NULL",
                (utc_now(), visitor_token),
            )
            return int(cur.rowcount)

    # -- export ---------------------------------------------------------
    EVENT_EXPORT_FIELDS = [
        "id", "event_uid", "tracking_id", "campaign_name", "created_at",
        "consent_status", "ip_address", "ip_hash", "country", "region", "city",
        "geo_source", "browser_family", "browser_version", "os_family",
        "os_version", "device_category", "referrer_host", "is_unique",
    ]

    def export_events(
        self,
        fmt: str = "csv",
        limit: int = 10_000,
        since: str | None = None,
        tracking_id: str | None = None,
    ) -> str:
        """Serialise events as CSV or JSON text."""
        events = self.list_events(
            limit=limit, since=since, tracking_id=tracking_id, order="asc"
        )
        records: list[dict[str, Any]] = []
        for event in events:
            row: dict[str, Any] = {}
            for field_name in self.EVENT_EXPORT_FIELDS:
                value = getattr(event, field_name, "")
                if field_name == "is_unique":
                    value = bool(value)
                row[field_name] = value
            records.append(row)

        if fmt == "json":
            return json.dumps(
                {
                    "generated_at": utc_now(),
                    "record_count": len(records),
                    "fields": self.EVENT_EXPORT_FIELDS,
                    "events": records,
                },
                indent=2,
            )
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=self.EVENT_EXPORT_FIELDS)
        writer.writeheader()
        writer.writerows(records)
        return buffer.getvalue()

    # -- diagnostics ----------------------------------------------------
    COUNTABLE_TABLES = (
        "administrators", "campaigns", "tracking_links",
        "consent_records", "analytics_events", "audit_log",
    )

    def table_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for table in self.COUNTABLE_TABLES:
            row = self.connection().execute(
                f"SELECT COUNT(*) AS c FROM {table}"  # noqa: S608 - fixed list
            ).fetchone()
            out[table] = int(row["c"])
        return out

    def integrity_check(self) -> str:
        row = self.connection().execute("PRAGMA integrity_check").fetchone()
        return str(row[0]) if row else "unknown"

    def database_size_bytes(self) -> int:
        if self.is_memory:
            return 0
        try:
            return Path(self.path).stat().st_size
        except OSError:
            return 0
