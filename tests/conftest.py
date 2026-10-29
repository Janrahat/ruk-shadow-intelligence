"""Shared pytest fixtures.

Every test gets an isolated in-memory database and a config with fixed test
values, so no test can see another's data and none touch the real database.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Set before importing config so Config.from_env picks these up.
os.environ.setdefault("SECRET_KEY", "t" * 64)
os.environ.setdefault("ENV", "test")
os.environ.setdefault("PUBLIC_BASE_URL", "http://127.0.0.1:8000")
os.environ.setdefault("DATABASE_PATH", ":memory:")
os.environ.setdefault("IP_STORAGE_MODE", "full")
os.environ.setdefault("GEO_PROVIDER", "none")
os.environ.setdefault("REQUIRE_HTTPS_LINKS", "false")

from config import Config  # noqa: E402
from database import Database  # noqa: E402
def _build_config(**overrides) -> Config:
    """Build a Config with test-safe values.

    Field names must match ``config.Config`` exactly; ``database_file`` is a
    read-only property derived from ``database_path``.
    """
    base = dict(
        env="testing",
        secret_key="t" * 64,
        secret_source="environment",
        bind_host="127.0.0.1",
        bind_port=8000,
        public_base_url="http://127.0.0.1:8000",
        require_https_links=False,
        # An absolute path keeps the property from resolving under PROJECT_ROOT.
        database_path=":memory:",
        trust_proxy_headers=False,
        ip_storage_mode="full",
        ip_hash_salt="test-hash-salt",
        geo_provider="none",
        geo_db_path="",
        geo_http_endpoint="",
        default_retention_days=90,
        retention_sweep_seconds=3600,
        session_lifetime_seconds=3600,
        session_cookie_secure=False,
        login_rate_limit=1000,
        login_rate_window=60,
        public_rate_limit=1000,
        public_rate_window=60,
        policy_version="1.0",
        warnings=[],
    )
    base.update(overrides)
    return Config(**base)


@pytest.fixture()
def config() -> Config:
    return _build_config()


@pytest.fixture()
def db() -> Database:
    database = Database(":memory:")
    yield database
    database.close()


@pytest.fixture()
def admin(db):
    from security import hash_password

    admin_id = db.create_admin("tester", hash_password("correct horse battery staple"), "superadmin")
    return db.get_admin_by_id(admin_id)


@pytest.fixture()
def app(config, db, admin):
    from app import create_app

    application = create_app(config, db)
    application.config.update(TESTING=True)
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def authed_client(client):
    """A test client already signed in as the admin fixture user."""
    import re

    page = client.get("/admin/login")
    token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
    response = client.post(
        "/admin/login",
        data={
            "csrf_token": token,
            "username": "tester",
            "password": "correct horse battery staple",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302, "login helper failed"
    return client


def csrf_from(response) -> str:
    """Pull the CSRF token out of a rendered form."""
    import re

    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match, "no csrf_token in response"
    return match.group(1).decode()


@pytest.fixture()
def make_link(db, config):
    """Factory: create a tracking link and return it."""
    from link_generator import LinkRequest, create_tracking_link

    def _make(destination: str = "https://example.com/target", **kwargs):
        request = LinkRequest(destination_url=destination, **kwargs)
        return create_tracking_link(db, config, request)

    return _make
