"""Terminal interface tests.

The module must be importable without a TTY, and its structural guarantees
(thirteen menu entries, an action for each, no hardcoded secrets) are checked
here. The menu actions themselves are covered by driving them with a captured
Rich console rather than by driving real stdin.
"""
from __future__ import annotations

import inspect
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import terminal_dashboard as term  # noqa: E402


class TestModuleShape:
    def test_ascii_logo_exists(self):
        assert term.ASCII_LOGO.strip()
        assert len(term.ASCII_LOGO.strip().splitlines()) >= 4

    def test_logo_is_wide_enough_to_read(self):
        widest = max(len(line) for line in term.ASCII_LOGO.splitlines())
        assert widest > 40

    def test_menu_items_defined(self):
        assert isinstance(term.MENU_ITEMS, list)

    def test_menu_has_thirteen_entries(self):
        assert len(term.MENU_ITEMS) == 13

    def test_menu_keys_are_sequential(self):
        keys = [key for key, _, _ in term.MENU_ITEMS]
        assert keys == [str(i) for i in range(1, 14)]

    def test_every_menu_entry_has_a_label_and_description(self):
        for key, label, description in term.MENU_ITEMS:
            assert label.strip()
            assert description.strip()

    def test_menu_tuples_are_three_wide(self):
        for item in term.MENU_ITEMS:
            assert len(item) == 3

    def test_menu_covers_required_functions(self):
        labels = " ".join(label.lower() for _, label, _ in term.MENU_ITEMS)
        for keyword in [
            "dashboard", "link", "campaign", "event", "visitor",
            "device", "ip", "consent", "export", "security",
            "diagnostic", "help", "exit",
        ]:
            assert keyword in labels, f"no menu entry mentions {keyword!r}"

    def test_last_entry_is_exit(self):
        assert term.MENU_ITEMS[-1][1].lower() == "exit"


class TestActionWiring:
    def test_actions_dict_covers_1_to_12(self):
        expected = {str(i) for i in range(1, 13)}
        assert set(term.ACTIONS) == expected

    def test_exit_is_not_an_action(self):
        """13 must be handled by the loop, not dispatched as an action."""
        assert "13" not in term.ACTIONS

    def test_every_action_is_callable(self):
        for key, action in term.ACTIONS.items():
            assert callable(action), f"action {key} is not callable"

    def test_every_action_takes_five_arguments(self):
        for key, action in term.ACTIONS.items():
            params = list(inspect.signature(action).parameters)
            assert len(params) == 5, f"action {key} has {len(params)} parameters"

    def test_action_names_match_menu_order(self):
        """Option N must dispatch to the action described by menu entry N."""
        expected_prefixes = {
            "1": "action_dashboard",
            "2": "action_create_link",
            "3": "action_manage_campaigns",
            "4": "action_live_events",
            "5": "action_visitor_analytics",
            "6": "action_browser_device",
            "7": "action_ip_metadata",
            "8": "action_consent",
            "9": "action_export",
            "10": "action_security",
            "11": "action_diagnostics",
            "12": "action_help",
        }
        for key, name in expected_prefixes.items():
            assert term.ACTIONS[key].__name__ == name


class TestRenderingHelpers:
    def test_ui_class_exposes_the_message_levels(self):
        for method in ["ok", "warn", "err", "info", "banner", "panel", "table", "pause"]:
            assert hasattr(term.UI, method), f"UI has no {method}()"

    def test_ui_methods_are_callables(self):
        for method in ["ok", "warn", "err", "info"]:
            assert callable(getattr(term.UI, method))

    def test_loading_wrapper_returns_the_work_result(self):
        from rich.console import Console

        ui = term.UI(Console(file=None, width=80))
        assert ui.loading("working", lambda a, b: a + b, 2, 3) == 5

    def test_loading_propagates_exceptions(self):
        from rich.console import Console

        ui = term.UI(Console(file=None, width=80))

        def boom():
            raise RuntimeError("expected")

        with pytest.raises(RuntimeError):
            ui.loading("working", boom)


class TestContextBuilder:
    def test_build_context_returns_four_things(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SECRET_KEY", "k" * 64)
        monkeypatch.setenv("RUK_ENV", "development")
        monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "t.db"))
        monkeypatch.setenv("PUBLIC_BASE_URL", "http://127.0.0.1:8000")
        monkeypatch.setenv("GEO_PROVIDER", "none")

        config, db, analytics, geo = term.build_context()
        assert config.database_path.endswith("t.db")
        assert db is not None
        assert analytics is not None
        assert geo.provider == "none"
        db.close()

    def test_build_context_rejects_bad_config(self, monkeypatch):
        monkeypatch.setenv("SECRET_KEY", "short")
        monkeypatch.setenv("RUK_ENV", "development")
        with pytest.raises(SystemExit):
            term.build_context()


class TestSecretHygiene:
    SOURCE = Path(term.__file__).read_text(encoding="utf-8")

    def test_no_hardcoded_secret_key(self):
        assert not re.search(
            r"SECRET_KEY\s*=\s*['\"][A-Za-z0-9_\-]{20,}['\"]", self.SOURCE
        )

    def test_no_hardcoded_password(self):
        assert not re.search(
            r"password\s*=\s*['\"][^'\"]{6,}['\"]", self.SOURCE, re.I
        )

    def test_no_hardcoded_api_token(self):
        assert not re.search(
            r"(api_key|token)\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]", self.SOURCE, re.I
        )

    def test_does_not_claim_to_collect_forbidden_data(self):
        """The help text must not promise spyware capabilities."""
        lowered = self.SOURCE.lower()
        for claim in ["password of the visitor", "read their messages", "track gps"]:
            assert claim not in lowered


class TestCliEntryPoints:
    def test_main_exists(self):
        assert callable(term.main)

    def test_create_admin_cli_exists(self):
        assert callable(term.create_admin_cli)

    def test_export_cli_exists(self):
        assert callable(term.export_cli)

    def test_diagnose_cli_exists(self):
        assert callable(term.diagnose_cli)

    def test_help_flag_exits_zero(self, monkeypatch, capsys):
        """--help must work even with no database and no admin."""
        monkeypatch.setattr(sys, "argv", ["terminal_dashboard.py", "--help"])
        with pytest.raises(SystemExit) as excinfo:
            term.main(["--help"])
        assert excinfo.value.code == 0

    def test_diagnose_cli_runs(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SECRET_KEY", "k" * 64)
        monkeypatch.setenv("RUK_ENV", "development")
        monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "diag.db"))
        monkeypatch.setenv("PUBLIC_BASE_URL", "http://127.0.0.1:8000")
        assert term.diagnose_cli() == 0

    def test_export_cli_csv(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SECRET_KEY", "k" * 64)
        monkeypatch.setenv("RUK_ENV", "development")
        monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "exp.db"))
        monkeypatch.setenv("PUBLIC_BASE_URL", "http://127.0.0.1:8000")
        assert term.export_cli("csv") == 0
        produced = list((term.PROJECT_ROOT / "reports").glob("*.csv"))
        assert produced, "export_cli wrote no CSV file"
