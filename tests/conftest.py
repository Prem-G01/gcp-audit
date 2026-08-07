from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.email_template import _load_yaml
from src.senders import gmail_sender

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def load_fixture():
    def _load(name: str) -> dict:
        with (FIXTURES_DIR / name).open("r", encoding="utf-8") as handle:
            return json.load(handle)

    return _load


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep retry-backoff tests fast -- no test should actually sleep."""
    monkeypatch.setattr(gmail_sender.time, "sleep", lambda _seconds: None)


@pytest.fixture(autouse=True)
def _clear_routing_config_cache() -> None:
    """Routing config is cached by path; avoid leaking state across tests."""
    _load_yaml.cache_clear()
    yield
    _load_yaml.cache_clear()


@pytest.fixture
def mailer_config() -> gmail_sender.MailerConfig:
    return gmail_sender.MailerConfig(
        delegated_sa="test-sa@test-project.iam.gserviceaccount.com",
        sender="alerts@example.com",
        max_attempts=3,
    )


ROUTING_YAML = """
severity_styles:
  CRITICAL:
    accent: "#ef4444"
    tint: "#fef2f2"
  HIGH:
    accent: "#f97316"
    tint: "#fff7ed"
  MEDIUM:
    accent: "#3b82f6"
    tint: "#eff6ff"
  LOW:
    accent: "#64748b"
    tint: "#f8fafc"

recipients:
  CRITICAL:
    - oncall@example.com
  default:
    - team@example.com
"""


@pytest.fixture
def routing_yaml_path(tmp_path):
    path = tmp_path / "routing.yaml"
    path.write_text(ROUTING_YAML, encoding="utf-8")
    return path
