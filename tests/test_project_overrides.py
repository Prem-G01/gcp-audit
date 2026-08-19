from __future__ import annotations

import pytest

from src.rules import project_overrides

PROJECT_RULES_YAML = """
version: 1
projects:
  prj-example:
    service_account_key_created: false
    iam_policy_change: true
"""


@pytest.fixture(autouse=True)
def _clear_cache():
    project_overrides._load_yaml.cache_clear()
    yield
    project_overrides._load_yaml.cache_clear()


@pytest.fixture
def config_path(tmp_path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "project_rules.yaml"
    path.write_text(PROJECT_RULES_YAML, encoding="utf-8")
    monkeypatch.setattr(project_overrides, "CONFIG_PATH", path)
    return path


def test_explicit_false_is_suppressed(config_path) -> None:
    assert project_overrides.is_rule_suppressed_for_project("service_account_key_created", "prj-example") is True


def test_explicit_true_is_not_suppressed(config_path) -> None:
    assert project_overrides.is_rule_suppressed_for_project("iam_policy_change", "prj-example") is False


def test_unlisted_rule_under_listed_project_is_not_suppressed(config_path) -> None:
    assert project_overrides.is_rule_suppressed_for_project("firewall_open_to_internet", "prj-example") is False


def test_unlisted_project_is_not_suppressed(config_path) -> None:
    assert project_overrides.is_rule_suppressed_for_project("service_account_key_created", "prj-other") is False


def test_none_project_id_is_not_suppressed(config_path) -> None:
    assert project_overrides.is_rule_suppressed_for_project("service_account_key_created", None) is False


def test_missing_file_degrades_to_not_suppressed(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(project_overrides, "CONFIG_PATH", tmp_path / "does-not-exist.yaml")
    assert project_overrides.is_rule_suppressed_for_project("service_account_key_created", "prj-example") is False


def test_malformed_yaml_degrades_to_not_suppressed(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "project_rules.yaml"
    path.write_text("projects: [this, is, a, list, not, a, mapping]", encoding="utf-8")
    monkeypatch.setattr(project_overrides, "CONFIG_PATH", path)

    assert project_overrides.is_rule_suppressed_for_project("service_account_key_created", "prj-example") is False


def test_not_a_mapping_top_level_degrades_to_not_suppressed(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "project_rules.yaml"
    path.write_text("- just\n- a\n- list\n", encoding="utf-8")
    monkeypatch.setattr(project_overrides, "CONFIG_PATH", path)

    assert project_overrides.is_rule_suppressed_for_project("service_account_key_created", "prj-example") is False
