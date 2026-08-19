from __future__ import annotations

import pytest

from src.rules import project_overrides

PROJECT_RULES_YAML = """
version: 1
folders:
  "111":
    service_account_key_created: false
    firewall_open_to_internet: false
    iam_policy_change: false
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


# --- Folder-level suppression -----------------------------------------------


def test_folder_level_false_suppresses_unlisted_project(config_path) -> None:
    assert (
        project_overrides.is_rule_suppressed_for_project(
            "service_account_key_created", "prj-brand-new", asset_ancestors=["folders/111"]
        )
        is True
    )


def test_folder_level_false_suppresses_new_project_covering_the_ask(config_path) -> None:
    """A project not present anywhere in the config, sitting under a
    suppressed folder, must still be silenced -- the whole point of the
    folder tier.
    """
    assert (
        project_overrides.is_rule_suppressed_for_project(
            "firewall_open_to_internet", "prj-created-tomorrow", asset_ancestors=["folders/111", "organizations/999"]
        )
        is True
    )


def test_folder_level_unlisted_rule_is_not_suppressed(config_path) -> None:
    assert (
        project_overrides.is_rule_suppressed_for_project(
            "org_policy_modified", "prj-brand-new", asset_ancestors=["folders/111"]
        )
        is False
    )


def test_folder_not_matching_any_ancestor_is_not_suppressed(config_path) -> None:
    assert (
        project_overrides.is_rule_suppressed_for_project(
            "service_account_key_created", "prj-brand-new", asset_ancestors=["folders/222"]
        )
        is False
    )


def test_empty_asset_ancestors_is_backward_compatible(config_path) -> None:
    assert project_overrides.is_rule_suppressed_for_project("service_account_key_created", "prj-brand-new") is False


def test_project_level_true_overrides_folder_level_false(config_path) -> None:
    """iam_policy_change is false at the folder level but true at the
    project level for prj-example -- project-level must win outright, so
    this specific project still alerts despite the folder-wide suppression.
    """
    assert (
        project_overrides.is_rule_suppressed_for_project(
            "iam_policy_change", "prj-example", asset_ancestors=["folders/111"]
        )
        is False
    )


def test_folder_level_false_still_applies_to_a_different_project_in_same_folder(config_path) -> None:
    """The same folder-wide iam_policy_change suppression DOES apply to a
    different project under that folder with no project-level override.
    """
    assert (
        project_overrides.is_rule_suppressed_for_project(
            "iam_policy_change", "prj-other-in-same-folder", asset_ancestors=["folders/111"]
        )
        is True
    )
