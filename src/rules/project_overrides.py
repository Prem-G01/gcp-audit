"""Permanent, hand-edited per-project (and per-folder) rule suppression.

config/project_rules.yaml lets an operator permanently silence a specific
rule for a specific project, or for an entire folder (`rule -> false`
under `projects.<project_id>` or `folders.<folder_id>`), without editing
config/rules.yaml itself. This is deliberately a different mechanism from
src/muting.py's Firestore-backed "Mute this alert" button: that one is
self-service and time-limited; this one is a version-controlled file the
operator edits by hand and that never expires on its own.

Default is always "not suppressed" -- an unlisted project/folder, an
unlisted rule, or an explicit `true` all mean the alert fires normally.
Only an explicit `false` silences it, so a new rule or a project/folder
nobody has configured yet never goes silent by accident.

Folder membership comes from EnrichedEvent.asset_ancestors -- already
populated by the existing Cloud Asset Inventory enrichment
(src/enrichment/asset_inventory.py), no separate lookup here. That means
folder suppression is only as reliable as that enrichment: if it fails or
hasn't indexed a brand-new project yet, asset_ancestors is empty and
folder suppression simply doesn't apply for that event -- failing open
(alert fires), same as every other degrade-gracefully boundary in this
pipeline. An explicit project-level entry (true or false) always takes
precedence over any folder-level setting, letting one project opt out of
(or back into) a folder-wide rule.

Unlike config/rules.yaml (validated strictly, fails loudly at cold start),
this file is expected to be hand-edited often -- a typo here degrades to
"nothing suppressed" rather than taking down the whole pipeline, matching
this platform's degrade-gracefully contract for every other external-input
boundary.

A third, independent axis: `service_account_muted_rules` (a plain list of
rule ids, not a project/folder-keyed map) mutes a rule for EVERY service
account principal, in every project, while leaving that same rule alerting
normally when a human triggers it. Built for a specific recurring problem:
an automated service account driving high-frequency legitimate traffic
(e.g. an API backend downloading files every few seconds) against a rule
with no volume threshold can exhaust Gmail's sending limit and block
delivery of every other alert. This is a coarser, org-wide version of the
projects:/folders: suppression above -- use it when the noise isn't
specific to one project, or when you don't yet know which project it'll
show up in next.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "project_rules.yaml"

_FOLDER_ANCESTOR_PREFIX = "folders/"


@lru_cache(maxsize=8)
def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except FileNotFoundError:
        return {}
    except Exception as exc:  # malformed file must never block an alert
        logger.warning("project_rules_load_failed", extra={"error": str(exc)})
        return {}
    return data if isinstance(data, dict) else {}


def _lookup(config: dict[str, Any], section: str, key: str, rule_id: str) -> bool | None:
    section_map = config.get(section)
    if not isinstance(section_map, dict):
        return None
    entries = section_map.get(key)
    if not isinstance(entries, dict):
        return None
    value = entries.get(rule_id)
    return value if isinstance(value, bool) else None


def _folder_ids(asset_ancestors: Sequence[str]) -> list[str]:
    return [a[len(_FOLDER_ANCESTOR_PREFIX) :] for a in asset_ancestors if a.startswith(_FOLDER_ANCESTOR_PREFIX)]


def is_rule_suppressed_for_project(
    rule_id: str, project_id: str | None, asset_ancestors: Sequence[str] = ()
) -> bool:
    """True when config/project_rules.yaml suppresses this rule for this
    project, or (absent an explicit project-level entry) for a folder the
    project belongs to per `asset_ancestors`. Absence, an unlisted
    project/folder, or an explicit true all mean "not suppressed" -- never
    silent by default. Never raises.
    """
    if not project_id:
        return False
    config = _load_yaml(CONFIG_PATH)

    project_value = _lookup(config, "projects", project_id, rule_id)
    if project_value is not None:
        return project_value is False

    for folder_id in _folder_ids(asset_ancestors):
        if _lookup(config, "folders", folder_id, rule_id) is False:
            return True

    return False


def is_rule_muted_for_service_accounts(rule_id: str) -> bool:
    """True when config/project_rules.yaml's service_account_muted_rules
    list contains this rule id. A plain list (not true/false-per-rule) --
    presence mutes, absence never does, so there's no true/false-meaning
    inversion to trip over relative to the projects:/folders: sections
    above. Never raises.
    """
    config = _load_yaml(CONFIG_PATH)
    muted = config.get("service_account_muted_rules")
    if not isinstance(muted, list):
        return False
    return rule_id in muted


__all__ = ["is_rule_muted_for_service_accounts", "is_rule_suppressed_for_project"]
