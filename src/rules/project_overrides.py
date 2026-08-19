"""Permanent, hand-edited per-project rule suppression.

config/project_rules.yaml lets an operator permanently silence a specific
rule for a specific project (`project -> rule_id -> false`) without editing
config/rules.yaml itself. This is deliberately a different mechanism from
src/muting.py's Firestore-backed "Mute this alert" button: that one is
self-service and time-limited; this one is a version-controlled file the
operator edits by hand and that never expires on its own.

Default is always "not suppressed" -- an unlisted project, an unlisted
rule, or an explicit `true` all mean the alert fires normally. Only an
explicit `false` silences it, so a new rule or a project nobody has
configured yet never goes silent by accident.

Unlike config/rules.yaml (validated strictly, fails loudly at cold start),
this file is expected to be hand-edited often -- a typo here degrades to
"nothing suppressed" rather than taking down the whole pipeline, matching
this platform's degrade-gracefully contract for every other external-input
boundary.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "project_rules.yaml"


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


def is_rule_suppressed_for_project(rule_id: str, project_id: str | None) -> bool:
    """True only when config/project_rules.yaml explicitly sets this
    project+rule to false. Absence, an unlisted project, or an explicit
    true all mean "not suppressed" -- never silent by default. Never raises.
    """
    if not project_id:
        return False
    config = _load_yaml(CONFIG_PATH)
    projects = config.get("projects")
    if not isinstance(projects, dict):
        return False
    rules = projects.get(project_id)
    if not isinstance(rules, dict):
        return False
    return rules.get(rule_id) is False


__all__ = ["is_rule_suppressed_for_project"]
