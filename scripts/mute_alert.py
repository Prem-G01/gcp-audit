"""Operator CLI for temporary alert muting -- create, list, and clear mutes
without editing config/rules.yaml or redeploying.

A mute suppresses one rule's alert email -- either org-wide, or scoped to
one specific project -- until it expires. The matched finding is still
evaluated and persisted to BigQuery (delivery_status="muted"); only the
email is suppressed, never the record that it happened. See src/muting.py
for the enforcement side (checked in main.py before every Gmail send).

Usage:
    python scripts/mute_alert.py mute --rule-id resource_created \
        --duration-hours 4 --reason "planned load test"
    python scripts/mute_alert.py mute --rule-id resource_created \
        --project-id prj-dg-devops-test --duration-hours 4 --reason "..."
    python scripts/mute_alert.py list
    python scripts/mute_alert.py clear --rule-id resource_created \
        --project-id prj-dg-devops-test

Requires the runtime identity running this script to hold write access to
the audit_platform_mutes Firestore collection (roles/datastore.user or
narrower, scoped to that collection) -- keyless, via your own gcloud
login (gcloud auth application-default login), same as every other
operator script in this repo. Never a service account key.

This is an interactive CLI tool (not the deployed Cloud Function), so like
scripts/probe_dwd.py it reports via print() rather than the `logging`
module -- that's what a human running it at a terminal expects.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import UTC
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import muting  # noqa: E402


def _current_gcloud_account() -> str:
    try:
        # shell=True (with a fixed, non-interpolated command string -- no
        # untrusted input reaches this) because on Windows `gcloud` is a
        # .cmd shim that subprocess.run can't launch via a plain argv list
        # without going through the shell.
        result = subprocess.run(
            "gcloud config get-value account",
            shell=True,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        account = result.stdout.strip()
        if account and account != "(unset)":
            return account
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def _cmd_mute(args: argparse.Namespace) -> int:
    muted_by = args.by or _current_gcloud_account()
    record = muting.create_mute(
        rule_id=args.rule_id,
        project_id=args.project_id,
        duration_hours=args.duration_hours,
        reason=args.reason,
        muted_by=muted_by,
    )
    scope = f"project {record.project_id}" if record.project_id else "org-wide (every project)"
    print(f"Muted: {record.rule_id} -- {scope}")
    print(f"  Expires: {record.expire_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Reason:  {record.reason}")
    print(f"  By:      {record.muted_by}")
    return 0


def _cmd_list(_args: argparse.Namespace) -> int:
    from datetime import datetime

    records = muting.list_mutes()
    if not records:
        print("No mutes found.")
        return 0
    now = datetime.now(UTC)
    for record in sorted(records, key=lambda r: r.expire_at):
        status = "ACTIVE" if record.expire_at > now else "EXPIRED (pending Firestore TTL cleanup)"
        if record.principal_email:
            scope = f"project {record.project_id}, principal {record.principal_email}"
        elif record.resource_name:
            scope = f"project {record.project_id}, resource {record.resource_name}"
        elif record.project_id:
            scope = f"project {record.project_id}"
        else:
            scope = "org-wide"
        print(f"[{status}] {record.rule_id} -- {scope}")
        print(f"  Expires: {record.expire_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"  Reason:  {record.reason}")
        print(f"  By:      {record.muted_by}")
    return 0


def _cmd_clear(args: argparse.Namespace) -> int:
    cleared = muting.clear_mute(rule_id=args.rule_id, project_id=args.project_id)
    scope = f"project {args.project_id}" if args.project_id else "org-wide"
    if cleared:
        print(f"Cleared: {args.rule_id} -- {scope}")
        return 0
    print(f"No active mute found for {args.rule_id} -- {scope}")
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest="command", required=True)

    mute_parser = subparsers.add_parser("mute", help="Create or replace a mute.")
    mute_parser.add_argument("--rule-id", required=True, help="Rule id from config/rules.yaml, e.g. resource_created")
    mute_parser.add_argument(
        "--project-id", default=None, help="Scope to one project. Omit to mute this rule everywhere."
    )
    mute_parser.add_argument("--duration-hours", required=True, type=float, help="How long the mute lasts, e.g. 4")
    mute_parser.add_argument("--reason", required=True, help="Why -- shown to anyone who runs 'list' later.")
    mute_parser.add_argument("--by", default=None, help="Defaults to your current gcloud account.")
    mute_parser.set_defaults(func=_cmd_mute)

    list_parser = subparsers.add_parser("list", help="Show all mutes (active and pending TTL cleanup).")
    list_parser.set_defaults(func=_cmd_list)

    clear_parser = subparsers.add_parser("clear", help="Remove a mute immediately.")
    clear_parser.add_argument("--rule-id", required=True)
    clear_parser.add_argument("--project-id", default=None)
    clear_parser.set_defaults(func=_cmd_clear)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
