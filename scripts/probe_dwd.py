"""Standalone diagnostic for the Gmail domain-wide-delegation auth flow.

Run this BEFORE deploying, to confirm signJwt + token exchange (+ optionally
an actual send) work for a given delegated mailbox, without needing a full
Cloud Function deployment to find out.

Usage:
    python scripts/probe_dwd.py <sender@domain> [--send-test <recipient>]

This is an interactive CLI tool (not the deployed Cloud Function), so unlike
the rest of the codebase it reports progress via print() rather than the
`logging` module -- that's what a human running it at a terminal expects.
It never prints the signed JWT or the access token.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.senders.gmail_sender import DelegatedGmailClient, GmailSendError, MailerConfig  # noqa: E402

_STAGE1_REMEDIATION = [
    "Verify the service account email is correct and actually exists.",
    'Confirm the identity running this script has the "Service Account Token '
    'Creator" role (roles/iam.serviceAccountTokenCreator) on that service account.',
    "Confirm you are authenticated to a project that can reach the target "
    "service account (gcloud auth application-default login, or run this as "
    "the Cloud Function's own runtime identity).",
    "Confirm the IAM Service Account Credentials API is enabled on the project.",
]

_STAGE2_REMEDIATION = [
    "Confirm domain-wide delegation is authorized for this service account's "
    "OAuth client ID with EXACTLY the scope "
    "https://www.googleapis.com/auth/gmail.send in the Workspace Admin "
    "Console (Security > API Controls > Domain-wide Delegation).",
    "Confirm the impersonated mailbox (the <sender> argument) is a real, "
    "active mailbox in that Workspace domain.",
    "Confirm the OAuth client ID registered for delegation matches this "
    "service account's unique ID, not a different service account.",
    "DWD grants can take several minutes to propagate -- retry after a short wait.",
]

_STAGE3_REMEDIATION = [
    "Confirm the sender mailbox holds a Gmail license (a bare Workspace "
    "identity without Gmail enabled cannot send mail).",
    "Confirm the --send-test recipient address is valid.",
    "Confirm the `sub` claim and the `userId` passed to messages().send() "
    "are identical (both must equal the <sender> argument) -- a 404 here "
    "means they diverged.",
    "Confirm the Gmail API is enabled on the project and daily send quotas "
    "have not been exhausted.",
]


def _print_failure(stage: int, exc: Exception, remediation: list[str]) -> None:
    print(f"STAGE {stage} FAILED")
    print(f"Error detail: {exc}")
    print("Remediation:")
    for index, step in enumerate(remediation, start=1):
        print(f"  {index}. {step}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "sender",
        help="Workspace mailbox to impersonate (the JWT 'sub' / Gmail API userId), "
        "e.g. alerts@yourdomain.com",
    )
    parser.add_argument(
        "--send-test",
        metavar="RECIPIENT",
        help="If set, actually sends a minimal HTML test email to this address (stage 3).",
    )
    args = parser.parse_args(argv)

    delegated_sa = os.environ.get("GMAIL_DELEGATED_SA")
    if not delegated_sa:
        print("STAGE 0 FAILED: GMAIL_DELEGATED_SA environment variable is not set.")
        return 1

    config = MailerConfig(delegated_sa=delegated_sa, sender=args.sender)
    client = DelegatedGmailClient(config)

    try:
        signed_jwt = client._sign_jwt()
    except GmailSendError as exc:
        _print_failure(1, exc, _STAGE1_REMEDIATION)
        return 1
    print("STAGE 1 OK: signJwt succeeded")

    try:
        client._exchange_token(signed_jwt)
    except GmailSendError as exc:
        _print_failure(2, exc, _STAGE2_REMEDIATION)
        return 1
    print("STAGE 2 OK: delegated token acquired")

    if args.send_test:
        try:
            message_id = client.send(
                to=[args.send_test],
                subject="[GCP Audit Platform] Domain-wide delegation probe",
                html_body=(
                    "<p>This is a diagnostic message from "
                    "<code>probe_dwd.py</code> confirming delegated Gmail-send "
                    "access is working.</p>"
                ),
                text_body=(
                    "This is a diagnostic message from probe_dwd.py confirming "
                    "delegated Gmail-send access is working."
                ),
            )
        except GmailSendError as exc:
            _print_failure(3, exc, _STAGE3_REMEDIATION)
            return 1
        print(f"STAGE 3 OK: message id {message_id}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
