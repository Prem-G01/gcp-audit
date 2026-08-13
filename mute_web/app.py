"""Standalone Cloud Run service: the "Mute this alert" confirmation flow
linked from every alert email. Deployed separately from the main
Pub/Sub-triggered pipeline (main.py) -- IAP's direct Cloud Run integration
(the mechanism gating this to the admin Google Group) isn't available on
Cloud Functions Gen2, only on a plain Cloud Run service. See
terraform/modules/mute_web for the IAP + IAM wiring.

Two routes:
  GET  /mute   -- shows a confirmation page. Does NOT mute anything --
                  email security scanners/link-prefetchers routinely fetch
                  links in emails automatically, and a bare GET must never
                  have a side effect.
  POST /mute   -- the actual mute action, only reachable by submitting the
                  real HTML form on the confirmation page (a genuine human
                  click, not an automated GET).

IAP sits in front of this entire service (Terraform-configured, not in
this code) and is the actual access-control boundary: only members of the
configured Google Group can reach either route at all. This code
additionally verifies IAP's signed JWT itself (rather than trusting the
unsigned X-Goog-Authenticated-User-Email header) so the muted_by value
recorded in Firestore can't be spoofed if a request somehow reached this
service without going through IAP (e.g. a future misconfiguration that
also allows unauthenticated Cloud Run access).
"""

from __future__ import annotations

import html
import logging
import os
import sys
from pathlib import Path

from flask import Flask, Response, request
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import muting  # noqa: E402

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

_DEFAULT_DURATION_HOURS = 4.0
_IAP_JWT_HEADER = "X-Goog-IAP-JWT-Assertion"
_IAP_ISSUER = "https://cloud.google.com/iap"
_IAP_PUBLIC_KEY_URL = "https://www.gstatic.com/iap/verify/public_key"


class IapVerificationError(Exception):
    """Raised whenever the caller can't be verified as having come through
    IAP -- always results in a 403, never a mute.
    """


def _iap_audience() -> str:
    """The expected JWT audience for this specific Cloud Run service.
    Must be set at deploy time to
    /projects/PROJECT_NUMBER/locations/REGION/services/SERVICE_NAME.
    """
    audience = os.environ.get("IAP_AUDIENCE")
    if not audience:
        raise IapVerificationError("IAP_AUDIENCE is not configured")
    return audience


def _verified_caller_email() -> str:
    """Verify the IAP-signed JWT and return the caller's real email.

    Never trusts the unsigned X-Goog-Authenticated-User-Email header --
    only a signature/issuer/audience-checked JWT is trustworthy, per IAP's
    own documented guidance.
    """
    jwt_assertion = request.headers.get(_IAP_JWT_HEADER)
    if not jwt_assertion:
        raise IapVerificationError("Missing IAP assertion -- request did not come through IAP")
    try:
        payload = id_token.verify_token(
            jwt_assertion,
            google_requests.Request(),
            audience=_iap_audience(),
            certs_url=_IAP_PUBLIC_KEY_URL,
        )
    except Exception as exc:  # noqa: BLE001 -- any verification failure is just "not authorized"
        raise IapVerificationError(f"IAP assertion failed verification: {exc}") from exc
    if payload.get("iss") != _IAP_ISSUER:
        raise IapVerificationError("Unexpected JWT issuer")
    email = payload.get("email")
    if not email:
        raise IapVerificationError("Verified JWT has no email claim")
    return str(email)


_PAGE_STYLE = """
  body { font-family: -apple-system, "Segoe UI", Roboto, Arial, sans-serif; background: #0f172a;
         color: #e2e8f0; display: flex; align-items: center; justify-content: center;
         min-height: 100vh; margin: 0; padding: 20px; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 32px;
          max-width: 480px; width: 100%; }
  h1 { font-size: 18px; margin: 0 0 12px; }
  p { font-size: 14px; color: #94a3b8; line-height: 1.6; }
  .field { margin: 16px 0; }
  label { display: block; font-size: 12px; color: #94a3b8; margin-bottom: 4px; }
  .value { font-family: ui-monospace, monospace; font-size: 13px; color: #e2e8f0;
           background: #0f172a; padding: 8px 12px; border-radius: 6px; border: 1px solid #334155; }
  select, input[type=text] { width: 100%; padding: 8px 10px; border-radius: 6px; border: 1px solid #334155;
           background: #0f172a; color: #e2e8f0; font-size: 13px; box-sizing: border-box; }
  .radio-option { display: flex; align-items: flex-start; gap: 8px; margin: 8px 0; font-size: 13px;
           color: #e2e8f0; font-weight: normal; text-transform: none; }
  .radio-option input { margin-top: 3px; flex-shrink: 0; }
  .radio-option .value { display: inline; padding: 2px 6px; }
  button { width: 100%; padding: 12px; border-radius: 6px; border: none; font-size: 14px;
           font-weight: 600; cursor: pointer; margin-top: 8px; }
  .confirm { background: #ef4444; color: #fff; }
  .done { background: #15803d; color: #fff; text-align: center; padding: 10px; border-radius: 6px;
          font-weight: 600; }
"""


def _render_page(*, title: str, body_html: str, status: int = 200) -> Response:
    doc = (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        f"<title>{html.escape(title)}</title><style>{_PAGE_STYLE}</style></head>"
        f"<body><div class=\"card\">{body_html}</div></body></html>"
    )
    return Response(doc, status=status, mimetype="text/html")


def _access_denied_page(reason: str) -> Response:
    logger.warning("mute_web_auth_failed", extra={"error": reason})
    return _render_page(
        title="Access denied",
        body_html=(
            "<h1>Access denied</h1>"
            "<p>You must be signed in as an authorized administrator to use this page.</p>"
        ),
        status=403,
    )


@app.route("/mute", methods=["GET"])
def mute_confirmation() -> Response:
    try:
        caller_email = _verified_caller_email()
    except IapVerificationError as exc:
        return _access_denied_page(str(exc))

    rule_id = request.args.get("rule_id", "")
    project_id = request.args.get("project_id") or None
    principal_email = request.args.get("principal_email") or None
    resource_name = request.args.get("resource_name") or None
    if not rule_id:
        return _render_page(
            title="Invalid link", body_html="<h1>Invalid link</h1><p>No rule specified.</p>", status=400
        )

    project_field = (
        f'<input type="hidden" name="project_id" value="{html.escape(project_id)}">' if project_id else ""
    )

    # principal_email/resource_name only ever arrive alongside a project_id
    # (see main.py's _mute_url) -- no project_id means there's nothing to
    # narrow within, so the static project/org-wide line is all there is.
    if project_id and (principal_email or resource_name):
        options = [
            (
                '<label class="radio-option">'
                f'<input type="radio" name="scope" value="project" checked>'
                f'<span>Entire project &mdash; <span class="value">{html.escape(project_id)}</span></span>'
                "</label>"
            )
        ]
        if principal_email:
            options.append(
                '<label class="radio-option">'
                '<input type="radio" name="scope" value="principal">'
                f'<span>Only this principal &mdash; <span class="value">{html.escape(principal_email)}</span></span>'
                "</label>"
            )
        if resource_name:
            options.append(
                '<label class="radio-option">'
                '<input type="radio" name="scope" value="resource">'
                f'<span>Only this resource &mdash; <span class="value">{html.escape(resource_name)}</span></span>'
                "</label>"
            )
        scope_html = "".join(options)
        principal_field = (
            f'<input type="hidden" name="principal_email" value="{html.escape(principal_email)}">'
            if principal_email
            else ""
        )
        resource_field = (
            f'<input type="hidden" name="resource_name" value="{html.escape(resource_name)}">' if resource_name else ""
        )
        narrowing_fields = principal_field + resource_field
    elif project_id:
        scope_html = f'<div class="value">{html.escape(project_id)}</div>'
        narrowing_fields = ""
    else:
        scope_html = '<div class="value">org-wide (every monitored project)</div>'
        narrowing_fields = ""

    body = f"""
      <h1>Mute this alert?</h1>
      <p>Signed in as {html.escape(caller_email)}</p>
      <div class="field"><label>Rule</label><div class="value">{html.escape(rule_id)}</div></div>
      <div class="field"><label>Scope</label>{scope_html}</div>
      <form method="POST" action="/mute">
        <input type="hidden" name="rule_id" value="{html.escape(rule_id)}">
        {project_field}
        {narrowing_fields}
        <div class="field">
          <label>Duration</label>
          <select name="duration_hours">
            <option value="1">1 hour</option>
            <option value="4" selected>4 hours</option>
            <option value="24">24 hours</option>
            <option value="72">3 days</option>
            <option value="168">7 days</option>
          </select>
        </div>
        <div class="field">
          <label>Reason (optional)</label>
          <input type="text" name="reason" placeholder="e.g. planned maintenance">
        </div>
        <button type="submit" class="confirm">Confirm mute</button>
      </form>
    """
    return _render_page(title="Mute this alert?", body_html=body)


@app.route("/mute", methods=["POST"])
def mute_confirm() -> Response:
    try:
        caller_email = _verified_caller_email()
    except IapVerificationError as exc:
        return _access_denied_page(str(exc))

    rule_id = request.form.get("rule_id", "")
    project_id = request.form.get("project_id") or None
    reason = request.form.get("reason") or "Muted via email link"
    try:
        duration_hours = float(request.form.get("duration_hours", _DEFAULT_DURATION_HOURS))
    except ValueError:
        duration_hours = _DEFAULT_DURATION_HOURS
    duration_hours = max(0.25, min(duration_hours, 168.0))  # clamp: 15 min .. 7 days

    if not rule_id:
        return _render_page(
            title="Invalid request", body_html="<h1>Invalid request</h1><p>No rule specified.</p>", status=400
        )

    # `scope` is which radio the admin picked (see mute_confirmation); the
    # actual principal_email/resource_name values ride along as hidden
    # fields regardless of which radio is checked, so only the selected
    # one gets forwarded to create_mute -- never both at once.
    scope = request.form.get("scope", "project")
    principal_email = request.form.get("principal_email") or None if scope == "principal" else None
    resource_name = request.form.get("resource_name") or None if scope == "resource" else None

    record = muting.create_mute(
        rule_id=rule_id,
        project_id=project_id,
        duration_hours=duration_hours,
        reason=reason,
        muted_by=caller_email,
        principal_email=principal_email,
        resource_name=resource_name,
    )
    logger.info(
        "alert_muted_via_web",
        extra={
            "rule_id": rule_id,
            "project_id": project_id,
            "principal_email": principal_email,
            "resource_name": resource_name,
            "muted_by": caller_email,
            "expire_at": record.expire_at.isoformat(),
        },
    )
    if record.principal_email:
        scope_text = f"principal {record.principal_email} in project {record.project_id}"
    elif record.resource_name:
        scope_text = f"resource {record.resource_name} in project {record.project_id}"
    elif record.project_id:
        scope_text = f"project {record.project_id}"
    else:
        scope_text = "org-wide"
    body = (
        '<div class="done">Muted</div>'
        f"<p><strong>{html.escape(record.rule_id)}</strong> is now muted for {html.escape(scope_text)} "
        f"until {html.escape(record.expire_at.strftime('%Y-%m-%d %H:%M:%S UTC'))}.</p>"
    )
    return _render_page(title="Muted", body_html=body)


@app.route("/", methods=["GET"])
def health() -> Response:
    return Response("ok", status=200, mimetype="text/plain")
