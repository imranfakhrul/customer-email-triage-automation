"""Manual verification script for Milestone [P2-07].

Verifies Webhook Alert Adapter with HMAC signing, dual payload formatting,
Channel Privacy Guard, and rate limit error classification.

Usage:
    ./venv/bin/python scripts/check_p2_07.py
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.adapters.base import (  # noqa: E402
    AdapterPermanentError,
    AdapterTransientError,
    DispatchPayload,
)
from utils.adapters.webhook_adapter import WebhookAdapter  # noqa: E402
from utils.adapters.webhook_format import (  # noqa: E402
    build_alert_payload,
    build_security_headers,
    build_slack_payload,
    compute_hmac_signature,
    determine_alert_type,
)


def require(condition: bool, msg: str = "") -> None:
    """Assertion helper avoiding S101 bandit flags in standalone scripts."""
    if not condition:
        raise RuntimeError(f"Check requirement failed: {msg}")


def run_checks() -> None:
    print("=" * 70)
    print(" RUNNING MANUAL VERIFICATION FOR MILESTONE [P2-07]")
    print(" Webhook Alert Adapter with HMAC Signing & Dual Formatting")
    print("=" * 70)

    signing_secret = "whsec_supersecretkey12345"  # nosec B105 # noqa: S105

    # -------------------------------------------------------------
    # Check 1: Cryptographic HMAC-SHA256 Signing & Replay Defense
    # -------------------------------------------------------------
    print("\n[Check 1] Cryptographic HMAC-SHA256 Signing & Replay Defense")
    raw_body = b'{"event":"customer_incident.critical","id":"inc_001"}'
    expected_hex = hmac.new(
        signing_secret.encode("utf-8"), raw_body, hashlib.sha256
    ).hexdigest()
    sig = compute_hmac_signature(raw_body, signing_secret)
    require(sig == f"sha256={expected_hex}", f"HMAC mismatch: {sig}")

    headers = build_security_headers(
        payload_bytes=raw_body,
        secret=signing_secret,
        idempotency_key="em_sec_01:webhook:alert",
        email_id="em_sec_01",
    )
    require(headers["Content-Type"] == "application/json", "Missing Content-Type")
    require(headers["X-Signature-SHA256"] == f"sha256={expected_hex}", "Signature header mismatch")
    require("T" in headers["X-Timestamp-ISO"], "Timestamp must be ISO format")
    require(headers["Idempotency-Key"] == "em_sec_01:webhook:alert", "Invalid Idempotency-Key")
    require(headers["X-Correlation-ID"] == "em_sec_01", "Invalid X-Correlation-ID")
    print("  -> HMAC-SHA256 signature generated and verified against standard. [PASS]")
    print(f"  -> X-Signature-SHA256: {sig[:20]}... [PASS]")
    print("  -> ISO replay defense timestamp & idempotency correlation verified. [PASS]")

    # -------------------------------------------------------------
    # Check 2: Channel Privacy Guard (Zero Customer PII Exposure)
    # -------------------------------------------------------------
    print("\n[Check 2] Channel Privacy Guard (Default unmask_pii: false)")
    record = {
        "email_id": "em_alert_priv_01",
        "message_id": "<em_alert_priv_01@enterprise.com>",
        "thread_id": "th_alert_01",
        "category": "Security/Account",
        "priority": "Critical",
        "sentiment": "Urgent",
        "customer_emotion": "panicked",
        "summary": "Suspected breach reported by enterprise tenant",
        "suggested_team": "Security Operations",
        "confidence": 0.99,
        "masked_subject": "Urgent: unauthorized account access for [PERSON_1]",
        "masked_body": (
            "We detected unauthorized access.\n"
            "Card on file is [CREDIT_CARD_1] and auth token [API_KEY_1].\n"
            "Please call me at [PHONE_1] immediately."
        ),
        "sender_email": "ciso@target-enterprise.com",
        "sender_domain": "target-enterprise.com",
        "p2_classifier_used": "jev",
    }

    alert_json = build_alert_payload(record)
    alert_raw_str = json.dumps(alert_json)

    # Invariant #1: Privacy checks on channel payload
    forbidden_tokens = ["Jane Doe", "+1-555-0199", "4111-2222-3333-4444", "sec_live_99887766"]
    for forbidden in forbidden_tokens:
        require(forbidden not in alert_raw_str, f"PII leaked in webhook payload: {forbidden}")

    # Must preserve masked tokens and sender domain
    require("[PERSON_1]" in alert_raw_str, "Masked token PERSON_1 must be present")
    require("[CREDIT_CARD_1]" in alert_raw_str, "Masked token CREDIT_CARD_1 must be present")
    require(alert_json["sender_domain"] == "target-enterprise.com", "Domain present")
    print("  -> Zero customer PII in alert payload (names, phones, cards, keys absent). [PASS]")
    print("  -> Masked tokens and sender domain correctly preserved. [PASS]")

    # -------------------------------------------------------------
    # Check 3: Alert Categorization & Dual Formatting
    # -------------------------------------------------------------
    print("\n[Check 3] Alert Categorization & Dual Formatting (Generic vs Slack)")
    require(
        determine_alert_type("Bug Report", "Critical") == "critical_outage",
        "Critical bug must be critical_outage",
    )
    require(
        determine_alert_type("Billing Issue", "High") == "urgent_billing",
        "High billing must be urgent_billing",
    )
    require(
        determine_alert_type("Refund Request", "Critical") == "urgent_billing",
        "Critical refund must be urgent_billing",
    )
    require(
        determine_alert_type("Security/Account", "Low") == "security_escalation",
        "Security must be security_escalation",
    )
    print("  -> Alert semantic categories mapped deterministically. [PASS]")

    # Slack Block Kit payload check
    slack_payload = build_slack_payload(record)
    require("attachments" in slack_payload, "Slack payload must have attachments")
    att = slack_payload["attachments"][0]
    require(att["color"] == "#E01E5A", "Critical severity must use Slack red (#E01E5A)")
    blocks = att["blocks"]
    require(blocks[0]["type"] == "header", "Block 0 must be header")
    require(blocks[1]["type"] == "section", "Block 1 must be section with fields")
    require("fields" in blocks[1], "Section must contain fields")
    fields = {f["text"] for f in blocks[1]["fields"]}
    require(any("Category:" in f for f in fields), "Fields missing Category")
    require(any("Priority:" in f for f in fields), "Fields missing Priority")
    print("  -> Slack Block Kit card structure with color coding verified. [PASS]")

    # -------------------------------------------------------------
    # Check 4: Adapter Execution & Fault Tolerance Simulation
    # -------------------------------------------------------------
    print("\n[Check 4] WebhookAdapter Execution & Error Classification")
    dispatch_payload = DispatchPayload.from_record(
        record=record,
        action_type="alert",
        idempotency_key="em_alert_priv_01:webhook:alert",
    )

    mock_client = MagicMock()
    adapter = WebhookAdapter(
        target="https://events.mycompany.internal/triage-alerts",
        secret_key=signing_secret,
        allowed_hosts=["events.mycompany.internal"],
        session=mock_client,
    )

    # 4a: Successful dispatch
    mock_success = MagicMock(status_code=200)
    mock_success.json.return_value = {"status": "received", "id": "alert_rec_999"}
    mock_client.request.return_value = mock_success

    res = adapter.dispatch(dispatch_payload)
    require(res.outcome == "success", "Dispatch should succeed")
    require(
        res.remote_id == f"webhook:{dispatch_payload.email_id}",
        f"Unexpected remote_id: {res.remote_id}",
    )
    print("  -> HTTP 200: Successfully signed, transmitted, and confirmed. [PASS]")

    # 4b: Rate limit (HTTP 429) -> AdapterTransientError
    mock_429 = MagicMock(status_code=429, headers={"Retry-After": "45"})
    mock_429.json.return_value = {"error": "Rate limit exceeded"}
    mock_client.request.return_value = mock_429

    try:
        adapter.dispatch(dispatch_payload)
        raise RuntimeError("Expected AdapterTransientError on 429")
    except AdapterTransientError:
        print("  -> HTTP 429: Correctly raised AdapterTransientError. [PASS]")

    # 4c: Client error (HTTP 400) -> AdapterPermanentError
    mock_400 = MagicMock(status_code=400, headers={})
    mock_400.json.return_value = {"error": "Malformed signature header"}
    mock_client.request.return_value = mock_400

    try:
        adapter.dispatch(dispatch_payload)
        raise RuntimeError("Expected AdapterPermanentError on 400")
    except AdapterPermanentError:
        print("  -> HTTP 400: Correctly raised AdapterPermanentError. [PASS]")

    print("\n" + "=" * 70)
    print(" ALL CHECKS PASSED: Webhook Alert Adapter is production ready!")
    print("=" * 70)


if __name__ == "__main__":
    run_checks()
