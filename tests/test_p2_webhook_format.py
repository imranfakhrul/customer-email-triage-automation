"""Unit tests for Webhook output formatting, HMAC signing, and security headers."""

import hashlib
import hmac
from datetime import UTC, datetime

from utils.adapters.webhook_format import (
    build_alert_payload,
    build_security_headers,
    build_slack_payload,
    compute_hmac_signature,
    determine_alert_type,
)


def test_compute_hmac_signature():
    secret = "test_webhook_secret_key_12345"
    payload_bytes = b'{"event":"customer_email_triage.alert","email_id":"em_test_001"}'

    expected_raw = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    expected_header = f"sha256={expected_raw}"

    computed = compute_hmac_signature(payload_bytes, secret)
    assert computed == expected_header


def test_compute_hmac_signature_empty_secret():
    payload_bytes = b'{"hello":"world"}'
    # If secret is empty, signature is empty string or raises
    assert compute_hmac_signature(payload_bytes, "") == ""


def test_determine_alert_type():
    assert determine_alert_type(category="Bug Report", priority="Critical") == "critical_outage"
    assert determine_alert_type(category="General Query", priority="Critical") == "critical_outage"
    assert determine_alert_type(category="Complaint", priority="Critical") == "critical_outage"
    assert determine_alert_type(category="Billing Issue", priority="High") == "urgent_billing"
    assert determine_alert_type(category="Refund Request", priority="Critical") == "urgent_billing"
    assert (
        determine_alert_type(category="Security/Account", priority="Medium")
        == "security_escalation"
    )
    assert determine_alert_type(category="Demo Request", priority="Low") == "general_alert"


def test_build_security_headers():
    secret = "super_secret_xyz"
    payload_bytes = b'{"alert":"test"}'
    idempotency_key = "idemp_wh_001"
    email_id = "em_001"
    fixed_time = datetime(2026, 10, 28, 14, 55, 0, tzinfo=UTC)

    headers = build_security_headers(
        payload_bytes=payload_bytes,
        secret=secret,
        idempotency_key=idempotency_key,
        email_id=email_id,
        timestamp=fixed_time,
    )

    assert headers["Content-Type"] == "application/json"
    assert headers["User-Agent"] == "Customer-Email-Triage-Automation"
    assert headers["Idempotency-Key"] == idempotency_key
    assert headers["X-Correlation-ID"] == email_id
    assert headers["X-Timestamp-ISO"] == "2026-10-28T14:55:00Z"

    expected_sig = compute_hmac_signature(payload_bytes, secret)
    assert headers["X-Signature-SHA256"] == expected_sig


def test_build_alert_payload_masked_by_default():
    record = {
        "email_id": "em_wh_001",
        "message_id": "<msg01@corp.com>",
        "thread_id": "th_wh_001",
        "category": "Billing Issue",
        "priority": "High",
        "sentiment": "Angry",
        "customer_emotion": "Angry",
        "summary": "Customer charged twice for monthly subscription",
        "suggested_team": "Billing",
        "confidence": 0.96,
        "masked_subject": "Urgent: Double charged for [PERSON_1]",
        "masked_body": "I was charged twice on card [CREDIT_CARD_1]. Refund immediately!",
        "sender_email": "john.customer@corp.com",
        "sender_domain": "corp.com",
        "token_map": {
            "[PERSON_1]": "John Doe",
            "[CREDIT_CARD_1]": "4111-2222-3333-4444",
        },
    }

    # Channel Privacy Guard: unmask_pii=False by default for webhooks
    alert = build_alert_payload(
        record=record,
        unmask_pii=False,
    )

    assert alert["event"] == "customer_email_triage.alert"
    assert alert["alert_type"] == "urgent_billing"
    assert alert["email_id"] == "em_wh_001"
    assert alert["category"] == "Billing Issue"
    assert alert["priority"] == "High"
    assert alert["sender_domain"] == "corp.com"
    assert "john.customer@corp.com" not in str(alert)

    # Context retains masked text only:
    assert "[PERSON_1]" in alert["subject"]
    assert "John Doe" not in alert["subject"]
    assert "[CREDIT_CARD_1]" in alert["context"]["masked_body"]
    assert "4111-2222-3333-4444" not in alert["context"]["masked_body"]


def test_build_slack_payload():
    record = {
        "email_id": "em_slack_001",
        "category": "Bug Report",
        "priority": "Critical",
        "sender_domain": "enterprise.com",
        "masked_subject": "Postgres connection pool exhausted",
        "summary": "Production database failure affecting all API instances",
        "suggested_team": "Engineering",
        "confidence": 0.99,
        "masked_body": "All pods crashing with connection refused.",
    }

    slack_data = build_slack_payload(record=record, unmask_pii=False)

    assert "text" in slack_data
    assert "🚨 [CRITICAL ALERT]" in slack_data["text"]
    assert "attachments" in slack_data
    attachment = slack_data["attachments"][0]
    assert attachment["color"] == "#E01E5A"  # Red for Critical

    blocks = attachment["blocks"]
    assert any(b["type"] == "header" for b in blocks)
