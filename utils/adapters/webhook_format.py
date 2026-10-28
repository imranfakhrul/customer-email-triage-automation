"""Output formatting, HMAC signing, and payload generation for Webhook alert adapter.

Guarantees:
1. Cryptographic Authenticity: HMAC-SHA256 request payload signature (X-Signature-SHA256).
2. Replay Protection: Aware UTC ISO-8601 timestamp (X-Timestamp-ISO).
3. Channel Privacy Guard: Enforces unmask_pii=False by default so that notifications
   in shared channels (Slack, Teams, Discord) contain zero customer PII.
4. Dual Format: Generates standard incident alert JSON and auto-formats Slack Block Kit.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from utils.unmasker import resolve_dispatch_content


def compute_hmac_signature(payload_bytes: bytes, secret: str) -> str:
    """Computes HMAC-SHA256 signature formatted as sha256=<hex_digest>.

    Args:
        payload_bytes: Raw UTF-8 encoded bytes of request payload.
        secret: Shared webhook secret key.

    Returns:
        String signature 'sha256=<hex>' or empty string if secret is empty.
    """
    if not secret or not payload_bytes:
        return ""
    digest = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def determine_alert_type(category: str | None, priority: str | None) -> str:
    """Classifies the severity and semantic alert type of the incident.

    Args:
        category: Email classification category.
        priority: Priority urgency ('Critical', 'High', etc.).

    Returns:
        Alert type identifier string.
    """
    cat = (category or "").strip()
    prio = (priority or "").strip()

    if cat in ("Billing Issue", "Refund Request"):
        return "urgent_billing"
    if cat == "Security/Account":
        return "security_escalation"
    if prio == "Critical":
        return "critical_outage"
    return "general_alert"


def build_security_headers(
    payload_bytes: bytes,
    secret: str,
    idempotency_key: str,
    email_id: str,
    timestamp: datetime | None = None,
) -> dict[str, str]:
    """Builds required cryptographic and tracking headers for outbound alert webhooks.

    Args:
        payload_bytes: Raw request body bytes.
        secret: Webhook shared signing secret.
        idempotency_key: Unique composite idempotency key.
        email_id: Email identifier for tracing.
        timestamp: Optional datetime; defaults to aware UTC now.

    Returns:
        Mapping of HTTP headers.
    """
    now = timestamp or datetime.now(UTC)
    iso_timestamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    signature = compute_hmac_signature(payload_bytes, secret)

    return {
        "Content-Type": "application/json",
        "User-Agent": "Customer-Email-Triage-Automation",
        "X-Signature-SHA256": signature,
        "X-Timestamp-ISO": iso_timestamp,
        "Idempotency-Key": idempotency_key,
        "X-Correlation-ID": email_id,
    }


def build_alert_payload(
    record: Mapping[str, Any],
    unmask_pii: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Builds standard incident alert JSON payload with channel privacy protections.

    Args:
        record: Database triage record or DispatchPayload mapping.
        unmask_pii: Whether to unmask contact entities (default False for shared webhooks).
        now: Optional timestamp override for deterministic testing.

    Returns:
        JSON-serializable incident alert dictionary.
    """
    resolved = resolve_dispatch_content(record, unmask_pii=unmask_pii)

    email_id = str(record.get("email_id") or "")
    category = str(record.get("category") or "")
    priority = str(record.get("priority") or "")
    sentiment = str(record.get("sentiment") or "")
    customer_emotion = str(record.get("customer_emotion") or "")
    suggested_team = str(record.get("suggested_team") or "")
    confidence = float(record.get("confidence") or 0.0)
    summary = str(record.get("summary") or "")

    ts = (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")
    alert_type = determine_alert_type(category, priority)

    return {
        "event": "customer_email_triage.alert",
        "alert_type": alert_type,
        "email_id": email_id,
        "timestamp": ts,
        "category": category,
        "priority": priority,
        "sentiment": sentiment,
        "customer_emotion": customer_emotion,
        "suggested_team": suggested_team,
        "confidence": confidence,
        "sender_domain": resolved["sender_domain"],
        "subject": resolved["subject"],
        "summary": summary,
        "context": {
            "masked_body": resolved["body"],
        },
    }


def build_slack_payload(
    record: Mapping[str, Any],
    unmask_pii: bool = False,
) -> dict[str, Any]:
    """Builds Slack Block Kit formatted alert card for Slack Incoming Webhooks.

    Args:
        record: Database triage record or DispatchPayload mapping.
        unmask_pii: Whether to unmask contact entities (default False).

    Returns:
        JSON-serializable Slack webhook payload with color attachments.
    """
    resolved = resolve_dispatch_content(record, unmask_pii=unmask_pii)

    category = str(record.get("category") or "")
    priority = str(record.get("priority") or "")
    domain = resolved.get("sender_domain") or "unknown"
    subject = resolved.get("subject") or "Alert"
    summary = str(record.get("summary") or subject)
    team = str(record.get("suggested_team") or "On-Call")

    if priority == "Critical":
        color = "#E01E5A"  # Red
        title_prefix = "🚨 [CRITICAL ALERT]"
    elif priority == "High":
        color = "#ECB22E"  # Amber
        title_prefix = "⚠️ [HIGH ALERT]"
    else:
        color = "#36C5F0"  # Blue
        title_prefix = "ℹ️ [NOTIFICATION]"  # noqa: RUF001

    return {
        "text": f"{title_prefix} {category} from {domain}: {subject}",
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": f"{title_prefix} {category}"},
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Category:*\n{category}"},
                            {"type": "mrkdwn", "text": f"*Priority:*\n{priority}"},
                            {"type": "mrkdwn", "text": f"*Domain:*\n{domain}"},
                            {"type": "mrkdwn", "text": f"*Suggested Team:*\n{team}"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*Summary:*\n{summary}"},
                    },
                ],
            }
        ],
    }
