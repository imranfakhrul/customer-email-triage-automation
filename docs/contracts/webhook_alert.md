# Webhook Alert Adapter Contract

## 1. Overview
This document specifies the HTTP API contract for the Customer Email Triage Automation pipeline delivering real-time, cryptographically authenticated webhook alerts for critical outages and urgent billing disputes.

## 2. Triggering Triggers (Dispatcher Matrix)
Webhooks are fired for:
1. **Critical Outages:** `Bug Report`, `General Query`, or `Complaint` with `priority == "Critical"`.
2. **Urgent Billing Disputes:** `Billing Issue` or `Refund Request` with `priority in ("High", "Critical")`.
3. **Security Inquiries:** `Security/Account` category (requires prior human HITL approval).

## 3. Cryptographic Authenticity & Security Headers
Every HTTP POST transmission includes:
- `X-Signature-SHA256`: `sha256=<hex_digest>` computed using HMAC-SHA256 over the exact UTF-8 raw request payload body using the shared secret (`WEBHOOK_SECRET_KEY`).
- `X-Timestamp-ISO`: Aware UTC ISO-8601 timestamp (e.g. `2026-10-28T14:55:00Z`). Receivers reject requests with drift exceeding 300 seconds (5 minutes) to prevent replay attacks.
- `Idempotency-Key`: Composite idempotency key (`{email_id}:webhook:alert`).
- `X-Correlation-ID`: Trace identifier (`{email_id}`).
- `Content-Type`: `application/json`
- `User-Agent`: `Customer-Email-Triage-Automation`

## 4. Privacy Guard (Channel Privacy Invariant #1)
- **Default Policy:** `unmask_pii: false`.
- Because webhook alerts frequently deliver to shared incident channels (Slack `#ops-alerts`, `#billing-triage`, Microsoft Teams, Discord), **zero customer PII (unmasked name, customer email, credit card, phone)** is included.
- Only structured incident metadata, `sender_domain`, and `masked_subject` / `masked_body` are transmitted.

## 5. Payload Schemas

### 5.1 Standard JSON Alert Schema
```json
{
  "event": "customer_email_triage.alert",
  "alert_type": "critical_outage",
  "email_id": "em_001",
  "timestamp": "2026-10-28T14:55:00Z",
  "category": "Bug Report",
  "priority": "Critical",
  "sentiment": "Negative",
  "customer_emotion": "Angry",
  "suggested_team": "Engineering",
  "confidence": 0.98,
  "sender_domain": "enterprise.com",
  "subject": "Production database down",
  "summary": "Customer reports all production API nodes crashing",
  "context": {
    "masked_body": "Hi, I am [PERSON_1]. Our database is down..."
  }
}
```

### 5.2 Slack Block Kit Format (Auto-detected if target is `hooks.slack.com`)
```json
{
  "text": "🚨 [CRITICAL ALERT] Bug Report from enterprise.com: Production database down",
  "attachments": [
    {
      "color": "#E01E5A",
      "blocks": [
        {
          "type": "header",
          "text": {"type": "plain_text", "text": "🚨 Critical Outage Alert"}
        },
        {
          "type": "section",
          "fields": [
            {"type": "mrkdwn", "text": "*Category:*\nBug Report"},
            {"type": "mrkdwn", "text": "*Priority:*\nCritical"},
            {"type": "mrkdwn", "text": "*Domain:*\nenterprise.com"},
            {"type": "mrkdwn", "text": "*Suggested Team:*\nEngineering"}
          ]
        },
        {
          "type": "section",
          "text": {"type": "mrkdwn", "text": "*Summary:*\nCustomer reports all production API nodes crashing"}
        }
      ]
    }
  ]
}
```

## 6. Error Handling & Retry Policies
- `200 / 201 / 204 / "ok"`: Success -> `DispatchResult(remote_id="webhook:{email_id}")`
- `429 Too Many Requests`: `AdapterTransientError("webhook_rate_limited")`
- `502 / 503 / 504`: `AdapterTransientError("webhook_service_unavailable")`
- `400 Bad Request`: `AdapterPermanentError("webhook_invalid_payload")`
- `401 / 403`: `AdapterPermanentError("webhook_auth_failed")`
- Post-send Timeout: `AdapterUnknownOutcomeError("webhook_network_timeout")`
