"""Pure formatting, HTML sanitization, and correlation marker helpers for FreeScout Helpdesk.

Guarantees:
1. System-owned correlation marker is strictly anchored at index 0 of the first thread's body.
2. Untrusted customer text is HTML-escaped and wrapped in safe HTML elements to prevent Stored XSS.
3. Unicode bidirectional overrides and control characters are stripped.
4. Conforms strictly to FreeScout REST API v1 conversation and thread schemas.
"""

import html
import re
from collections.abc import Mapping
from typing import Any

from utils.unmasker import resolve_dispatch_content

MARKER_PREFIX = "<!-- triage-bot:v1"
BIDI_AND_CONTROL_RE = re.compile(
    r"[\u202a-\u202e\u2066-\u2069\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]"
)


def build_marker(idempotency_key: str, email_id: str, thread_id: str) -> str:
    """Builds a system-owned correlation marker anchored to the top of thread text.

    Args:
        idempotency_key: Outbox idempotency key string.
        email_id: Unique incoming email identifier.
        thread_id: Canonical email thread identifier.

    Returns:
        Structured marker string.
    """
    safe_key = BIDI_AND_CONTROL_RE.sub("", str(idempotency_key)).strip()
    safe_email_id = BIDI_AND_CONTROL_RE.sub("", str(email_id)).strip()
    safe_thread_id = BIDI_AND_CONTROL_RE.sub("", str(thread_id)).strip()
    return (
        f"{MARKER_PREFIX}\n"
        f"key: {safe_key}\n"
        f"email_id: {safe_email_id}\n"
        f"thread_id: {safe_thread_id}\n"
        f"-->\n"
    )


def parse_marker(text: str | None) -> dict[str, str] | None:
    """Extracts idempotency key and correlation IDs from an anchored marker at index 0 of text.

    A marker appearing later in text (e.g. injected inside customer text) or preceded
    by any characters or whitespace is strictly ignored.

    Args:
        text: Thread body string or None.

    Returns:
        Dict with 'key', 'email_id', 'thread_id' or None if not found/unanchored.
    """
    if not text or not isinstance(text, str) or not text.startswith(MARKER_PREFIX):
        return None

    end_idx = text.find("-->")
    if end_idx == -1:
        return None

    marker_content = text[len(MARKER_PREFIX) : end_idx]
    lines = [line.strip() for line in marker_content.splitlines() if line.strip()]

    extracted: dict[str, str] = {}
    for line in lines:
        if ":" in line:
            k, v = line.split(":", 1)
            extracted[k.strip()] = v.strip()

    if "key" in extracted and "email_id" in extracted and "thread_id" in extracted:
        return {
            "key": extracted["key"],
            "email_id": extracted["email_id"],
            "thread_id": extracted["thread_id"],
        }
    return None


def sanitize_html_body(text: str | None) -> str:
    """Hardens customer text into safe HTML by escaping entities and stripping bidi controls.

    Args:
        text: Raw or unmasked text string.

    Returns:
        Safe HTML string wrapped in <p> tags with <br> newlines.
    """
    if not text:
        return "<p></p>"

    # 1. Strip bidi overrides and control chars
    clean_text = BIDI_AND_CONTROL_RE.sub("", str(text))

    # 2. HTML Escape special characters to prevent Stored XSS
    escaped = html.escape(clean_text, quote=True)

    # 3. Format linebreaks
    formatted = escaped.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br>\n")

    return f"<p>{formatted}</p>"


def sanitize_subject(subject: str | None, max_len: int = 200) -> str:
    """Sanitizes subject by flattening whitespace, removing control chars, and clamping length.

    Args:
        subject: Subject line string.
        max_len: Maximum length (default 200).

    Returns:
        Clean single-line subject string.
    """
    if not subject:
        return "Customer Support Ticket"
    clean = BIDI_AND_CONTROL_RE.sub("", str(subject))
    flattened = " ".join(clean.split())
    if len(flattened) > max_len:
        return flattened[:max_len]
    return flattened or "Customer Support Ticket"


def build_conversation_payload(
    record: Mapping[str, Any],
    mailbox_id: int,
    idempotency_key: str,
    unmask_pii: bool = True,
    allowed_entity_types: set[str] | None = None,
) -> dict[str, Any]:
    """Builds a complete, hardened FreeScout conversation creation payload.

    Args:
        record: Database triage record or DispatchPayload mapping.
        mailbox_id: Configured FreeScout destination mailbox ID.
        idempotency_key: Unique composite idempotency key.
        unmask_pii: Whether to selectively unmask contact entities.
        allowed_entity_types: Optional entity types to allow.

    Returns:
        JSON-serializable FreeScout conversation dictionary.
    """
    resolved = resolve_dispatch_content(
        record,
        unmask_pii=unmask_pii,
        allowed_entity_types=allowed_entity_types,
    )

    email_id = str(record.get("email_id") or "")
    thread_id = str(record.get("thread_id") or "")

    # Customer email resolution: real sender_email if unmask_pii permitted, else synthetic
    if resolved["customer_email"] and "@" in resolved["customer_email"]:
        customer_email = resolved["customer_email"]
    else:
        domain = resolved["sender_domain"] or "customer.internal"
        customer_email = f"triage+{email_id}@{domain}"

    sanitized_subject = sanitize_subject(resolved["subject"])
    sanitized_body = sanitize_html_body(resolved["body"])
    marker = build_marker(idempotency_key, email_id, thread_id)
    thread_text = f"{marker}{sanitized_body}"

    return {
        "mailboxId": int(mailbox_id),
        "type": "email",
        "status": "active",
        "subject": sanitized_subject,
        "customer": {
            "email": customer_email,
        },
        "threads": [
            {
                "type": "customer",
                "text": thread_text,
                "customer": {
                    "email": customer_email,
                },
            }
        ],
    }


def build_thread_reply_payload(
    record: Mapping[str, Any],
    idempotency_key: str,
    unmask_pii: bool = True,
    allowed_entity_types: set[str] | None = None,
) -> dict[str, Any]:
    """Builds an append thread message payload for an existing FreeScout conversation.

    Args:
        record: Database triage record or DispatchPayload mapping.
        idempotency_key: Unique composite idempotency key.
        unmask_pii: Whether to selectively unmask contact entities.
        allowed_entity_types: Optional entity types to allow.

    Returns:
        JSON-serializable FreeScout thread append dictionary.
    """
    resolved = resolve_dispatch_content(
        record,
        unmask_pii=unmask_pii,
        allowed_entity_types=allowed_entity_types,
    )

    email_id = str(record.get("email_id") or "")
    thread_id = str(record.get("thread_id") or "")

    if resolved["customer_email"] and "@" in resolved["customer_email"]:
        customer_email = resolved["customer_email"]
    else:
        domain = resolved["sender_domain"] or "customer.internal"
        customer_email = f"triage+{email_id}@{domain}"

    sanitized_body = sanitize_html_body(resolved["body"])
    marker = build_marker(idempotency_key, email_id, thread_id)
    thread_text = f"{marker}{sanitized_body}"

    return {
        "type": "customer",
        "text": thread_text,
        "customer": {
            "email": customer_email,
        },
        "status": "active",
    }
