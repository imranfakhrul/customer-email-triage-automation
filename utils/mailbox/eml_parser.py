"""Native RFC 822 / MIME (.eml) email parser for enterprise mailbox ingestion.

Parses raw email files or byte streams into normalized triage intake dictionaries
without external third-party dependencies (pure standard library email package).
"""

from __future__ import annotations

import email
import re
import uuid
from email import policy
from typing import Any


def parse_eml_bytes(data: bytes) -> dict[str, Any]:
    """Parses raw RFC 822 / MIME bytes into normalized email triage state.

    Args:
        data: Raw email bytes (UTF-8, ASCII, or ISO-8859 with MIME boundaries).

    Returns:
        Normalized dictionary ready for pipeline.prepare_initial_state().
    """
    msg = email.message_from_bytes(data, policy=policy.default)

    subject = str(msg.get("Subject", "")).strip()
    from_hdr = msg.get("From")
    from_raw = str(from_hdr or "").strip()
    message_id = str(msg.get("Message-ID") or f"<eml_{uuid.uuid4().hex[:12]}@local>")

    # Extract sender email and domain
    sender_email = from_raw
    if from_hdr is not None and hasattr(from_hdr, "addresses"):
        addresses = getattr(from_hdr, "addresses", None)
        if addresses:
            sender_email = str(addresses[0].addr_spec)
    elif "@" in from_raw:
        match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", from_raw)
        if match:
            sender_email = match.group(0)

    sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else "unknown.domain"

    # Thread continuity: extract In-Reply-To or References header
    thread_id = str(msg.get("In-Reply-To") or msg.get("References") or message_id).strip()

    # Body extraction: navigate multipart to find plain text, with HTML fallback
    plain_body = ""
    html_body = ""

    body_part = msg.get_body(preferencelist=("plain", "html"))
    if body_part:
        content = body_part.get_content()
        if body_part.get_content_type() == "text/plain":
            plain_body = str(content)
        else:
            html_body = str(content)

    if not plain_body and html_body:
        from utils.mailbox.gmail_connector import _clean_html_text

        resolved_body = _clean_html_text(html_body)
    elif plain_body:
        resolved_body = plain_body
    else:
        # Fallback to direct payload string if non-multipart
        payload_data = msg.get_payload()
        if isinstance(payload_data, str):
            resolved_body = payload_data
        elif isinstance(payload_data, list) and payload_data:
            first_part = payload_data[0]
            if isinstance(first_part, email.message.Message):
                raw_sub = first_part.get_payload(decode=True)
                if isinstance(raw_sub, bytes):
                    resolved_body = raw_sub.decode("utf-8", errors="replace")
                elif isinstance(raw_sub, str):
                    resolved_body = raw_sub
                else:
                    resolved_body = ""
            elif isinstance(first_part, str):
                resolved_body = first_part
            else:
                resolved_body = ""
        else:
            resolved_body = ""

    # Authentication status evaluation
    auth_results = str(msg.get("Authentication-Results", "")).lower()
    received_spf = str(msg.get("Received-SPF", "")).lower()

    if "dkim=pass" in auth_results or "spf=pass" in auth_results or "pass" in received_spf:
        auth_status = "pass"
    elif "fail" in auth_results or "softfail" in auth_results:
        auth_status = "fail"
    else:
        auth_status = "none"

    email_id = f"em_eml_{uuid.uuid4().hex[:8]}"

    return {
        "email_id": email_id,
        "message_id": message_id,
        "thread_id": thread_id,
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "email_subject": subject or "(No Subject)",
        "email_body": resolved_body,
        "raw_body": resolved_body,
        "has_attachments": bool(list(msg.iter_attachments())),
        "auth_status": auth_status,
    }


def parse_eml_file(file_path: str) -> dict[str, Any]:
    """Reads and parses an RFC 822 .eml file from disk.

    Args:
        file_path: Absolute or relative path to the .eml file.

    Returns:
        Normalized dictionary ready for pipeline.prepare_initial_state().
    """
    with open(file_path, "rb") as f:
        return parse_eml_bytes(f.read())
