"""Output formatting, formula injection defanging, and lead scoring for CRM adapters.

Guarantees:
1. Formula / CSV Injection Defanging: Strings starting with formula trigger chars
   (=, +, -, @, \\t, \\r) are prepended with a single quote (') to neutralize
   arbitrary code execution when leads are exported to Excel or Google Sheets.
2. Freemail Filtering: Detects personal freemail providers to distinguish corporate prospects.
3. Deterministic Lead Scoring: Bounded 0-100 score evaluating inquiry intent, priority,
   domain authority, and customer sentiment.
4. Universal Selective Unmasking: Restores contact context (PERSON, EMAIL, PHONE, IP_ADDRESS)
   while strictly keeping secrets (CREDIT_CARD, SSN, IBAN, API_KEY) masked.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from utils.unmasker import resolve_dispatch_content

# Unicode bidi override characters and ASCII control codes (excluding safe whitespace)
BIDI_AND_CONTROL_RE = re.compile(
    r"[\u200e\u200f\u202a-\u202e\u2066-\u2069\x00-\x08\x0b\x0c\x0e-\x1f]"
)

# Characters that trigger spreadsheet formula calculation in CSV exports
FORMULA_TRIGGER_CHARS = ("=", "+", "-", "@", "\t", "\r")

# Well-known free/public webmail domains
FREEMAIL_DOMAINS: frozenset[str] = frozenset(
    {
        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "outlook.com",
        "live.com",
        "msn.com",
        "icloud.com",
        "me.com",
        "mac.com",
        "aol.com",
        "proton.me",
        "protonmail.com",
        "mail.com",
        "zoho.com",
        "yandex.com",
        "gmx.com",
    }
)


# Regex matching standard international phone format (e.g. +1-555-0199, +44 20 7123 4567)
PHONE_SAFE_RE = re.compile(r"^\+[0-9\s\-\(\)\.]{6,25}$")


def sanitize_crm_field(text: str | None) -> str:
    """Sanitizes CRM string fields against formula injection and control characters.

    Args:
        text: Raw input text.

    Returns:
        Formula-defanged string with control chars stripped.
    """
    if text is None:
        return ""

    # 1. Strip bidi controls and non-printable control codes
    clean = BIDI_AND_CONTROL_RE.sub("", str(text))
    if not clean:
        return ""

    # 2. Check if stripped text starts with formula triggers
    stripped_leading = clean.lstrip(" \t\r\n")
    if stripped_leading and stripped_leading[0] in FORMULA_TRIGGER_CHARS:
        # Allow standard international phone numbers starting with '+'
        if stripped_leading.startswith("+") and PHONE_SAFE_RE.match(stripped_leading):
            return clean
        return f"'{stripped_leading}"

    return clean


def is_freemail_domain(domain: str | None) -> bool:
    """Checks whether a domain belongs to a known public freemail provider.

    Args:
        domain: Domain name string (e.g. 'gmail.com').

    Returns:
        True if freemail provider, False otherwise.
    """
    if not domain:
        return False
    clean = domain.strip().lower()
    return clean in FREEMAIL_DOMAINS


def extract_company_domain(sender_email: str | None, sender_domain: str | None) -> str:
    """Derives corporate company domain, filtering out freemail providers.

    Args:
        sender_email: Prospect's email address.
        sender_domain: Prospect's email domain.

    Returns:
        Corporate domain string or empty string if freemail / absent.
    """
    candidate = str(sender_domain or "").strip().lower()
    if not candidate and sender_email and "@" in sender_email:
        candidate = sender_email.split("@", 1)[1].strip().lower()

    if candidate and not is_freemail_domain(candidate):
        return candidate
    return ""


def calculate_lead_score(
    category: str | None,
    priority: str | None,
    domain: str | None,
    sentiment: str | None,
) -> int:
    """Calculates a deterministic qualification score (0-100) for inbound leads.

    Args:
        category: Classified intent category.
        priority: Urgency / Priority level.
        domain: Prospect sender domain.
        sentiment: Classified sentiment.

    Returns:
        Integer score clamped to [0, 100].
    """
    cat = (category or "").strip()
    prio = (priority or "").strip()
    sent = (sentiment or "").strip().capitalize()

    # Base category weight
    if cat == "Demo Request":
        score = 70
    elif cat == "Pricing Inquiry":
        score = 60
    else:
        score = 30

    # Priority bonus
    if prio == "Critical":
        score += 20
    elif prio == "High":
        score += 15
    elif prio == "Medium":
        score += 5

    # Corporate domain bonus
    if domain and not is_freemail_domain(domain):
        score += 15

    # Sentiment adjustment
    if sent == "Positive":
        score += 5
    elif sent == "Negative":
        score -= 10

    return max(0, min(100, score))


def _extract_contact_names(token_map: Mapping[str, Any] | None) -> tuple[str, str]:
    """Extracts first and last name from token_map PERSON tokens if available."""
    if not token_map or not isinstance(token_map, Mapping):
        return "Prospect", ""

    for token, val in token_map.items():
        if isinstance(token, str) and token.startswith("[PERSON_"):
            full_name = str(val).strip()
            if full_name:
                parts = full_name.split(None, 1)
                firstname = parts[0]
                lastname = parts[1] if len(parts) > 1 else ""
                return firstname, lastname

    return "Prospect", ""


def _extract_contact_phone(token_map: Mapping[str, Any] | None) -> str:
    """Extracts phone number from token_map PHONE tokens if available."""
    if not token_map or not isinstance(token_map, Mapping):
        return ""

    for token, val in token_map.items():
        if isinstance(token, str) and token.startswith("[PHONE_"):
            phone = str(val).strip()
            if phone:
                return phone

    return ""


def build_hubspot_payload(
    record: Mapping[str, Any],
    idempotency_key: str,
    unmask_pii: bool = True,
) -> dict[str, Any]:
    """Builds a hardened HubSpot Contact/Lead ingestion payload.

    Args:
        record: Database triage record or DispatchPayload mapping.
        idempotency_key: Unique composite idempotency key.
        unmask_pii: Whether to selectively unmask contact entities.

    Returns:
        JSON-serializable HubSpot Contact API payload.
    """
    resolved = resolve_dispatch_content(record, unmask_pii=unmask_pii)

    email_id = str(record.get("email_id") or "")
    sender_domain = resolved.get("sender_domain") or ""
    company = extract_company_domain(
        resolved.get("customer_email") or str(record.get("sender_email") or ""),
        sender_domain,
    )

    if resolved.get("customer_email") and "@" in resolved["customer_email"]:
        customer_email = resolved["customer_email"]
    else:
        domain = sender_domain or "prospect.internal"
        customer_email = f"lead+{email_id}@{domain}"

    token_map = record.get("token_map")
    if unmask_pii and isinstance(token_map, Mapping):
        firstname, lastname = _extract_contact_names(token_map)
        phone = _extract_contact_phone(token_map)
    else:
        firstname, lastname = "Prospect", ""
        phone = ""

    category = str(record.get("category") or "")
    priority = str(record.get("priority") or "")
    sentiment = str(record.get("sentiment") or "")
    score = calculate_lead_score(
        category=category,
        priority=priority,
        domain=sender_domain,
        sentiment=sentiment,
    )

    raw_message = (resolved.get("body") or "").strip()
    sanitized_message = sanitize_crm_field(raw_message)

    return {
        "properties": {
            "email": customer_email,
            "firstname": sanitize_crm_field(firstname),
            "lastname": sanitize_crm_field(lastname),
            "phone": sanitize_crm_field(phone),
            "company": sanitize_crm_field(company),
            "hs_lead_status": "NEW",
            "lead_score": str(score),
            "triage_email_id": email_id,
            "triage_idempotency_key": idempotency_key,
            "message": sanitized_message,
        }
    }
