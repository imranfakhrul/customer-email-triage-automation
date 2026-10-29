"""Universal selective unmasking and content resolution helper for destination adapters.

Guarantees:
1. Invariant: When unmask_pii=False, returns strictly masked text, sender domain,
   and zero customer email.
2. Invariant: When unmask_pii=True, restores allowed contact and technical entities
   (PERSON, EMAIL, PHONE, IP_ADDRESS) and provides real sender_email as customer_email.
3. Invariant: High-risk secrets (CREDIT_CARD, SSN, IBAN, API_KEY) and token_map NEVER leave
   the machine unmasked under any configuration.
4. Lifecyle Fallback: If token_map is absent (e.g. standalone worker mode), binds customer_email
   to sender_email and optionally invokes mailbox_fetcher before falling back to masked_body.
"""

import logging
from collections.abc import Callable, Mapping
from typing import Any

logger = logging.getLogger(__name__)


def unmask_text(text: str, token_map: Mapping[str, str]) -> str:
    """Restores masked tokens back to their original values.

    Args:
        text: Masked text string.
        token_map: Dictionary mapping [TOKEN_N_nonce] -> original value.

    Returns:
        Original unmasked text string.
    """
    if not text or not token_map:
        return text or ""

    restored = text
    # Sort tokens by length in descending order to prevent sub-token replacement collisions
    for token in sorted(token_map.keys(), key=len, reverse=True):
        if token.startswith("__"):
            continue
        restored = restored.replace(token, str(token_map[token]))
    return restored


# Safe default contact entities allowed to be restored for authorized destinations (FreeScout, CRM)
DEFAULT_SAFE_UNMASK_ENTITIES: set[str] = {"PERSON", "EMAIL", "PHONE", "IP_ADDRESS"}

# High-risk financial and auth secrets that must NEVER be unmasked in downstream tickets/leads
HIGH_RISK_SECRET_ENTITIES: set[str] = {"CREDIT_CARD", "SSN", "IBAN", "API_KEY"}

KNOWN_ENTITY_TYPES: tuple[str, ...] = (
    "CREDIT_CARD",
    "IP_ADDRESS",
    "API_KEY",
    "PERSON",
    "EMAIL",
    "PHONE",
    "SSN",
    "IBAN",
)


def extract_entity_type_from_token(token: str) -> str | None:
    """Extracts entity type from a placeholder token such as [PERSON_1_a1b2] or [IP_ADDRESS_2_c3d4].

    Args:
        token: Masked placeholder token enclosed in brackets.

    Returns:
        Recognized entity type string or None.
    """
    if not (isinstance(token, str) and token.startswith("[") and token.endswith("]")):
        return None
    inner = token[1:-1]
    for known in KNOWN_ENTITY_TYPES:
        if inner.startswith(f"{known}_"):
            return known
    parts = inner.split("_")
    return parts[0] if parts else None


def resolve_dispatch_content(
    record: Mapping[str, Any],
    unmask_pii: bool = False,
    allowed_entity_types: set[str] | None = None,
    mailbox_fetcher: Callable[[str], str | None] | None = None,
) -> dict[str, Any]:
    """Resolves outbound subject, body, and customer identity based on destination privacy policy.

    Args:
        record: Mapping containing email metadata, classification fields, and masked text.
        unmask_pii: If True, selectively unmasks allowed entities and provides real sender email.
        allowed_entity_types: Optional set of allowed entity types
            (defaults to DEFAULT_SAFE_UNMASK_ENTITIES).
        mailbox_fetcher: Optional callback to re-fetch raw body by message_id
            when token_map is absent.

    Returns:
        Dictionary containing resolved subject, body, customer_email, sender_domain,
        is_unmasked flag, and tuple of restored_entity_types.
    """
    masked_subject_val = record.get("masked_subject")
    masked_body_val = record.get("masked_body")
    if masked_subject_val is None or masked_body_val is None:
        raise ValueError(
            "Missing required masked text: 'masked_subject' and 'masked_body' must be present"
        )

    masked_subject = str(masked_subject_val)
    masked_body = str(masked_body_val)
    sender_email = str(record.get("sender_email") or "").strip()
    sender_domain = str(record.get("sender_domain") or "").strip().lower()

    if not sender_domain and "@" in sender_email:
        sender_domain = sender_email.split("@", 1)[1].lower()

    if not unmask_pii:
        return {
            "subject": masked_subject,
            "body": masked_body,
            "customer_email": None,
            "sender_domain": sender_domain,
            "is_unmasked": False,
            "restored_entity_types": (),
        }

    # Selective unmasking mode
    if allowed_entity_types is not None:
        target_allowed = set(allowed_entity_types)
    else:
        target_allowed = set(DEFAULT_SAFE_UNMASK_ENTITIES)

    # Invariant: High-risk secrets can NEVER be unmasked
    safe_allowed = target_allowed - HIGH_RISK_SECRET_ENTITIES

    token_map = record.get("token_map")
    restored_types: set[str] = set()
    subject = masked_subject
    body = masked_body

    if isinstance(token_map, dict) and token_map:
        filtered_tokens: dict[str, str] = {}
        for token, original_val in token_map.items():
            if not isinstance(token, str) or token.startswith("__"):
                continue
            etype = extract_entity_type_from_token(token)
            if etype and etype in safe_allowed:
                filtered_tokens[token] = str(original_val)
                restored_types.add(etype)

        if filtered_tokens:
            subject = unmask_text(masked_subject, filtered_tokens)
            body = unmask_text(masked_body, filtered_tokens)
    else:
        # Token map is absent (e.g. SQLite worker mode)
        message_id = str(record.get("message_id") or "")
        if mailbox_fetcher and message_id:
            try:
                fetched_body = mailbox_fetcher(message_id)
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    f"[Unmasker] Mailbox fetch failed for '{message_id}': {type(e).__name__}"
                )
                fetched_body = None

            if fetched_body is not None:
                # Lazy import avoids circular import (nodes -> dispatcher -> adapters -> unmasker)
                from nodes.pii_masker import mask_pii

                # Invariant 1: Re-mask re-fetched text so that high-risk secrets
                # (CREDIT_CARD, SSN, IBAN, API_KEY) remain strictly masked
                re_masked_body, re_token_map = mask_pii(str(fetched_body))
                re_filtered_tokens: dict[str, str] = {}
                for token, original_val in re_token_map.items():
                    if not isinstance(token, str) or token.startswith("__"):
                        continue
                    etype = extract_entity_type_from_token(token)
                    if etype and etype in safe_allowed:
                        re_filtered_tokens[token] = str(original_val)
                        restored_types.add(etype)

                if re_filtered_tokens:
                    body = unmask_text(re_masked_body, re_filtered_tokens)
                else:
                    body = re_masked_body

    customer_email = sender_email if sender_email else None

    return {
        "subject": subject,
        "body": body,
        "customer_email": customer_email,
        "sender_domain": sender_domain,
        "is_unmasked": True,
        "restored_entity_types": tuple(sorted(restored_types)),
    }
