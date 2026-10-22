"""Node 04: Sensitive-Skip Rules and Diversion Handler.

This node acts as a deterministic, pre-LLM security and regulatory guardrail:
1. Evaluates incoming emails against high-liability legal, law-enforcement, and regulatory keywords
   (e.g., 'subpoena', 'court order', 'lawsuit', 'police', 'passport', 'wire transfer routing').
2. Detects high credential/token density (e.g. leaked secrets or credential dumps from Node 03).
3. Immediately diverts matching emails to the 'Review/Sensitive' quarantine mailbox.
4. Marks the SQLite idempotency record as 'done' with routing_status 'sensitive_diverted'.
5. Provides the LangGraph conditional router 'should_route_after_sensitive'.
"""

import re
from typing import Any, Dict, List, Optional, Tuple
import logging
from db.database import TriageDatabase
from state import TriageState
from utils.config import load_config

logger = logging.getLogger(__name__)

# Default high-liability keywords and phrases if config is unavailable
DEFAULT_SENSITIVE_KEYWORDS = [
    "passport",
    "driver's license",
    "national id",
    "nid",
    "police",
    "lawsuit",
    "court order",
    "legal notice",
    "subpoena",
    "bank account details",
    "wire transfer routing",
    "will file a chargeback",
    "filing chargeback",
    "filing a chargeback",
    "chargeback filed",
    "formal chargeback",
    "dispute notice",
    "disputing this charge",
    "my lawyer",
    "cease and desist",
    "arbitration demand",
    "gdpr erasure request",
    "gdpr",
    "erasure",
    "dsar",
    "ccpa",
    "do not sell",
    "banking details",
    "bank details",
    "wire transfer instructions",
    "routing number",
    "preservation demand",
    "litigation",
    "wage garnishment",
    "data breach",
]

DEFAULT_MAX_CODE_DENSITY = 4


def compile_keyword_patterns(keywords: List[str]) -> List[Tuple[str, re.Pattern]]:
    """Compiles case-insensitive word-boundary regex patterns for keywords.

    Args:
        keywords: List of keyword strings or multi-word phrases.

    Returns:
        List of tuples (original_keyword, compiled_regex).
    """
    patterns = []
    for kw in keywords:
        clean_kw = kw.strip()
        if not clean_kw:
            continue
        # Use \b word boundaries so e.g. 'nid' doesn't match 'denied' and 'police' doesn't match 'policy'
        escaped = re.escape(clean_kw)
        pattern = re.compile(rf"\b{escaped}\b", re.IGNORECASE)
        patterns.append((clean_kw, pattern))
    return patterns


def evaluate_sensitive(
    text: str,
    subject: str = "",
    token_map: Optional[Dict[str, str]] = None,
    config: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, Optional[str]]:
    """Evaluates whether an email triggers sensitive-skip guardrails.

    Args:
        text: Email body text (masked or cleaned).
        subject: Email subject line.
        token_map: Anonymized token dictionary from Node 03.
        config: System configuration dictionary.

    Returns:
        Tuple of (is_sensitive: bool, sensitive_reason: Optional[str]).
    """
    if config is None:
        try:
            config = load_config()
        except Exception:
            config = {}

    privacy_cfg = config.get("privacy", {})
    keywords = privacy_cfg.get("sensitive_keywords", DEFAULT_SENSITIVE_KEYWORDS)
    max_code_density = privacy_cfg.get("max_code_density", DEFAULT_MAX_CODE_DENSITY)

    combined_text = f"{subject}\n{text}" if subject else text

    # 1. Keyword / Phrase Inspection
    compiled_patterns = compile_keyword_patterns(keywords)
    for kw, pattern in compiled_patterns:
        if pattern.search(combined_text):
            return True, f"Matched sensitive keyword or phrase: '{kw}'"

    # 2. Token / Credential Density Check
    # High concentrations of leaked credentials or payment info must be diverted to human triage
    if token_map:
        sensitive_token_count = sum(
            1
            for token in token_map.keys()
            if any(
                token.startswith(prefix)
                for prefix in ("[API_KEY_", "[CREDIT_CARD_", "[SSN_", "[TAX_ID_")
            )
        )
        if sensitive_token_count > max_code_density:
            return (
                True,
                f"High credential density detected ({sensitive_token_count} tokens > max {max_code_density})",
            )

        api_keys_leaked = [k for k in token_map.keys() if k.startswith("[API_KEY_")]
        if api_keys_leaked:
            return (
                True,
                f"Customer credential leak detected ({len(api_keys_leaked)} secret key(s) in payload)",
            )

    return False, None


def sensitive_skip_node(
    state: TriageState,
    db: Optional[TriageDatabase] = None,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """LangGraph node execution function for sensitive guardrail evaluation.

    Args:
        state: Pipeline state.
        db: Optional TriageDatabase instance.
        config: Optional configuration dictionary.

    Returns:
        State dictionary update reflecting sensitivity evaluation and routing status.
    """
    subject = state.get("email_subject") or ""
    # Check masked_body first, then cleaned_body, then email_body / raw_body
    body = (
        state.get("masked_body")
        or state.get("cleaned_body")
        or state.get("email_body")
        or state.get("raw_body")
        or ""
    )
    token_map = state.get("token_map", {})
    email_id = state.get("email_id", "")

    is_sensitive, sensitive_reason = evaluate_sensitive(
        text=body,
        subject=subject,
        token_map=token_map,
        config=config,
    )

    if is_sensitive:
        logger.info(
            f"Email '{email_id}' intercepted by sensitive-skip guardrail: {sensitive_reason}"
        )
        existing_labels = list(state.get("labels_to_apply") or [])
        if "Review/Sensitive" not in existing_labels:
            existing_labels.append("Review/Sensitive")

        # Mark completed & diverted in SQLite idempotency store
        if db is not None and email_id:
            try:
                db.mark_done(
                    email_id=email_id,
                    routing_status="sensitive_diverted",
                    dispatch_target="Review/Sensitive",
                )
            except Exception as exc:
                logger.warning(
                    f"Failed to record sensitive diversion in DB for '{email_id}': {exc}"
                )

        return {
            "is_sensitive": True,
            "sensitive_reason": sensitive_reason,
            "labels_to_apply": existing_labels,
            "is_starred": True,
            "dispatch_target": "Review/Sensitive",
            "dispatch_status": "done",
            "routing_status": "sensitive_diverted",
        }

    return {
        "is_sensitive": False,
        "sensitive_reason": None,
    }


def should_route_after_sensitive(state: TriageState) -> str:
    """Conditional edge router for LangGraph after sensitive-skip evaluation.

    Args:
        state: Pipeline state.

    Returns:
        'end' if email is sensitive (quarantined), or 'continue' to proceed to Gatekeeper.
    """
    if state.get("is_sensitive", False):
        return "end"

    return "continue"
