"""Node 05: Jev AI Spam Gatekeeper and Decision Routing.

This node performs sub-second spam, threat, and legitimacy gatekeeping:
1. Thread Continuity Bypass: Automatically approves emails in active ongoing threads.
2. Inbound Classification: Evaluates inbound inquiries via Jev AI with Groq and heuristic fallbacks.
3. Decision Actions:
   - 'spam': Diverts to 'Junk/Spam', commits 'done' in SQLite, terminates triage.
   - 'manual_review': Flags with 'Review/Manual', stars message, commits 'done' in SQLite.
   - 'legitimate': Approves email ('gatekeeper_approved') to proceed to downstream triage.
4. Conditional Router: Provides 'should_route_after_gatekeeper' for LangGraph workflow execution.
"""

from typing import Any, Dict, Optional
import logging
from db.database import TriageDatabase
from state import TriageState
from utils.jev_client import (
    JevClient,
    get_default_client,
    normalize_result,
    reset_default_client,
)

logger = logging.getLogger(__name__)


def _record_and_build_gatekeeper_result(
    state: TriageState,
    decision: str,
    routing_status: str,
    dispatch_target: Optional[str],
    confidence: float,
    is_spam: bool,
    is_threat: bool,
    threat_details: Optional[str],
    classifier_used: str,
    db: Optional[TriageDatabase] = None,
    is_starred: Optional[bool] = None,
    extra_label: Optional[str] = None,
) -> Dict[str, Any]:
    """Helper to (a) build returned state, (b) perform DB write via mark_done, and (c) handle DB failures."""
    email_id = state.get("email_id", "")
    is_active_thread = bool(state.get("is_active_thread", False))
    masked_subject = state.get("masked_subject")
    masked_body = state.get("masked_body")

    existing_labels = list(state.get("labels_to_apply") or [])
    if extra_label and extra_label not in existing_labels:
        existing_labels.append(extra_label)

    if db is not None and email_id:
        try:
            db.mark_done(
                email_id=email_id,
                routing_status=routing_status,
                dispatch_target=dispatch_target,
                masked_subject=masked_subject,
                masked_body=masked_body,
                is_active_thread=is_active_thread,
                gatekeeper_decision=decision,
                gatekeeper_confidence=confidence,
                classifier_used=classifier_used,
            )
        except Exception as exc:
            # Log only exception class name and email_id, never exception text and never any email content
            logger.error(
                f"[Gatekeeper] Database write failed for email '{email_id}': {exc.__class__.__name__}"
            )
            try:
                db.mark_failed(email_id, error_message="database write failed")
            except Exception:
                pass

            res = {
                "gatekeeper_decision": decision,
                "is_spam": is_spam,
                "gatekeeper_confidence": confidence,
                "is_threat": is_threat,
                "threat_details": threat_details,
                "classifier_used": classifier_used,
                "labels_to_apply": existing_labels,
                "dispatch_status": "failed",
                "routing_status": "persist_failed",
                "error_message": "database write failed",
                "is_active_thread": is_active_thread,
            }
            if is_starred is not None:
                res["is_starred"] = is_starred
            return res

    res = {
        "gatekeeper_decision": decision,
        "is_spam": is_spam,
        "gatekeeper_confidence": confidence,
        "is_threat": is_threat,
        "threat_details": threat_details,
        "classifier_used": classifier_used,
        "labels_to_apply": existing_labels,
        "dispatch_target": dispatch_target,
        "dispatch_status": "done",
        "routing_status": routing_status,
        "is_active_thread": is_active_thread,
    }
    if is_starred is not None:
        res["is_starred"] = is_starred
    return res


def jev_gatekeeper_node(
    state: TriageState,
    client: Optional[JevClient] = None,
    db: Optional[TriageDatabase] = None,
    offline: bool = False,
) -> Dict[str, Any]:
    """LangGraph node execution function for Jev AI spam & threat gatekeeping.

    Args:
        state: Pipeline state.
        client: Optional JevClient instance (initialized from config if None).
        db: Optional TriageDatabase instance.
        offline: Whether the pipeline is running in offline mode.

    Returns:
        State dictionary updates including gatekeeper decision, confidence, and routing.
    """
    email_id = state.get("email_id", "")

    if client is None:
        client = get_default_client()

    # Fail-closed privacy safeguard: if masked_subject is missing/None, do not egress to AI
    subject = state.get("masked_subject")
    if subject is None:
        logger.warning(
            f"[Gatekeeper] Email '{email_id}' missing masked_subject; "
            "failing closed to manual_review without external AI calls."
        )
        return _record_and_build_gatekeeper_result(
            state=state,
            decision="manual_review",
            routing_status="manual_review",
            dispatch_target="Review/Manual",
            confidence=0.0,
            is_spam=False,
            is_threat=False,
            threat_details="Missing masked_subject privacy safeguard triggered",
            classifier_used="fail_closed",
            db=db,
            is_starred=True,
            extra_label="Review/Manual",
        )

    # Fail-closed privacy safeguard (A8): if spaCy is missing or failed while external AI is enabled,
    # send nothing outside (no Jev, no Groq call) and route to manual_review with dispatch_status done.
    from nodes.pii_masker import is_spacy_available, is_external_ai_enabled

    ext_ai = is_external_ai_enabled(client=client, offline=offline)
    if ext_ai and (state.get("spacy_failed") or not is_spacy_available()):
        logger.warning(
            f"[Gatekeeper] spaCy unavailable for email '{email_id}' while external AI enabled; "
            "failing closed to manual_review without external AI calls."
        )
        return _record_and_build_gatekeeper_result(
            state=state,
            decision="manual_review",
            routing_status="manual_review",
            dispatch_target="Review/Manual",
            confidence=0.0,
            is_spam=False,
            is_threat=False,
            threat_details="spaCy model unavailable while external AI enabled",
            classifier_used="fail_closed",
            db=db,
            is_starred=True,
            extra_label="Review/Manual",
        )

    # Use masked_body if available to protect PII, falling back to cleaned or raw body
    body = (
        state.get("masked_body")
        or state.get("cleaned_body")
        or state.get("email_body")
        or state.get("raw_body")
        or ""
    )

    # Send only the sender domain (never the full email address or username)
    sender = state.get("sender_domain") or ""
    if not sender:
        sender_email = state.get("sender_email") or ""
        if "@" in sender_email:
            sender = sender_email.split("@")[-1].strip().rstrip(">").lower()
        else:
            sender = sender_email

    # 1. Gatekeeper Evaluation (Jev AI -> Groq Fallback -> Heuristics)
    # Active thread replies are fully inspected for threats, injections, and spam
    raw_result = client.classify(subject=subject, body=body, sender=sender)
    client_config = getattr(client, "config", None)
    result = normalize_result(raw_result, config=client_config)

    decision = result.get("decision", "manual_review")
    confidence = float(result.get("confidence", 0.0))
    is_spam = bool(result.get("is_spam", decision == "spam"))
    is_threat = bool(result.get("is_threat", False))
    threat_details = result.get("threat_details")
    classifier_used = result.get("classifier_used", "regex")

    # Structured one-line audit log per email
    logger.info(
        f"[Gatekeeper] Email '{email_id}' evaluated by engine='{classifier_used}' -> "
        f"decision='{decision}', confidence={confidence:.2f}"
    )

    # 2. Decision Dispatch Mapping
    if decision == "spam":
        logger.info(
            f"Email '{email_id}' flagged as SPAM by gatekeeper: {threat_details}"
        )
        return _record_and_build_gatekeeper_result(
            state=state,
            decision="spam",
            routing_status="spam_skipped",
            dispatch_target="Junk/Spam",
            confidence=confidence,
            is_spam=True,
            is_threat=is_threat,
            threat_details=threat_details,
            classifier_used=classifier_used,
            db=db,
            extra_label="Junk/Spam",
        )

    if decision == "manual_review":
        logger.info(f"Email '{email_id}' flagged for MANUAL REVIEW by gatekeeper.")
        return _record_and_build_gatekeeper_result(
            state=state,
            decision="manual_review",
            routing_status="manual_review",
            dispatch_target="Review/Manual",
            confidence=confidence,
            is_spam=is_spam,
            is_threat=is_threat,
            threat_details=threat_details,
            classifier_used=classifier_used,
            db=db,
            is_starred=True,
            extra_label="Review/Manual",
        )

    # 3. Legitimate Inbound Approval
    logger.info(
        f"Email '{email_id}' approved as LEGITIMATE (confidence: {confidence:.2f})."
    )
    return _record_and_build_gatekeeper_result(
        state=state,
        decision="legitimate",
        routing_status="gatekeeper_approved",
        dispatch_target=None,
        confidence=confidence,
        is_spam=False,
        is_threat=is_threat,
        threat_details=threat_details,
        classifier_used=classifier_used,
        db=db,
    )


def should_route_after_gatekeeper(state: TriageState) -> str:
    """Conditional router for LangGraph after gatekeeper classification.

    Args:
        state: Pipeline state.

    Returns:
        'continue' if email is approved and DB persist succeeded; 'end' otherwise.
    """
    decision = state.get("gatekeeper_decision")
    dispatch_status = state.get("dispatch_status")
    routing_status = state.get("routing_status")

    if (
        decision == "legitimate"
        and dispatch_status != "failed"
        and routing_status != "persist_failed"
    ):
        return "continue"

    return "end"
