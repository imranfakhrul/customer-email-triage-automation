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
from utils.jev_client import JevClient

logger = logging.getLogger(__name__)


def jev_gatekeeper_node(
    state: TriageState,
    client: Optional[JevClient] = None,
    db: Optional[TriageDatabase] = None,
) -> Dict[str, Any]:
    """LangGraph node execution function for Jev AI spam & threat gatekeeping.

    Args:
        state: Pipeline state.
        client: Optional JevClient instance (initialized from config if None).
        db: Optional TriageDatabase instance.

    Returns:
        State dictionary updates including gatekeeper decision, confidence, and routing.
    """
    email_id = state.get("email_id", "")
    is_active_thread = state.get("is_active_thread", False)

    # 1. Active Thread Continuity Bypass
    # Ongoing customer conversations bypass gatekeeping to minimize latency and false flags
    if is_active_thread:
        logger.info(
            f"Email '{email_id}' belongs to an active thread; bypassing gatekeeper check."
        )
        return {
            "gatekeeper_decision": "legitimate",
            "is_spam": False,
            "gatekeeper_confidence": 1.0,
            "is_threat": False,
            "threat_details": None,
            "classifier_used": "thread_continuity",
            "routing_status": "active_thread_continuation",
        }

    if client is None:
        client = JevClient()

    subject = state.get("email_subject") or ""
    # Use masked_body if available to protect PII, falling back to cleaned or raw body
    body = (
        state.get("masked_body")
        or state.get("cleaned_body")
        or state.get("email_body")
        or state.get("raw_body")
        or ""
    )
    sender = state.get("sender_email") or ""

    # 2. Gatekeeper Evaluation (Jev AI -> Groq Fallback -> Heuristics)
    result = client.classify(subject=subject, body=body, sender=sender)
    decision = result.get("decision", "legitimate")
    confidence = float(result.get("confidence", 0.85))
    is_spam = bool(result.get("is_spam", decision == "spam"))
    is_threat = bool(result.get("is_threat", False))
    threat_details = result.get("threat_details")
    classifier_used = result.get("classifier_used", "regex")

    # Structured one-line audit log per email
    logger.info(
        f"[Gatekeeper] Email '{email_id}' evaluated by engine='{classifier_used}' -> "
        f"decision='{decision}', confidence={confidence:.2f}"
    )

    existing_labels = list(state.get("labels_to_apply") or [])

    # 3. Decision Dispatch Mapping
    if decision == "spam":
        logger.info(
            f"Email '{email_id}' flagged as SPAM by gatekeeper: {threat_details}"
        )
        if "Junk/Spam" not in existing_labels:
            existing_labels.append("Junk/Spam")

        if db is not None and email_id:
            try:
                db.mark_done(
                    email_id=email_id,
                    routing_status="spam_skipped",
                    dispatch_target="Junk/Spam",
                )
            except Exception as exc:
                logger.warning(f"Failed to record spam diversion in DB: {exc}")

        return {
            "gatekeeper_decision": "spam",
            "is_spam": True,
            "gatekeeper_confidence": confidence,
            "is_threat": is_threat,
            "threat_details": threat_details,
            "classifier_used": classifier_used,
            "labels_to_apply": existing_labels,
            "dispatch_target": "Junk/Spam",
            "dispatch_status": "done",
            "routing_status": "spam_skipped",
        }

    if decision == "manual_review":
        logger.info(f"Email '{email_id}' flagged for MANUAL REVIEW by gatekeeper.")
        if "Review/Manual" not in existing_labels:
            existing_labels.append("Review/Manual")

        if db is not None and email_id:
            try:
                db.mark_done(
                    email_id=email_id,
                    routing_status="manual_review",
                    dispatch_target="Review/Manual",
                )
            except Exception as exc:
                logger.warning(f"Failed to record manual review diversion in DB: {exc}")

        return {
            "gatekeeper_decision": "manual_review",
            "is_spam": False,
            "gatekeeper_confidence": confidence,
            "is_threat": is_threat,
            "threat_details": threat_details,
            "classifier_used": classifier_used,
            "labels_to_apply": existing_labels,
            "is_starred": True,
            "dispatch_target": "Review/Manual",
            "dispatch_status": "done",
            "routing_status": "manual_review",
        }

    # Legitimate Inbound
    logger.info(
        f"Email '{email_id}' approved as LEGITIMATE (confidence: {confidence:.2f})."
    )
    return {
        "gatekeeper_decision": "legitimate",
        "is_spam": False,
        "gatekeeper_confidence": confidence,
        "is_threat": is_threat,
        "threat_details": threat_details,
        "classifier_used": classifier_used,
        "routing_status": "gatekeeper_approved",
        "dispatch_status": "processing",
    }


def should_route_after_gatekeeper(state: TriageState) -> str:
    """Conditional router for LangGraph after gatekeeper classification.

    Args:
        state: Pipeline state.

    Returns:
        'end' if email is spam or routed to manual review; 'continue' if approved.
    """
    decision = state.get("gatekeeper_decision")
    if decision in ("spam", "manual_review"):
        return "end"

    return "continue"
