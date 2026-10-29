"""Node 07: Human-in-the-Loop (HITL) Review Queue Router & State Gating.

This node evaluates automated email classifications against safety gating rules:
1. Threat & Injection Pre-Filter: prompt injection or security threats flagged by the classifier.
2. Missing or Malformed Content: classification is missing, malformed, or category is "Other".
3. Policy Category Review: categories listed in `classification.always_review_categories`
   (e.g. "Security/Account") require mandatory human review regardless of confidence or emotion.
4. Low Confidence: confidence < hitl_threshold (default 0.85).
5. Customer Escalation: Frustrated/Angry emotion with Critical/High priority.

Diverted emails receive `hitl_status = "pending"` and `p2_status = "hitl_pending"`.
Approved machine-evaluated emails receive `hitl_status = "auto_approved"` and `p2_status = "auto_approved"`.
Phase 1 data is never overwritten.
"""

import logging
from typing import Any, Dict, Optional

from db.database import TriageDatabase
from state import EmailClassification, TriageState
from utils.config import get_config

logger = logging.getLogger(__name__)


def hitl_queue_node(
    state: TriageState,
    db: Optional[TriageDatabase] = None,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Evaluates classification against HITL gating rules and persists review state.

    Args:
        state: Current LangGraph triage state.
        db: Optional TriageDatabase instance for persistence.
        config: Optional configuration dictionary. Broken configs raise ConfigError (B5).

    Returns:
        State update dictionary containing hitl_status, hitl_reason, and p2_status.
        Does NOT return routing_status or dispatch_target.
    """
    if config is None:
        config = get_config()

    class_cfg = config.get("classification", {}) if isinstance(config, dict) else {}
    hitl_threshold = float(class_cfg.get("hitl_threshold", 0.85))
    always_review_categories = class_cfg.get("always_review_categories", ["Security/Account"])
    if not isinstance(always_review_categories, list):
        always_review_categories = ["Security/Account"]

    email_id = state.get("email_id", "<unknown>")
    classification = state.get("classification")
    p2_classifier_used = state.get("p2_classifier_used", "offline_heuristic")

    # PRR-01: Check if a human reviewer already resolved this email (approved or rejected)
    prior_hitl_status = state.get("hitl_status")
    if db is not None and prior_hitl_status not in ("approved", "rejected"):
        try:
            db_hitl = db.get_hitl_status(email_id)
            if db_hitl in ("approved", "rejected"):
                prior_hitl_status = db_hitl
        except Exception as exc:
            logger.debug(
                "[Node 07: HITL] Could not check db hitl_status for %s: %s",
                email_id,
                exc.__class__.__name__,
            )

    if prior_hitl_status == "approved":
        logger.info(
            f"[Node 07: HITL] Email '{email_id}' was human-approved; passing directly to dispatcher."
        )
        return {
            "hitl_status": "approved",
            "hitl_reason": None,
            "p2_status": "auto_approved",
        }
    if prior_hitl_status == "rejected":
        logger.info(
            f"[Node 07: HITL] Email '{email_id}' was human-rejected; terminating dispatch."
        )
        return {
            "hitl_status": "rejected",
            "hitl_reason": "Rejected by human reviewer",
            "p2_status": "failed",
            "dispatch_status": "rejected",
        }

    cat: Optional[str] = None
    prio: Optional[str] = None
    sent: Optional[str] = None
    emotion: str = "Calm"
    conf: Optional[float] = None
    team: str = "Support"
    summary: str = ""

    if isinstance(classification, EmailClassification):
        cat = classification.category
        prio = classification.priority
        sent = classification.sentiment
        emotion = classification.customer_emotion
        conf = classification.confidence
        team = classification.suggested_team
        summary = classification.summary
    elif isinstance(classification, dict):
        cat = classification.get("category")
        prio = classification.get("priority")
        sent = classification.get("sentiment")
        emotion = classification.get("customer_emotion", "Calm")
        conf_raw = classification.get("confidence")
        conf = float(conf_raw) if conf_raw is not None else None
        team = classification.get("suggested_team", "Support")
        summary = classification.get("summary", "")
    elif classification is not None:
        cat = getattr(classification, "category", None)
        prio = getattr(classification, "priority", None)
        sent = getattr(classification, "sentiment", None)
        emotion = getattr(classification, "customer_emotion", "Calm")
        conf_raw = getattr(classification, "confidence", None)
        conf = float(conf_raw) if conf_raw is not None else None
        team = getattr(classification, "suggested_team", "Support")
        summary = getattr(classification, "summary", "")

    divert_to_hitl = False
    hitl_reason: Optional[str] = None

    # Condition 1: Threat / Prompt injection pre-filter flagged
    is_threat = state.get("is_threat", False)
    if is_threat or p2_classifier_used == "regex_filter" or "prompt injection" in summary.lower():
        divert_to_hitl = True
        hitl_reason = "Prompt injection pre-filter flagged"
    # Condition 2: Missing or malformed classification
    elif classification is None or cat is None or conf is None:
        divert_to_hitl = True
        hitl_reason = "Missing or malformed classification"
    # Condition 3: Always-review categories policy (e.g. Security/Account)
    elif cat in always_review_categories:
        divert_to_hitl = True
        hitl_reason = f"Category '{cat}' requires mandatory human review"
    # Condition 4: Unclassified category "Other"
    elif cat == "Other":
        divert_to_hitl = True
        hitl_reason = "Unclassified category (Other)"
    # Condition 5: Confidence below threshold
    elif conf < hitl_threshold:
        divert_to_hitl = True
        hitl_reason = f"Confidence {conf:.2f} below threshold {hitl_threshold:.2f}"
    # Condition 6: Frustrated/Angry emotion + Critical/High priority
    elif emotion in ("Frustrated", "Angry") and prio in ("Critical", "High"):
        divert_to_hitl = True
        hitl_reason = f"Escalated customer emotion ({emotion}) with {prio} priority"

    if divert_to_hitl:
        hitl_status = "pending"
        p2_status = "hitl_pending"
        logger.info(
            f"[Node 07: HITL] Email '{email_id}' diverted to HITL review queue. "
            f"Reason: {hitl_reason}"
        )
    else:
        hitl_status = "auto_approved"
        p2_status = "auto_approved"
        hitl_reason = None
        logger.info(
            f"[Node 07: HITL] Email '{email_id}' auto-approved for automated dispatch to '{team}'"
        )

    # Persist Phase 2 classification & HITL state if database is provided
    if db is not None:
        try:
            db.record_phase2_classification(
                email_id=email_id,
                classification=classification,
                p2_classifier_used=p2_classifier_used,
                hitl_status=hitl_status,
                hitl_reason=hitl_reason,
            )
        except Exception as exc:
            # B4 Fail-Safe pattern: log only exception class name and email_id (never text)
            logger.error(
                f"[Node 07: HITL] Database persistence failed for email_id='{email_id}': "
                f"{exc.__class__.__name__}"
            )
            return {
                "hitl_status": "none",
                "hitl_reason": None,
                "p2_status": "persist_failed",
                "dispatch_status": "failed",
                "error_message": "database write failed",
            }

    return {
        "hitl_status": hitl_status,
        "hitl_reason": hitl_reason,
        "p2_status": p2_status,
    }


def should_route_after_hitl(state: TriageState) -> str:
    """Conditional edge router determining whether to continue dispatch or terminate.

    Args:
        state: Current LangGraph triage state.

    Returns:
        'continue' only when hitl_status is auto_approved or approved and p2_status is not persist_failed.
        Otherwise 'end'.
    """
    hitl_status = state.get("hitl_status")
    p2_status = state.get("p2_status")

    if hitl_status in ("auto_approved", "approved") and p2_status != "persist_failed":
        return "continue"

    return "end"
