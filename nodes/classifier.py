"""Node 06: Deep LLM Intent, Category, and Sentiment Classifier.

This node performs semantic classification on sanitized, gatekeeper-approved emails:
1. Consumes ONLY `masked_subject` and `masked_body`, adhering strictly to Phase 1 PII privacy guarantees.
2. If masked text is missing or None, fails closed to human review (confidence 0.0, engine offline_heuristic)
   without ever touching raw unmasked fields or making external calls.
3. Utilizes `ClassifierClient` with multi-tier evaluation:
   - Primary: TypeSafe Jev AI choice router (`gmail_router`) if enabled
   - Secondary: Groq LLM fallback (`openai/gpt-oss-120b`)
   - Tertiary: Local rule-based heuristic ensemble (fail-closed to HITL)
4. Outputs an `EmailClassification` object into `state["classification"]` and tracks the engine
   in `state["p2_classifier_used"]`.
"""

import logging
import threading
from typing import Any, Dict, Optional

from state import EmailClassification, TriageState
from utils.classifier_client import ClassifierClient

logger = logging.getLogger(__name__)

_DEFAULT_CLASSIFIER_CLIENT: Optional[ClassifierClient] = None
_DEFAULT_CLASSIFIER_CLIENT_LOCK = threading.Lock()


def get_default_classifier_client(config: Optional[Dict[str, Any]] = None) -> ClassifierClient:
    """Returns the singleton default ClassifierClient instance under a lock."""
    global _DEFAULT_CLASSIFIER_CLIENT
    if _DEFAULT_CLASSIFIER_CLIENT is not None:
        return _DEFAULT_CLASSIFIER_CLIENT
    with _DEFAULT_CLASSIFIER_CLIENT_LOCK:
        if _DEFAULT_CLASSIFIER_CLIENT is not None:
            return _DEFAULT_CLASSIFIER_CLIENT
        _DEFAULT_CLASSIFIER_CLIENT = ClassifierClient(config=config)
        return _DEFAULT_CLASSIFIER_CLIENT


def reset_default_classifier_client() -> None:
    """Resets the singleton default ClassifierClient under lock (useful for testing)."""
    global _DEFAULT_CLASSIFIER_CLIENT
    with _DEFAULT_CLASSIFIER_CLIENT_LOCK:
        _DEFAULT_CLASSIFIER_CLIENT = None


def classifier_node(
    state: TriageState,
    client: Optional[ClassifierClient] = None,
) -> Dict[str, Any]:
    """Node function that categorizes, prioritizes, and scores customer emails.

    Args:
        state: Current LangGraph triage state.
        client: Optional ClassifierClient instance (uses singleton if None).

    Returns:
        State update dictionary containing 'classification' and 'p2_classifier_used'.
    """
    email_id = state.get("email_id", "<unknown>")

    # PRR-01: If already classified and approved by human, preserve existing classification without redundant LLM call
    existing_classification = state.get("classification")
    if existing_classification is not None and state.get("hitl_status") in ("approved", "auto_approved"):
        logger.info(
            f"[Node 06: Classifier] Email '{email_id}' has existing classification and prior approval; preserving."
        )
        return {
            "classification": existing_classification,
            "p2_classifier_used": state.get("p2_classifier_used", "human_review"),
        }

    # Strict Privacy Invariant: Node 06 must ONLY consume masked text from state.
    # Every fallback to email_subject / email_body is strictly removed.
    masked_subject = state.get("masked_subject")
    masked_body = state.get("masked_body")

    if (
        not masked_subject
        or not isinstance(masked_subject, str)
        or not masked_subject.strip()
        or not masked_body
        or not isinstance(masked_body, str)
        or not masked_body.strip()
    ):
        logger.warning(
            f"[Node 06: Classifier] Email '{email_id}' missing masked text privacy safeguard triggered. Failing closed."
        )
        fail_closed_obj = EmailClassification(
            category="Other",
            priority="Medium",
            sentiment="Neutral",
            customer_emotion="Calm",
            summary="Missing masked text privacy safeguard triggered; diverted to human review.",
            suggested_team="Support",
            confidence=0.0,
        )
        return {
            "classification": fail_closed_obj,
            "p2_classifier_used": "offline_heuristic",
        }

    if client is None:
        client = get_default_classifier_client()

    try:
        raw_classification = client.classify(masked_subject, masked_body)
    except Exception as e:
        logger.warning(
            f"[Node 06: Classifier] Classification failed for email '{email_id}': {type(e).__name__}."
        )
        fail_closed_obj = EmailClassification(
            category="Other",
            priority="Medium",
            sentiment="Neutral",
            customer_emotion="Calm",
            summary="Classification error encountered; diverted to human review.",
            suggested_team="Support",
            confidence=0.0,
        )
        return {
            "classification": fail_closed_obj,
            "p2_classifier_used": "offline_heuristic",
        }

    classification_obj = EmailClassification(
        category=raw_classification["category"],
        priority=raw_classification["priority"],
        sentiment=raw_classification["sentiment"],
        customer_emotion=raw_classification["customer_emotion"],
        summary=raw_classification["summary"],
        suggested_team=raw_classification["suggested_team"],
        confidence=raw_classification["confidence"],
    )

    p2_classifier_used = raw_classification.get("p2_classifier_used", "offline_heuristic")

    logger.info(
        f"[Node 06: Classifier] Email '{email_id}' classified as '{classification_obj.category}' "
        f"(priority={classification_obj.priority}, emotion={classification_obj.customer_emotion}, "
        f"conf={classification_obj.confidence:.2f}, engine={p2_classifier_used})"
    )

    return {
        "classification": classification_obj,
        "p2_classifier_used": p2_classifier_used,
    }
