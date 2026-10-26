"""Node 01: Ingestion, Idempotency Check, and Active Thread Verification.

This node is the entry point for the LangGraph triage pipeline. It ensures:
1. Standardized extraction of sender domain, message IDs, and thread context.
2. Idempotent processing using SQLite store to avoid duplicate work.
3. Automated recovery of stale processing locks (> 10 minutes by default).
4. Detection of active existing threads for contextual thread continuity verification.
"""

from typing import Any, Dict, Optional
import uuid

from db.database import TriageDatabase
from state import TriageState
from utils.config import get_config


def ingest_node(
    state: TriageState, db: Optional[TriageDatabase] = None
) -> Dict[str, Any]:
    """Ingests incoming email, checks idempotency, and detects thread continuity.

    Args:
        state: Incoming TriageState with email payload.
        db: Optional TriageDatabase instance. If None, initialized from config.

    Returns:
        Updated dictionary with normalized fields, idempotency status, and thread info.
    """
    if db is None:
        db = TriageDatabase()

    # Load system settings
    config = get_config()
    stale_minutes = config.get("system", {}).get("idempotency_stale_minutes", 10)
    max_retries = config.get("system", {}).get("max_dispatch_retries", 3)

    # Normalize identifiers
    raw_email_id = state.get("email_id") or state.get("message_id")
    email_id = str(raw_email_id) if raw_email_id else f"email_{uuid.uuid4().hex[:12]}"

    raw_msg_id = state.get("message_id")
    message_id = str(raw_msg_id) if raw_msg_id else email_id

    raw_thread_id = state.get("thread_id")
    thread_id = str(raw_thread_id) if raw_thread_id else email_id

    # Normalize sender information & domain extraction
    sender_email = str(state.get("sender_email") or "").strip()
    sender_domain = state.get("sender_domain")
    if not sender_domain:
        if "@" in sender_email:
            sender_domain = sender_email.split("@")[-1].lower()
        else:
            sender_domain = ""

    # Normalize body & subject
    email_body = state.get("email_body") or ""
    raw_body = state.get("raw_body") or email_body
    email_subject = state.get("email_subject") or ""
    has_attachments = bool(state.get("has_attachments", False))

    # Active Thread Continuity Check (A5: Never trust incoming payload claims; require prior approved history)
    has_prior_thread = db.is_active_thread(thread_id, exclude_email_id=email_id) if db is not None else False
    is_known_participant = (
        db.is_thread_participant(thread_id, sender_email, exclude_email_id=email_id)
        if (has_prior_thread and db is not None)
        else False
    )
    is_active_thread = bool(has_prior_thread and is_known_participant)

    # Check and acquire idempotency lock
    allowed, outcome, record = db.check_and_acquire(
        email_id=email_id,
        thread_id=thread_id,
        message_id=message_id,
        sender_email=sender_email,
        stale_minutes=stale_minutes,
        max_retries=max_retries,
    )

    # Map idempotency outcome to state update
    if outcome == "already_completed":
        return {
            "email_id": email_id,
            "message_id": message_id,
            "thread_id": thread_id,
            "sender_email": sender_email,
            "sender_domain": sender_domain,
            "email_subject": email_subject,
            "email_body": email_body,
            "raw_body": raw_body,
            "has_attachments": has_attachments,
            "is_active_thread": is_active_thread,
            "dispatch_status": "done",
            "routing_status": "duplicate_skipped",
            "error_message": None,
        }

    if outcome == "in_flight":
        return {
            "email_id": email_id,
            "message_id": message_id,
            "thread_id": thread_id,
            "sender_email": sender_email,
            "sender_domain": sender_domain,
            "email_subject": email_subject,
            "email_body": email_body,
            "raw_body": raw_body,
            "has_attachments": has_attachments,
            "is_active_thread": is_active_thread,
            "dispatch_status": "processing",
            "routing_status": "in_flight_skipped",
            "error_message": None,
        }

    if outcome == "max_retries_exceeded":
        return {
            "email_id": email_id,
            "message_id": message_id,
            "thread_id": thread_id,
            "sender_email": sender_email,
            "sender_domain": sender_domain,
            "email_subject": email_subject,
            "email_body": email_body,
            "raw_body": raw_body,
            "has_attachments": has_attachments,
            "is_active_thread": is_active_thread,
            "dispatch_status": "failed",
            "routing_status": "max_retries_exceeded",
            "error_message": record.get("error_message")
            or "Maximum retry attempts exceeded",
        }

    # Processing allowed (new, recovered stale lock, or valid retry)
    retry_count = record.get("retry_count", 0)
    if outcome == "recovered_stale":
        routing_status = "stale_recovery"
    elif outcome == "retry_failed":
        routing_status = "retry"
    else:
        routing_status = "processing"

    return {
        "email_id": email_id,
        "message_id": message_id,
        "thread_id": thread_id,
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "email_subject": email_subject,
        "email_body": email_body,
        "raw_body": raw_body,
        "has_attachments": has_attachments,
        "is_active_thread": is_active_thread,
        "dispatch_status": "processing",
        "retry_count": retry_count,
        "routing_status": routing_status,
        "error_message": None,
    }


def should_continue_triage(state: TriageState) -> str:
    """Conditional edge router for LangGraph after ingestion.

    Directs duplicate, currently in-flight, or failed emails to graph END,
    and forwards newly acquired emails to the privacy stripping stage.

    Args:
        state: Current pipeline state.

    Returns:
        'end' if triage should abort, 'continue' to proceed to next node.
    """
    routing_status = state.get("routing_status")
    dispatch_status = state.get("dispatch_status")

    if routing_status in (
        "duplicate_skipped",
        "in_flight_skipped",
        "max_retries_exceeded",
    ):
        return "end"

    if dispatch_status in ("done", "failed"):
        return "end"

    return "continue"
