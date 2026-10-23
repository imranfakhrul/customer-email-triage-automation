"""LangGraph Pipeline Definition for Customer Email Triage Automation.

Chains together the full ingestion-to-decision pipeline:
1. Node 01: Ingestion & Idempotency Store (SQLite state machine, thread detection)
2. Node 02: Signature & Quoted Reply Stripper (RFC header, Outlook, mobile cleanup)
3. Node 03: Local spaCy NER & Regex PII Masker (100% on-premise PII redaction)
4. Node 04: Sensitive-Skip Rules (immediate quarantine for legal/confidential notices)
5. Node 05: Jev AI Decision Gatekeeper (sub-second spam, threat, & legitimacy scoring)
"""

import logging
from typing import Any, Dict, Optional
import uuid

from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph

from db.database import TriageDatabase
from nodes import (
    ingest_node,
    jev_gatekeeper_node,
    pii_masker_node,
    sensitive_skip_node,
    should_continue_triage,
    should_route_after_gatekeeper,
    should_route_after_sensitive,
    signature_stripper_node,
)
from state import TriageState
from utils.config import load_config
from utils.jev_client import JevAIClient

logger = logging.getLogger("triage.pipeline")


def prepare_initial_state(payload: Dict[str, Any]) -> TriageState:
    """Normalizes an incoming raw email dictionary into a valid initial TriageState.

    Args:
        payload: Input dictionary containing email metadata and body.

    Returns:
        Fully populated TriageState dictionary ready for LangGraph execution.
    """
    raw_email_id = payload.get("email_id") or payload.get("message_id")
    email_id = str(raw_email_id) if raw_email_id else f"em_{uuid.uuid4().hex[:12]}"
    message_id = str(payload.get("message_id") or email_id)
    thread_id = str(payload.get("thread_id") or email_id)

    sender_email = payload.get("sender_email", "")
    sender_domain = payload.get("sender_domain")
    if not sender_domain and "@" in sender_email:
        sender_domain = sender_email.split("@")[-1].lower()

    raw_body = payload.get("raw_body") or payload.get("email_body") or ""
    email_body = payload.get("email_body") or raw_body

    initial_state: TriageState = {
        "email_id": email_id,
        "message_id": message_id,
        "thread_id": thread_id,
        "sender_email": sender_email,
        "sender_domain": sender_domain or "unknown.domain",
        "email_subject": payload.get("email_subject", "(No Subject)"),
        "email_body": email_body,
        "raw_body": raw_body,
        "has_attachments": bool(payload.get("has_attachments", False)),
        "is_active_thread": payload.get("is_active_thread"),
        "cleaned_body": payload.get("cleaned_body"),
        "masked_body": payload.get("masked_body"),
        "masked_subject": payload.get("masked_subject"),
        "token_map": dict(payload.get("token_map") or {}),
        "is_sensitive": bool(payload.get("is_sensitive", False)),
        "sensitive_reason": payload.get("sensitive_reason"),
        "is_spam": payload.get("is_spam"),
        "gatekeeper_decision": payload.get("gatekeeper_decision"),
        "gatekeeper_confidence": payload.get("gatekeeper_confidence"),
        "is_threat": payload.get("is_threat"),
        "threat_details": payload.get("threat_details"),
        "classifier_used": payload.get("classifier_used"),
        "customer_tier": payload.get("customer_tier"),
        "sla_target": payload.get("sla_target"),
        "classification": payload.get("classification"),
        "labels_to_apply": list(payload.get("labels_to_apply") or []),
        "is_starred": bool(payload.get("is_starred", False)),
        "dispatch_target": payload.get("dispatch_target"),
        "dispatch_status": payload.get("dispatch_status", "processing"),
        "retry_count": int(payload.get("retry_count", 0)),
        "error_message": payload.get("error_message"),
        "routing_status": payload.get("routing_status", "processing"),
    }
    return initial_state


def create_triage_pipeline(
    db: Optional[TriageDatabase] = None,
    config: Optional[Dict[str, Any]] = None,
    client: Optional[JevAIClient] = None,
) -> CompiledStateGraph:
    """Builds and compiles the LangGraph StateGraph for email triage up to Gatekeeper.

    Args:
        db: Optional TriageDatabase instance.
        config: Optional system configuration dict.
        client: Optional JevAIClient instance.

    Returns:
        CompiledStateGraph ready to invoke with TriageState.
    """
    builder = StateGraph(TriageState)

    if client is None and config is not None:
        client = JevAIClient(config=config)

    # 1. Register Nodes with bound dependencies
    builder.add_node("ingest", lambda state: ingest_node(state, db=db))
    builder.add_node("signature_stripper", signature_stripper_node)
    builder.add_node("pii_masker", pii_masker_node)
    builder.add_node(
        "sensitive_skip",
        lambda state: sensitive_skip_node(state, db=db, config=config),
    )
    builder.add_node(
        "jev_gatekeeper",
        lambda state: jev_gatekeeper_node(state, client=client, db=db),
    )

    # 2. Wire Entry Point & Graph Routing Edges
    builder.set_entry_point("ingest")

    # Ingestion conditional routing: duplicates / in-flight terminate immediately
    builder.add_conditional_edges(
        "ingest",
        should_continue_triage,
        {
            "continue": "signature_stripper",
            "end": END,
        },
    )

    # Linear preprocessing: signature strip -> PII mask -> sensitive guardrail
    builder.add_edge("signature_stripper", "pii_masker")
    builder.add_edge("pii_masker", "sensitive_skip")

    # Sensitive guardrail routing: sensitive emails quarantined, else proceed to gatekeeper
    builder.add_conditional_edges(
        "sensitive_skip",
        should_route_after_sensitive,
        {
            "continue": "jev_gatekeeper",
            "end": END,
        },
    )

    # Gatekeeper decision routing: spam and manual_review terminate; legitimate approved
    builder.add_conditional_edges(
        "jev_gatekeeper",
        should_route_after_gatekeeper,
        {
            "continue": END,
            "end": END,
        },
    )

    return builder.compile()


def run_triage_pipeline(
    payload: Dict[str, Any],
    pipeline: Optional[CompiledStateGraph] = None,
    db: Optional[TriageDatabase] = None,
    config: Optional[Dict[str, Any]] = None,
    client: Optional[JevAIClient] = None,
) -> TriageState:
    """Executes an email payload through the triage pipeline and returns final state.

    Args:
        payload: Input dictionary with email data.
        pipeline: Optional pre-compiled CompiledStateGraph. If None, created dynamically.
        db: Optional TriageDatabase instance.
        config: Optional configuration dictionary.
        client: Optional JevAIClient instance.

    Returns:
        Final TriageState after pipeline completion.
    """
    initial_state = prepare_initial_state(payload)

    if pipeline is None:
        pipeline = create_triage_pipeline(db=db, config=config, client=client)

    final_state = pipeline.invoke(initial_state)
    return final_state
