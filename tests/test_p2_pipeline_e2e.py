"""End-to-End Integration Tests for Phase 2 LangGraph Pipeline Compilation & Dispatch Handoff.

Milestone [P2-08]:
Verifies unified pipeline (Phase 1 + Phase 2) and standalone worker pipeline topologies:
1. Phase 1 backward compatibility when phase2=False.
2. Full unified pipeline auto-approval and outbox dispatch traversal.
3. HITL review queue quarantine halts before dispatcher.
4. Gatekeeper spam/threat rejection halts before classifier.
5. Sensitive-skip quarantine halts before gatekeeper.
6. Standalone worker pipeline (create_phase2_worker_pipeline) execution without Nodes 01-05.
7. Zero-Touch Policy on Phase 1 database columns (email_triage status, routing_status).
8. Privacy: high-risk secrets remain masked in dispatched payloads and ledger.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from db.database import TriageDatabase
from pipeline import (
    create_phase2_worker_pipeline,
    create_triage_pipeline,
    prepare_initial_state,
)
from state import TriageState
from utils.classifier_client import ClassifierClient
from utils.config import get_config


@pytest.fixture
def temp_db_path(tmp_path: Path) -> str:
    return str(tmp_path / "test_pipeline_p2.db")


@pytest.fixture
def test_db(temp_db_path: str) -> TriageDatabase:
    return TriageDatabase(db_path=temp_db_path)


@pytest.fixture
def sample_config() -> dict[str, Any]:
    cfg = get_config()
    cfg_copy = json.loads(json.dumps(cfg))
    cfg_copy["classification"]["primary"] = "offline_heuristic"
    cfg_copy["dispatch"]["dry_run"] = True
    return cfg_copy


def insert_approved_triage_record(
    db: TriageDatabase,
    email_id: str,
    category: str = "Demo Request",
    priority: str = "High",
    confidence: float = 0.95,
    hitl_status: str = "auto_approved",
    masked_subject: str = "Demo request for 500 enterprise seats",
    masked_body: str = "Hi sales team, we would like an enterprise demo.",
    sender_email: str = "buyer@enterprise.com",
) -> None:
    """Helper inserting pre-approved email triage record simulating Phase 1 output."""
    with db.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO email_triage (
                email_id, message_id, thread_id, sender_email,
                masked_subject, masked_body, routing_status, status,
                p2_category, p2_priority, p2_sentiment, p2_customer_emotion,
                p2_summary, p2_suggested_team, p2_confidence, p2_classifier_used,
                hitl_status, created_at, updated_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, 'gatekeeper_approved', 'done',
                ?, ?, 'Neutral', 'Calm', ?, 'Sales', ?, 'groq', ?,
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
            """,
            (
                email_id,
                f"<{email_id}@example.com>",
                f"th_{email_id}",
                sender_email,
                masked_subject,
                masked_body,
                category,
                priority,
                masked_subject,
                confidence,
                hitl_status,
            ),
        )


def test_phase2_disabled_by_default(test_db: TriageDatabase, sample_config: dict[str, Any]):
    """Default create_triage_pipeline(phase2=False) must terminate at gatekeeper."""
    pipeline = create_triage_pipeline(db=test_db, config=sample_config, offline=True, phase2=False)

    payload = {
        "email_id": "em_e2e_p1_001",
        "message_id": "<p1-001@example.com>",
        "thread_id": "th_p1_001",
        "sender_email": "jane@example.com",
        "sender_domain": "example.com",
        "email_subject": "Need volume pricing for 50 licenses",
        "email_body": "Hello, we need volume pricing. Thanks, Jane.",
    }

    result = pipeline.invoke(prepare_initial_state(payload))

    assert result["routing_status"] == "gatekeeper_approved"
    assert result["gatekeeper_decision"] == "legitimate"
    # Phase 2 nodes must NOT have run
    assert result.get("classification") is None
    assert result.get("hitl_status") is None
    assert result.get("p2_status") is None


def test_phase2_unified_pipeline_auto_approved_and_dispatched(
    test_db: TriageDatabase, sample_config: dict[str, Any]
):
    """Unified pipeline (phase2=True) runs Nodes 01->08 and stages dispatch actions."""
    mock_classifier = MagicMock(spec=ClassifierClient)
    mock_classifier.classify.return_value = {
        "category": "Bug Report",
        "priority": "High",
        "sentiment": "Negative",
        "customer_emotion": "Calm",
        "summary": "Database pool exhaustion 500 error",
        "suggested_team": "Engineering",
        "confidence": 0.95,
        "p2_classifier_used": "groq",
    }

    pipeline = create_triage_pipeline(
        db=test_db,
        config=sample_config,
        classifier_client=mock_classifier,
        offline=True,
        phase2=True,
    )

    payload = {
        "email_id": "em_e2e_p2_bug_001",
        "message_id": "<bug-001@acme.com>",
        "thread_id": "th_bug_001",
        "sender_email": "developer@acme.com",
        "sender_domain": "acme.com",
        "email_subject": "Critical bug: 500 error on database connection pool",
        "email_body": (
            "Hi Support,\n"
            "We are seeing a 500 internal server error when connecting.\n"
            "Stacktrace in /srv/app/db.py: Connection timeout.\n"
            "Please fix urgently."
        ),
    }

    result = pipeline.invoke(prepare_initial_state(payload))

    # Phase 1 verification
    assert result["routing_status"] == "gatekeeper_approved"
    assert result["gatekeeper_decision"] == "legitimate"

    # Phase 2 verification
    assert result["classification"] is not None
    assert result["classification"].category == "Bug Report"
    assert result["hitl_status"] == "auto_approved"
    assert result["p2_status"] in ("simulated", "dispatched")

    # DB verification
    record = test_db.get_record("em_e2e_p2_bug_001")
    assert record is not None
    assert record["routing_status"] == "gatekeeper_approved"
    assert record["status"] == "done"  # Phase 1 status unchanged
    assert record["p2_category"] == "Bug Report"
    assert record["hitl_status"] == "auto_approved"

    # Dispatch ledger verification (Bug Report routes to GitHub)
    logs = test_db.get_dispatch_log("em_e2e_p2_bug_001")
    assert len(logs) == 1
    assert logs[0]["destination"] == "github"
    assert logs[0]["action_type"] == "create_issue"
    assert logs[0]["mode"] == "dry_run"
    assert logs[0]["state"] == "simulated"


def test_phase2_unified_pipeline_hitl_quarantine_stops_before_dispatcher(
    test_db: TriageDatabase, sample_config: dict[str, Any]
):
    """Low-confidence classification diverts to HITL and halts before dispatcher."""
    mock_classifier = MagicMock(spec=ClassifierClient)
    mock_classifier.classify.return_value = {
        "category": "General Query",
        "priority": "Low",
        "sentiment": "Neutral",
        "customer_emotion": "Calm",
        "summary": "Ambiguous inquiry",
        "suggested_team": "Support",
        "confidence": 0.40,  # Below 0.85 threshold
        "p2_classifier_used": "groq",
    }

    pipeline = create_triage_pipeline(
        db=test_db,
        config=sample_config,
        classifier_client=mock_classifier,
        offline=True,
        phase2=True,
    )

    payload = {
        "email_id": "em_e2e_hitl_001",
        "message_id": "<hitl-001@example.com>",
        "thread_id": "th_hitl_001",
        "sender_email": "user@example.com",
        "sender_domain": "example.com",
        "email_subject": "Question about account",
        "email_body": "Can someone help me with something general?",
    }

    result = pipeline.invoke(prepare_initial_state(payload))

    assert result["routing_status"] == "gatekeeper_approved"
    assert result["hitl_status"] == "pending"
    assert result["p2_status"] == "hitl_pending"

    # Dispatcher must NOT have executed
    assert result.get("dispatch_results") in (None, [])
    logs = test_db.get_dispatch_log("em_e2e_hitl_001")
    assert len(logs) == 0


def test_phase2_unified_pipeline_spam_stops_at_gatekeeper(
    test_db: TriageDatabase, sample_config: dict[str, Any]
):
    """Spam email terminates at Gatekeeper and never reaches Node 06 (Classifier)."""
    pipeline = create_triage_pipeline(db=test_db, config=sample_config, offline=True, phase2=True)

    payload = {
        "email_id": "em_e2e_spam_001",
        "message_id": "<spam-001@lottery.xyz>",
        "thread_id": "th_spam_001",
        "sender_email": "winner@lottery.xyz",
        "sender_domain": "lottery.xyz",
        "email_subject": "CONGRATULATIONS! You won $10,000,000 lottery cash prize wire transfer",
        "email_body": "Claim your Nigerian prince inheritance wire transfer immediately.",
    }

    result = pipeline.invoke(prepare_initial_state(payload))

    assert result["gatekeeper_decision"] in ("spam", "manual_review")
    assert result["routing_status"] in ("junk_routed", "manual_review")

    # Classifier and HITL must NOT have run
    assert result.get("classification") is None
    assert result.get("hitl_status") is None
    assert result.get("p2_status") is None
    assert len(test_db.get_dispatch_log("em_e2e_spam_001")) == 0


def test_phase2_unified_pipeline_sensitive_stops_at_sensitive_skip(
    test_db: TriageDatabase, sample_config: dict[str, Any]
):
    """Sensitive email diverts at Node 04 and never reaches Gatekeeper or Classifier."""
    pipeline = create_triage_pipeline(db=test_db, config=sample_config, offline=True, phase2=True)

    payload = {
        "email_id": "em_e2e_sens_001",
        "message_id": "<legal-001@lawfirm.com>",
        "thread_id": "th_sens_001",
        "sender_email": "attorney@lawfirm.com",
        "sender_domain": "lawfirm.com",
        "email_subject": "Formal litigation hold notice and confidential subpoena",
        "email_body": "This is a confidential legal notice regarding litigation hold.",
    }

    result = pipeline.invoke(prepare_initial_state(payload))

    assert result["is_sensitive"] is True
    assert result["routing_status"] == "sensitive_diverted"
    assert result.get("gatekeeper_decision") is None
    assert result.get("classification") is None
    assert result.get("hitl_status") is None
    assert len(test_db.get_dispatch_log("em_e2e_sens_001")) == 0


def test_phase2_standalone_worker_pipeline(test_db: TriageDatabase, sample_config: dict[str, Any]):
    """Standalone worker pipeline executes directly from classifier without re-running Phase 1."""
    email_id = "em_worker_test_001"
    insert_approved_triage_record(
        db=test_db,
        email_id=email_id,
        category="Demo Request",
        priority="High",
        confidence=0.96,
        hitl_status="auto_approved",
    )

    mock_classifier = MagicMock(spec=ClassifierClient)
    mock_classifier.classify.return_value = {
        "category": "Demo Request",
        "priority": "High",
        "sentiment": "Positive",
        "customer_emotion": "Calm",
        "summary": "Enterprise demo request for 500 seats",
        "suggested_team": "Sales",
        "confidence": 0.96,
        "p2_classifier_used": "groq",
    }

    worker_pipeline = create_phase2_worker_pipeline(
        db=test_db, config=sample_config, classifier_client=mock_classifier, offline=True
    )

    initial_worker_state: TriageState = prepare_initial_state({
        "email_id": email_id,
        "message_id": f"<{email_id}@acme.com>",
        "thread_id": f"th_{email_id}",
        "sender_email": "lead@acme.com",
        "sender_domain": "acme.com",
        "masked_subject": "Requesting demo for enterprise tier",
        "masked_body": "Hi, we would like to schedule a product demo for 500 users.",
        "routing_status": "gatekeeper_approved",
        "gatekeeper_decision": "legitimate",
        "token_map": {},
    })

    result = worker_pipeline.invoke(initial_worker_state)

    assert result["classification"] is not None
    assert result["classification"].category == "Demo Request"
    assert result["hitl_status"] == "auto_approved"
    assert result["p2_status"] in ("simulated", "dispatched")

    # Ledger check (Demo Request routes to CRM)
    logs = test_db.get_dispatch_log(email_id)
    assert len(logs) == 1
    assert logs[0]["destination"] == "crm"
    assert logs[0]["action_type"] == "create_lead"


def test_phase2_zero_touch_on_phase1_database_records(
    test_db: TriageDatabase, sample_config: dict[str, Any]
):
    """Hard Invariant #10: Phase 2 execution must never overwrite Phase 1 database columns."""
    email_id = "em_zero_touch_001"
    mock_classifier = MagicMock(spec=ClassifierClient)
    mock_classifier.classify.return_value = {
        "category": "Bug Report",
        "priority": "High",
        "sentiment": "Negative",
        "customer_emotion": "Calm",
        "summary": "Export feature fails on CSV generation",
        "suggested_team": "Engineering",
        "confidence": 0.92,
        "p2_classifier_used": "groq",
    }

    pipeline = create_triage_pipeline(
        db=test_db,
        config=sample_config,
        classifier_client=mock_classifier,
        offline=True,
        phase2=True,
    )

    payload = {
        "email_id": email_id,
        "message_id": "<zt-001@customer.com>",
        "thread_id": "th_zt_001",
        "sender_email": "alice@customer.com",
        "sender_domain": "customer.com",
        "email_subject": "Bug with export feature",
        "email_body": "Export fails on CSV generation with 500 error.",
    }

    pipeline.invoke(prepare_initial_state(payload))

    rec = test_db.get_record(email_id)
    assert rec is not None

    # Phase 1 columns must remain exactly as Phase 1 defined them
    assert rec["status"] == "done"
    assert rec["routing_status"] == "gatekeeper_approved"
    assert rec["gatekeeper_decision"] == "legitimate"
    assert rec["dispatch_target"] is None  # Phase 1 column untouched
    assert rec["masked_subject"] is not None
    assert rec["masked_body"] is not None

    # Phase 2 columns are updated
    assert rec["p2_category"] == "Bug Report"
    assert rec["p2_priority"] is not None
    assert rec["p2_classifier_used"] is not None
    assert rec["hitl_status"] == "auto_approved"


def test_phase2_privacy_invariants_and_human_review_dispatch(
    test_db: TriageDatabase, sample_config: dict[str, Any]
):
    """Hard Invariant #1, #2, #9: Security/Account diverts to HITL; human approval dispatches."""
    email_id = "em_sec_priv_001"
    mock_classifier = MagicMock(spec=ClassifierClient)
    mock_classifier.classify.return_value = {
        "category": "Security/Account",
        "priority": "Critical",
        "sentiment": "Negative",
        "customer_emotion": "Calm",
        "summary": "API token exposed",
        "suggested_team": "Security",
        "confidence": 0.99,
        "p2_classifier_used": "groq",
    }

    pipeline = create_triage_pipeline(
        db=test_db,
        config=sample_config,
        classifier_client=mock_classifier,
        offline=True,
        phase2=True,
    )

    payload = {
        "email_id": email_id,
        "message_id": "<priv-001@customer.com>",
        "thread_id": "th_priv_001",
        "sender_email": "john.smith@secretcorp.com",
        "sender_domain": "secretcorp.com",
        "email_subject": "Security issue reported by John Smith",
        "email_body": (
            "Hello, I am John Smith (phone: 555-0199, card: 4111-2222-3333-4444).\n"
            "Our API token sec_live_12345 was exposed."
        ),
    }

    # 1. Run through pipeline: Security/Account policy triggers mandatory human review
    result = pipeline.invoke(prepare_initial_state(payload))

    assert result["hitl_status"] == "pending"
    assert "Security/Account" in result["hitl_reason"]
    # At this point, dispatcher has NOT dispatched yet
    assert len(test_db.get_dispatch_log(email_id)) == 0

    # 2. Human reviewer reviews and approves the item
    resolved = test_db.resolve_hitl_review(email_id, "approved", "sec_officer")
    assert resolved is True

    # 3. Resume / invoke dispatcher for approved email
    from nodes.dispatcher import dispatcher_node
    disp_res = dispatcher_node(result, db=test_db, config=sample_config)
    assert disp_res["p2_status"] in ("simulated", "dispatched")

    # 4. Check outbox ledger
    logs = test_db.get_dispatch_log(email_id)
    assert len(logs) == 1
    assert logs[0]["destination"] == "webhook"
    assert logs[0]["action_type"] == "alert"

    # Invariant: ledger row must not contain customer raw text or token_map
    log_str = json.dumps(logs[0])
    assert "John Smith" not in log_str
    assert "4111-2222-3333-4444" not in log_str
    assert "sec_live_12345" not in log_str


def test_phase2_unified_pipeline_frustrated_customer_escalation(
    test_db: TriageDatabase, sample_config: dict[str, Any]
):
    """Frustrated or Angry emotion + Critical/High priority triggers mandatory HITL gating."""
    mock_classifier = MagicMock(spec=ClassifierClient)
    mock_classifier.classify.return_value = {
        "category": "Bug Report",
        "priority": "Critical",
        "sentiment": "Negative",
        "customer_emotion": "Angry",
        "summary": "System outage destroying customer data",
        "suggested_team": "Engineering",
        "confidence": 0.99,
        "p2_classifier_used": "groq",
    }

    pipeline = create_triage_pipeline(
        db=test_db,
        config=sample_config,
        classifier_client=mock_classifier,
        offline=True,
        phase2=True,
    )

    payload = {
        "email_id": "em_angry_001",
        "message_id": "<angry-001@client.com>",
        "thread_id": "th_angry_001",
        "sender_email": "cto@client.com",
        "sender_domain": "client.com",
        "email_subject": "UNACCEPTABLE DOWNTIME",
        "email_body": "Your system has been down for 4 hours. Fix this right now!",
    }

    result = pipeline.invoke(prepare_initial_state(payload))

    assert result["hitl_status"] == "pending"
    assert "Escalated customer emotion (Angry) with Critical priority" in result["hitl_reason"]
    # Halts before dispatcher
    assert len(test_db.get_dispatch_log("em_angry_001")) == 0


def test_phase2_unified_pipeline_multidestination_critical_billing(
    test_db: TriageDatabase, sample_config: dict[str, Any]
):
    """Critical priority Billing Issue stages both FreeScout ticket and Webhook alert."""
    mock_classifier = MagicMock(spec=ClassifierClient)
    mock_classifier.classify.return_value = {
        "category": "Billing Issue",
        "priority": "Critical",
        "sentiment": "Neutral",
        "customer_emotion": "Calm",
        "summary": "Urgent enterprise billing discrepancy",
        "suggested_team": "Billing",
        "confidence": 0.95,
        "p2_classifier_used": "groq",
    }

    pipeline = create_triage_pipeline(
        db=test_db,
        config=sample_config,
        classifier_client=mock_classifier,
        offline=True,
        phase2=True,
    )

    payload = {
        "email_id": "em_crit_bill_001",
        "message_id": "<bill-001@enterprise.com>",
        "thread_id": "th_bill_001",
        "sender_email": "finance@enterprise.com",
        "sender_domain": "enterprise.com",
        "email_subject": "Urgent: Billing discrepancy on monthly invoice",
        "email_body": "Please review invoice INV-9901 immediately.",
    }

    result = pipeline.invoke(prepare_initial_state(payload))

    assert result["hitl_status"] == "auto_approved"
    assert result["p2_status"] in ("simulated", "dispatched")

    logs = test_db.get_dispatch_log("em_crit_bill_001")
    assert len(logs) == 2
    destinations = {entry["destination"] for entry in logs}
    assert destinations == {"freescout", "webhook"}


def test_phase2_run_triage_pipeline_helper(test_db: TriageDatabase, sample_config: dict[str, Any]):
    """Verifies run_triage_pipeline() helper with phase2=True."""
    mock_classifier = MagicMock(spec=ClassifierClient)
    mock_classifier.classify.return_value = {
        "category": "Feature Request",
        "priority": "Low",
        "sentiment": "Positive",
        "customer_emotion": "Calm",
        "summary": "Request for dark mode UI",
        "suggested_team": "Engineering",
        "confidence": 0.90,
        "p2_classifier_used": "groq",
    }

    payload = {
        "email_id": "em_run_helper_001",
        "message_id": "<feat-001@user.com>",
        "thread_id": "th_feat_001",
        "sender_email": "user@user.com",
        "sender_domain": "user.com",
        "email_subject": "Dark mode feature suggestion",
        "email_body": "It would be great to have a dark mode option in the dashboard.",
    }

    from pipeline import run_triage_pipeline

    result = run_triage_pipeline(
        payload=payload,
        db=test_db,
        config=sample_config,
        classifier_client=mock_classifier,
        offline=True,
        phase2=True,
    )

    assert result["routing_status"] == "gatekeeper_approved"
    assert result["hitl_status"] == "auto_approved"
    assert result["p2_status"] in ("simulated", "dispatched")

    logs = test_db.get_dispatch_log("em_run_helper_001")
    assert len(logs) == 1
    assert logs[0]["destination"] == "github"
    assert logs[0]["action_type"] == "create_issue"

