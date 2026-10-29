"""Tests for PRR-01: Human Approval Pass-Through and State Gating.

Validates that approved emails in hitl_resolved state are passed directly
through to dispatcher without being re-diverted to pending, and that
pre-existing classifications are preserved without redundant LLM calls.
"""

from typing import Any

import pytest

from db.database import TriageDatabase
from nodes.classifier import classifier_node
from nodes.hitl_queue import hitl_queue_node, should_route_after_hitl
from state import EmailClassification, TriageState


@pytest.fixture
def temp_db(tmp_path: Any) -> TriageDatabase:
    """Creates a temporary SQLite database initialized with schema."""
    db_path = tmp_path / "test_prr_01.db"
    return TriageDatabase(db_path=str(db_path))


class TestPrr01HitlQueueApprovalPassThrough:
    """Unit tests for hitl_queue_node prior approval handling."""

    def test_approved_security_account_bypasses_mandatory_review_gate(self) -> None:
        """Security/Account emails mandate review, but prior human approval passes through."""
        classification = EmailClassification(
            category="Security/Account",
            priority="Critical",
            sentiment="Negative",
            customer_emotion="Frustrated",
            summary="Vulnerability report in auth service",
            suggested_team="Security",
            confidence=0.95,
        )
        state: TriageState = {
            "email_id": "em_sec_001",
            "classification": classification,
            "p2_classifier_used": "groq",
            "hitl_status": "approved",
            "routing_status": "gatekeeper_approved",
            "status": "done",
            "masked_subject": "Security issue",
            "masked_body": "Token leak detected",
        }

        result = hitl_queue_node(state)

        assert result["hitl_status"] == "approved"
        assert result["p2_status"] == "auto_approved"
        assert result["hitl_reason"] is None

        # Verify should_route_after_hitl allows transition to dispatcher
        combined_state = {**state, **result}
        assert should_route_after_hitl(combined_state) == "continue"

    def test_approved_low_confidence_passes_through(self) -> None:
        """Low confidence emails normally divert, but prior approval passes through."""
        classification = EmailClassification(
            category="General Query",
            priority="Low",
            sentiment="Neutral",
            customer_emotion="Calm",
            summary="Vague inquiry",
            suggested_team="Support",
            confidence=0.30,  # Far below 0.85 threshold
        )
        state: TriageState = {
            "email_id": "em_low_002",
            "classification": classification,
            "p2_classifier_used": "offline_heuristic",
            "hitl_status": "approved",
            "routing_status": "gatekeeper_approved",
            "status": "done",
        }

        result = hitl_queue_node(state)

        assert result["hitl_status"] == "approved"
        assert result["p2_status"] == "auto_approved"
        combined_state = {**state, **result}
        assert should_route_after_hitl(combined_state) == "continue"

    def test_db_approved_status_detected_when_not_in_state(self, temp_db: TriageDatabase) -> None:
        """If state has hitl_status='none', node inspects DB and respects 'approved'."""
        email_id = "em_db_003"
        temp_db.check_and_acquire(
            email_id=email_id,
            thread_id="th_003",
            message_id="<msg_003@test.local>",
            sender_email="user@example.com",
        )
        temp_db.mark_done(
            email_id=email_id,
            routing_status="gatekeeper_approved",
            dispatch_target="p2_queue",
            masked_subject="Password reset issue",
            masked_body="Need assistance with password",
        )
        # Record classification and set to pending
        temp_db.record_phase2_classification(
            email_id=email_id,
            classification={"category": "Security/Account", "confidence": 0.90},
            hitl_status="pending",
            hitl_reason="Mandatory security review",
        )
        # Human reviewer approves it
        temp_db.resolve_hitl_review(
            email_id=email_id,
            decision="approved",
            reviewed_by="security_lead",
            notes="Legitimate user request",
        )

        state: TriageState = {
            "email_id": email_id,
            "classification": {
                "category": "Security/Account",
                "priority": "High",
                "confidence": 0.90,
                "suggested_team": "Security",
            },
            "p2_classifier_used": "groq",
            "hitl_status": "none",  # Not set in state
            "routing_status": "gatekeeper_approved",
            "status": "done",
        }

        result = hitl_queue_node(state, db=temp_db)

        assert result["hitl_status"] == "approved"
        assert result["p2_status"] == "auto_approved"
        combined_state = {**state, **result}
        assert should_route_after_hitl(combined_state) == "continue"

    def test_rejected_status_terminates_routing(self) -> None:
        """Pre-rejected items must terminate immediately with p2_status='failed'."""
        state: TriageState = {
            "email_id": "em_rej_004",
            "classification": {"category": "Bug Report", "confidence": 0.95},
            "hitl_status": "rejected",
            "routing_status": "gatekeeper_approved",
            "status": "done",
        }

        result = hitl_queue_node(state)

        assert result["hitl_status"] == "rejected"
        assert result["p2_status"] == "failed"
        combined_state = {**state, **result}
        assert should_route_after_hitl(combined_state) == "end"


class TestPrr01ClassifierRedundantCallPrevention:
    """Verifies classifier_node preserves existing classification for pre-approved jobs."""

    def test_classifier_preserves_existing_classification_on_approved_job(self) -> None:
        """When an approved email is claimed, classifier does not re-invoke external LLM."""
        existing_obj = EmailClassification(
            category="Demo Request",
            priority="High",
            sentiment="Positive",
            customer_emotion="Calm",
            summary="Enterprise sales inquiry for 200 seats",
            suggested_team="Sales",
            confidence=0.98,
        )

        state: TriageState = {
            "email_id": "em_demo_005",
            "masked_subject": "Enterprise Demo Request",
            "masked_body": "Looking to purchase 200 licenses",
            "classification": existing_obj,
            "p2_classifier_used": "groq",
            "hitl_status": "approved",
            "routing_status": "gatekeeper_approved",
            "status": "done",
        }

        # client=None: if it tries to classify, it would raise or use default client
        result = classifier_node(state, client=None)

        assert result["classification"] == existing_obj
        assert result["p2_classifier_used"] == "groq"


class TestPrr01WorkerApprovalExecution:
    """End-to-end worker verification that approved jobs are processed and not re-diverted."""

    def test_worker_processes_approved_security_email_to_done(
        self, temp_db: TriageDatabase
    ) -> None:
        """When an approved Security email is claimed by worker, it completes as done."""
        from scripts.phase2_worker import run_worker_once

        email_id = "em_worker_sec_006"
        temp_db.check_and_acquire(
            email_id=email_id,
            thread_id="th_006",
            message_id="<msg_006@test.local>",
            sender_email="alice@techcorp.com",
        )
        temp_db.mark_done(
            email_id=email_id,
            routing_status="gatekeeper_approved",
            dispatch_target="p2_queue",
            masked_subject="[MASKED] Access token leak",
            masked_body="[MASKED] GitHub token exposed in log file.",
        )
        temp_db.sync_p2_intake()

        # Step 1: Initial classification diverts to HITL pending
        temp_db.record_phase2_classification(
            email_id=email_id,
            classification={
                "category": "Security/Account",
                "priority": "Critical",
                "sentiment": "Negative",
                "customer_emotion": "Frustrated",
                "summary": "Access token leak detected",
                "suggested_team": "Security",
                "confidence": 0.99,
            },
            hitl_status="pending",
            hitl_reason="Category 'Security/Account' requires mandatory human review",
        )
        temp_db.finish_p2_job(email_id=email_id, state="hitl_pending")

        # Step 2: Human reviewer approves
        temp_db.resolve_hitl_review(
            email_id=email_id,
            decision="approved",
            reviewed_by="security_officer",
            notes="Authorized token disclosure",
        )

        # Assert job state is hitl_resolved in p2_jobs
        with temp_db.get_connection() as conn:
            cur = conn.execute("SELECT state FROM p2_jobs WHERE email_id = ?", (email_id,))
            assert cur.fetchone()["state"] == "hitl_resolved"

        # Step 3: Run worker cycle
        processed = run_worker_once(
            db=temp_db,
            batch_size=10,
            dry_run=True,
            offline=True,
        )

        assert processed == 1

        # Step 4: Verify terminal state is done (not stuck in hitl_pending)
        with temp_db.get_connection() as conn:
            cur = conn.execute("SELECT state FROM p2_jobs WHERE email_id = ?", (email_id,))
            final_job_state = cur.fetchone()["state"]
            assert final_job_state == "done"

