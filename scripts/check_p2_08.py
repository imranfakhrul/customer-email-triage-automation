"""Manual verification script for Milestone [P2-08].

Verifies End-to-End LangGraph Phase 2 Graph Compilation, unified pipeline
auto-approval traversal, HITL queue gating, standalone worker pipeline, and
Phase 1 database Zero-Touch immutability.

Usage:
    ./venv/bin/python scripts/check_p2_08.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from db.database import TriageDatabase  # noqa: E402
from nodes.dispatcher import dispatcher_node  # noqa: E402
from pipeline import (  # noqa: E402
    create_phase2_worker_pipeline,
    create_triage_pipeline,
    prepare_initial_state,
)
from utils.classifier_client import ClassifierClient  # noqa: E402
from utils.config import get_config  # noqa: E402


def require(condition: bool, msg: str = "") -> None:
    """Assertion helper avoiding S101 bandit flags in standalone scripts."""
    if not condition:
        raise RuntimeError(f"Check requirement failed: {msg}")


def run_checks() -> None:
    print("=" * 70)
    print(" RUNNING MANUAL VERIFICATION FOR MILESTONE [P2-08]")
    print(" End-to-End LangGraph Phase 2 Graph Compilation & Dispatch Handoff")
    print("=" * 70)

    cfg = get_config()
    test_config = json.loads(json.dumps(cfg))
    test_config["classification"]["primary"] = "offline_heuristic"
    test_config["dispatch"]["dry_run"] = True

    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = str(Path(tmp_dir) / "check_p2_08.db")
        db = TriageDatabase(db_path=db_path)

        # -------------------------------------------------------------
        # Check 1: Backward Compatibility (phase2=False)
        # -------------------------------------------------------------
        print("\n[Check 1] Phase 1 Backward Compatibility (phase2=False)")
        p1_pipeline = create_triage_pipeline(
            db=db, config=test_config, offline=True, phase2=False
        )

        p1_payload = {
            "email_id": "em_chk_p1_001",
            "message_id": "<p1-001@example.com>",
            "thread_id": "th_p1_001",
            "sender_email": "jane@example.com",
            "sender_domain": "example.com",
            "email_subject": "Volume pricing for 100 enterprise users",
            "email_body": "Hi, please send pricing. Thanks, Jane.",
        }

        p1_result = p1_pipeline.invoke(prepare_initial_state(p1_payload))
        require(
            p1_result["routing_status"] == "gatekeeper_approved",
            "P1 must be gatekeeper_approved",
        )
        require(p1_result.get("classification") is None, "P1 must not have classification")
        require(p1_result.get("hitl_status") is None, "P1 must not have hitl_status")
        print("  -> Default pipeline terminates cleanly after Gatekeeper (Phase 1). [PASS]")

        # -------------------------------------------------------------
        # Check 2: Unified Pipeline Full Traversal (phase2=True)
        # -------------------------------------------------------------
        print("\n[Check 2] Unified Pipeline Full Traversal (Nodes 01 -> 08)")
        mock_classifier = MagicMock(spec=ClassifierClient)
        mock_classifier.classify.return_value = {
            "category": "Bug Report",
            "priority": "High",
            "sentiment": "Negative",
            "customer_emotion": "Calm",
            "summary": "Postgres pool connection error",
            "suggested_team": "Engineering",
            "confidence": 0.95,
            "p2_classifier_used": "groq",
        }

        unified_pipeline = create_triage_pipeline(
            db=db,
            config=test_config,
            classifier_client=mock_classifier,
            offline=True,
            phase2=True,
        )

        bug_payload = {
            "email_id": "em_chk_p2_001",
            "message_id": "<p2-001@acme.com>",
            "thread_id": "th_p2_001",
            "sender_email": "dev@acme.com",
            "sender_domain": "acme.com",
            "email_subject": "Critical Bug: 500 error in export endpoint",
            "email_body": "Internal server error: DB pool exhausted in worker.py.",
        }

        unified_result = unified_pipeline.invoke(prepare_initial_state(bug_payload))
        require(
            unified_result["routing_status"] == "gatekeeper_approved",
            "Gatekeeper approved",
        )
        require(
            unified_result["classification"].category == "Bug Report",
            "Classified as Bug Report",
        )
        require(
            unified_result["hitl_status"] == "auto_approved",
            "HITL auto-approved",
        )
        require(
            unified_result["p2_status"] in ("simulated", "dispatched"),
            "Dispatched/simulated",
        )

        logs = db.get_dispatch_log("em_chk_p2_001")
        require(len(logs) == 1, "Expected 1 outbox ledger row")
        require(logs[0]["destination"] == "github", "Bug Report routes to GitHub")
        require(logs[0]["action_type"] == "create_issue", "Action is create_issue")
        print("  -> Full traversal through Gatekeeper -> Classifier -> HITL -> Dispatcher. [PASS]")
        print("  -> GitHub issue staging confirmed in SQLite outbox ledger. [PASS]")

        # -------------------------------------------------------------
        # Check 3: HITL Review Queue Gating & Handoff
        # -------------------------------------------------------------
        print("\n[Check 3] HITL Review Queue Gating & Reviewer Resolution")
        low_conf_classifier = MagicMock(spec=ClassifierClient)
        low_conf_classifier.classify.return_value = {
            "category": "General Query",
            "priority": "Low",
            "sentiment": "Neutral",
            "customer_emotion": "Calm",
            "summary": "Ambiguous inquiry needing clarification",
            "suggested_team": "Support",
            "confidence": 0.45,  # Below 0.85
            "p2_classifier_used": "groq",
        }

        hitl_pipeline = create_triage_pipeline(
            db=db,
            config=test_config,
            classifier_client=low_conf_classifier,
            offline=True,
            phase2=True,
        )

        hitl_payload = {
            "email_id": "em_chk_hitl_001",
            "message_id": "<hitl-001@corp.com>",
            "thread_id": "th_hitl_001",
            "sender_email": "user@corp.com",
            "sender_domain": "corp.com",
            "email_subject": "General question about settings",
            "email_body": "Can someone help me with my dashboard configuration?",
        }

        hitl_result = hitl_pipeline.invoke(prepare_initial_state(hitl_payload))
        require(hitl_result["hitl_status"] == "pending", "Must be diverted to HITL pending")
        require(hitl_result["p2_status"] == "hitl_pending", "P2 status must be hitl_pending")
        require(len(db.get_dispatch_log("em_chk_hitl_001")) == 0, "No dispatch before approval")
        print("  -> Low-confidence email halted before dispatcher in HITL queue. [PASS]")

        # Human reviewer resolution
        resolved = db.resolve_hitl_review("em_chk_hitl_001", "approved", "sec_reviewer")
        require(resolved is True, "Review resolution must succeed")
        disp_res = dispatcher_node(hitl_result, db=db, config=test_config)
        require(disp_res["p2_status"] in ("simulated", "dispatched"), "Dispatch after approval")
        require(len(db.get_dispatch_log("em_chk_hitl_001")) == 1, "Dispatched after approval")
        print("  -> Human approval resolved review row and unblocked dispatch. [PASS]")

        # -------------------------------------------------------------
        # Check 4: Standalone Worker Pipeline Execution
        # -------------------------------------------------------------
        print("\n[Check 4] Standalone Phase 2 Worker Pipeline Execution")
        worker_email_id = "em_chk_worker_001"
        with db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO email_triage (
                    email_id, message_id, thread_id, sender_email,
                    masked_subject, masked_body, routing_status, status,
                    p2_category, p2_priority, p2_sentiment, p2_customer_emotion,
                    p2_summary, p2_suggested_team, p2_confidence, p2_classifier_used,
                    hitl_status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'gatekeeper_approved', 'done',
                          'Demo Request', 'High', 'Neutral', 'Calm',
                          'Demo inquiry', 'Sales', 0.95, 'groq', 'auto_approved',
                          CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (
                    worker_email_id,
                    f"<{worker_email_id}@sales.com>",
                    f"th_{worker_email_id}",
                    "lead@sales.com",
                    "Demo request for enterprise seats",
                    "Hi sales, we would like a demo.",
                ),
            )

        worker_classifier = MagicMock(spec=ClassifierClient)
        worker_classifier.classify.return_value = {
            "category": "Demo Request",
            "priority": "High",
            "sentiment": "Positive",
            "customer_emotion": "Calm",
            "summary": "Demo inquiry for enterprise tier",
            "suggested_team": "Sales",
            "confidence": 0.95,
            "p2_classifier_used": "groq",
        }

        worker_pipeline = create_phase2_worker_pipeline(
            db=db,
            config=test_config,
            classifier_client=worker_classifier,
            offline=True,
        )

        worker_state = prepare_initial_state({
            "email_id": worker_email_id,
            "message_id": f"<{worker_email_id}@sales.com>",
            "thread_id": f"th_{worker_email_id}",
            "sender_email": "lead@sales.com",
            "sender_domain": "sales.com",
            "masked_subject": "Demo request for enterprise seats",
            "masked_body": "Hi sales, we would like a demo.",
            "routing_status": "gatekeeper_approved",
            "gatekeeper_decision": "legitimate",
        })

        worker_result = worker_pipeline.invoke(worker_state)
        require(worker_result["hitl_status"] == "auto_approved", "Worker auto-approved")
        require(
            worker_result["p2_status"] in ("simulated", "dispatched"),
            "Worker dispatched",
        )
        worker_logs = db.get_dispatch_log(worker_email_id)
        require(len(worker_logs) == 1, "Worker created outbox row")
        require(worker_logs[0]["destination"] == "crm", "Demo Request routes to CRM")
        print("  -> Worker pipeline executed directly starting at Node 06 (Classifier). [PASS]")

        # -------------------------------------------------------------
        # Check 5: Hard Invariant #10 (Zero-Touch on Phase 1 Data)
        # -------------------------------------------------------------
        print("\n[Check 5] Hard Invariant #10 (Zero-Touch on Phase 1 Data)")
        rec = db.get_record("em_chk_p2_001")
        require(rec is not None, "Record must exist")
        require(rec["status"] == "done", "Phase 1 status must remain 'done'")
        require(
            rec["routing_status"] == "gatekeeper_approved",
            "Phase 1 routing_status must remain 'gatekeeper_approved'",
        )
        require(rec["dispatch_target"] is None, "Phase 1 dispatch_target must remain untouched")
        require(rec["masked_subject"] is not None, "Masked subject preserved")
        require(rec["masked_body"] is not None, "Masked body preserved")
        print("  -> Phase 1 columns remain 100% immutable throughout Phase 2 execution. [PASS]")

    print("\n" + "=" * 70)
    print(" ALL CHECKS PASSED: Phase 2 LangGraph Pipeline Integration is ready!")
    print("=" * 70)


if __name__ == "__main__":
    run_checks()
