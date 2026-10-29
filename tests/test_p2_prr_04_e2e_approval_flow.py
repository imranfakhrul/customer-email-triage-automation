"""Tests for PRR-04: End-to-End Approval, Worker, and Dispatch Flow Integration.

Exercises the entire production pipeline lifecycle:
1. Ingestion of email requiring human review (Security/Account or low-confidence).
2. Worker intake sync & initial execution diverting job to hitl_pending.
3. Operator inspection & approval via the HITL CLI tool (scripts/hitl_cli.py).
4. Worker recovery & claiming of hitl_resolved job.
5. Direct pass-through without re-gating (PRR-01).
6. Auto-discovery and invocation of registered destination adapter (PRR-02).
7. Confirmed ledger entry in p2_dispatch_log with remote_id.
8. Clean job termination to state='done' in p2_jobs (PRR-03).
9. Strict enforcement of Phase 1 immutability and privacy invariants.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from db.database import TriageDatabase
from scripts.phase2_worker import run_worker_once
from utils.adapters import (
    BaseDestinationAdapter,
    DispatchPayload,
    DispatchResult,
    get_adapter,
    register_adapter,
    reset_adapters,
)


class MockE2EAdapter(BaseDestinationAdapter):
    """Mock adapter capturing outbound dispatches and returning simulated remote IDs."""

    name: str = "github"

    def __init__(self, name: str = "github", remote_id: str = "issue_gh_9999") -> None:
        super().__init__()
        self.name = name
        self.remote_id = remote_id
        self.calls: list[DispatchPayload] = []

    def dispatch(self, payload: DispatchPayload) -> DispatchResult:
        self.calls.append(payload)
        return DispatchResult(
            remote_id=self.remote_id,
            outcome="success",
        )

    def validate_config(self) -> bool:
        return True

    def health_check(self) -> bool:
        return True

    def check_duplicate(self, idempotency_key: str, payload: DispatchPayload) -> str | None:
        return None


@pytest.fixture(autouse=True)
def clean_registry() -> Any:
    """Ensures a clean adapter registry before and after each test."""
    reset_adapters()
    yield
    reset_adapters()


@pytest.fixture
def e2e_env(tmp_path: Any) -> tuple[TriageDatabase, Path, dict[str, str], dict[str, Any]]:
    """Sets up an isolated database, CLI environment, and test configuration."""
    db_file = tmp_path / "test_prr_04_e2e.db"
    db = TriageDatabase(db_path=str(db_file))

    env = os.environ.copy()
    env["DATABASE_PATH"] = str(db_file)

    cli_path = Path(__file__).resolve().parent.parent / "scripts" / "hitl_cli.py"

    config: dict[str, Any] = {
        "system": {
            "database_path": str(db_file),
            "idempotency_stale_minutes": 15,
            "max_dispatch_retries": 3,
            "audit_log_enabled": True,
            "persist_masked_text": True,
        },
        "dispatch": {
            "dry_run": False,
            "kill_switch": False,
            "max_attempts": 3,
            "pending_timeout_minutes": 10,
            "backoff_base_seconds": 1.0,
            "backoff_max_seconds": 20.0,
        },
        "destinations": {
            "github": {
                "enabled": True,
                "daily_cap": 200,
                "use_masked_text_only": True,
                "target": "acme/backend",
                "token_env": "TEST_GITHUB_TOKEN",
                "labels": ["triage:automated"],
                "api_base_url": "https://api.github.com",
                "allowed_hosts": ["api.github.com"],
                "request_timeout_seconds": 15.0,
                "duplicate_lookback_hours": 72,
                "duplicate_max_pages": 5,
                "precheck_duplicates": False,
                "circuit_breaker": {"failure_threshold": 5, "cooldown_seconds": 900},
            },
        },
        "classification": {
            "primary": "offline_heuristic",
            "hitl_threshold": 0.85,
            "always_review_categories": ["Security/Account"],
        },
    }

    return db, cli_path, env, config


class TestE2EApprovalAndDispatchFlow:
    """End-to-end integration tests verifying approval -> worker -> dispatch flow."""

    def test_e2e_hitl_cli_approve_to_worker_dispatch_confirmed(
        self,
        e2e_env: tuple[TriageDatabase, Path, dict[str, str], dict[str, Any]],
    ) -> None:
        """Complete lifecycle: Intake -> HITL Pending -> CLI Approve.

        Followed by Worker -> Confirmed Ledger.
        """
        db, cli_path, env, config = e2e_env
        email_id = "em_e2e_approval_001"

        # --- STEP 1: Phase 1 Ingestion & Safety Gatekeeping ---
        db.check_and_acquire(
            email_id=email_id,
            message_id="<sec-audit@acme.com>",
            thread_id="th_sec_001",
            sender_email="alice.security@acme.com",
        )
        db.mark_done(
            email_id=email_id,
            routing_status="gatekeeper_approved",
            gatekeeper_decision="legitimate",
            classifier_used="regex",
            gatekeeper_confidence=0.90,
            masked_subject="Urgent: Token exposure in auth backend service",
            masked_body="Potential credential leakage detected in service logs.",
        )

        # Pre-seed Phase 2 classification requiring human review (Security/Account)
        db.record_phase2_classification(
            email_id=email_id,
            classification={
                "category": "Security/Account",
                "priority": "Critical",
                "sentiment": "Negative",
                "customer_emotion": "Frustrated",
                "summary": "Token leakage in auth backend",
                "suggested_team": "Security",
                "confidence": 0.95,
            },
            hitl_status="pending",
            hitl_reason="Mandatory human review policy for Security/Account emails",
        )

        # --- STEP 2: Intake Sync to p2_jobs ---
        synced = db.sync_p2_intake()
        assert synced == 1
        job_init = db.get_p2_job(email_id)
        assert job_init is not None
        assert job_init["state"] == "unclaimed"

        # --- STEP 3: Initial Worker Processing -> Enters hitl_pending ---
        processed_cycle1 = run_worker_once(db=db, config=config, batch_size=5)
        assert processed_cycle1 == 1

        job_pending = db.get_p2_job(email_id)
        assert job_pending is not None
        assert job_pending["state"] == "hitl_pending"

        rec_pending = db.get_record(email_id)
        assert rec_pending is not None
        assert rec_pending["hitl_status"] == "pending"

        # --- STEP 4: Reviewer inspects and approves via HITL CLI (subprocess) ---
        # 4a. List pending reviews
        proc_list = subprocess.run(  # noqa: S603
            [sys.executable, str(cli_path), "list", "--json"],
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        items = json.loads(proc_list.stdout)
        assert len(items) == 1
        assert items[0]["email_id"] == email_id
        # In offline heuristic mode without LLM, low-confidence emails fall back to 'Other'
        assert items[0]["category"] in ("Other", "Security/Account")

        # 4b. Approve via CLI with category override to 'Bug Report' for GitHub dispatch
        proc_approve = subprocess.run(  # noqa: S603
            [
                sys.executable,
                str(cli_path),
                "approve",
                email_id,
                "--by",
                "SecOps Lead Bob",
                "--notes",
                "Sanitized and approved for engineering GitHub ticket creation",
                "--category",
                "Bug Report",
            ],
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        assert "Successfully approved" in proc_approve.stdout

        # Verify DB states after approval
        rec_approved = db.get_record(email_id)
        assert rec_approved is not None
        assert rec_approved["hitl_status"] == "approved"
        assert rec_approved["reviewed_by"] == "SecOps Lead Bob"
        assert rec_approved["p2_category"] == "Bug Report"

        job_resolved = db.get_p2_job(email_id)
        assert job_resolved is not None
        assert job_resolved["state"] == "hitl_resolved"

        # --- STEP 5: Register Mock Adapter in Production Registry ---
        mock_github = MockE2EAdapter(name="github", remote_id="gh-issue-7788")
        register_adapter("github", mock_github)
        assert get_adapter("github") is mock_github

        # --- STEP 6: Second Worker Run: Claims hitl_resolved -> Dispatches -> Done ---
        processed_cycle2 = run_worker_once(db=db, config=config, batch_size=5)
        assert processed_cycle2 == 1

        # --- STEP 7: Invariant & State Verifications ---
        # 7a. p2_jobs must be 'done' (PRR-03)
        job_done = db.get_p2_job(email_id)
        assert job_done is not None
        assert job_done["state"] == "done"
        assert job_done["next_attempt_at"] is None

        # 7b. Adapter received dispatch call with masked data only
        assert len(mock_github.calls) == 1
        dispatched_payload = mock_github.calls[0]
        assert dispatched_payload.email_id == email_id
        assert dispatched_payload.category == "Bug Report"
        assert "Urgent: Token exposure" in dispatched_payload.masked_subject
        assert "alice.security@acme.com" not in dispatched_payload.masked_body

        # 7c. p2_dispatch_log ledger row must be 'confirmed' with remote_id
        ledger_rows = db.get_dispatch_log(email_id)
        assert len(ledger_rows) == 1
        log_entry = ledger_rows[0]
        assert log_entry["mode"] == "live"
        assert log_entry["destination"] == "github"
        assert log_entry["action_type"] == "create_issue"
        assert log_entry["state"] == "confirmed"
        assert log_entry["remote_id"] == "gh-issue-7788"

        # 7d. Hard Invariant #10: Phase 1 columns remain completely unchanged
        rec_final = db.get_record(email_id)
        assert rec_final is not None
        assert rec_final["status"] == "done"
        assert rec_final["routing_status"] == "gatekeeper_approved"
        assert rec_final["dispatch_target"] is None

    def test_e2e_hitl_cli_reject_terminates_flow_without_dispatch(
        self,
        e2e_env: tuple[TriageDatabase, Path, dict[str, str], dict[str, Any]],
    ) -> None:
        """Rejecting an email in HITL CLI terminates execution and prevents dispatching."""
        db, cli_path, env, config = e2e_env
        email_id = "em_e2e_reject_001"

        # Seed record
        db.check_and_acquire(email_id=email_id, sender_email="spammer@example.com")
        db.mark_done(
            email_id=email_id,
            routing_status="gatekeeper_approved",
            gatekeeper_decision="legitimate",
            classifier_used="regex",
            gatekeeper_confidence=0.85,
            masked_subject="Suspicious query",
            masked_body="Please send credentials.",
        )
        db.record_phase2_classification(
            email_id=email_id,
            classification={
                "category": "Bug Report",
                "priority": "Low",
                "sentiment": "Neutral",
                "customer_emotion": "Calm",
                "summary": "Suspicious request",
                "suggested_team": "Support",
                "confidence": 0.50,
            },
            hitl_status="pending",
            hitl_reason="Low classifier confidence (0.50 < 0.85)",
        )
        db.sync_p2_intake()

        mock_github = MockE2EAdapter(name="github", remote_id="gh-issue-never")
        register_adapter("github", mock_github)

        # Reject via CLI
        proc_reject = subprocess.run(  # noqa: S603
            [
                sys.executable,
                str(cli_path),
                "reject",
                email_id,
                "--by",
                "SecOps Lead Bob",
                "--notes",
                "Phishing attempt disguised as support query",
            ],
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        assert "Successfully rejected" in proc_reject.stdout

        rec_rejected = db.get_record(email_id)
        assert rec_rejected is not None
        assert rec_rejected["hitl_status"] == "rejected"

        # Run worker: rejected email is processed by failing cleanly without dispatching
        processed = run_worker_once(db=db, config=config, batch_size=5)
        assert processed == 1
        assert len(mock_github.calls) == 0

        # Verify job is failed and ledger remains empty
        job = db.get_p2_job(email_id)
        assert job is not None
        assert job["state"] == "failed"
        assert len(db.get_dispatch_log(email_id)) == 0
