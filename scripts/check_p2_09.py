"""Manual verification script for Milestone [P2-09].

Verifies Persistent Phase 2 Queue Worker, Atomic Batch Claiming, Crash Recovery,
Dead-Letter Queue Transitions, and Phase 1 Database Immutability.

Usage:
    ./venv/bin/python scripts/check_p2_09.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from db.database import TriageDatabase  # noqa: E402
from scripts.phase2_worker import run_worker_once  # noqa: E402
from utils.config import get_config  # noqa: E402


def require(condition: bool, msg: str = "") -> None:
    """Assertion helper avoiding S101 bandit flags in standalone scripts."""
    if not condition:
        raise RuntimeError(f"Check requirement failed: {msg}")


def _insert_p1_email(
    db: TriageDatabase,
    email_id: str,
    status: str = "done",
    routing_status: str = "gatekeeper_approved",
    subject: str = "Test Subject",
    body: str = "Test Body",
) -> None:
    with db.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO email_triage (
                email_id, message_id, thread_id, sender_email,
                masked_subject, masked_body, routing_status, status,
                created_at, updated_at
            ) VALUES (?, ?, ?, 'user@example.com', ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (
                email_id,
                f"<{email_id}@ex.com>",
                f"th_{email_id}",
                subject,
                body,
                routing_status,
                status,
            ),
        )


def run_checks() -> None:
    print("=" * 70)
    print(" RUNNING MANUAL VERIFICATION FOR MILESTONE [P2-09]")
    print(" Persistent Phase 2 Queue Worker, Atomic Claiming & Recovery")
    print("=" * 70)

    cfg = get_config()
    test_config = json.loads(json.dumps(cfg))
    test_config["classification"]["primary"] = "offline_heuristic"
    test_config["dispatch"]["dry_run"] = True

    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = str(Path(tmp_dir) / "check_p2_09.db")
        db = TriageDatabase(db_path=db_path)

        # -------------------------------------------------------------
        # Check 1: Intake Synchronization & Idempotency
        # -------------------------------------------------------------
        print("\n[Check 1] Phase 1 Intake Synchronization & Idempotency")
        _insert_p1_email(db, "chk_sync_01", status="done", routing_status="gatekeeper_approved")
        _insert_p1_email(db, "chk_sync_02", status="processing", routing_status="processing")
        _insert_p1_email(db, "chk_sync_03", status="done", routing_status="spam_diverted")
        _insert_p1_email(db, "chk_sync_04", status="done", routing_status="gatekeeper_approved")

        synced = db.sync_p2_intake()
        print(f"  -> First intake sync inserted: {synced} jobs (expected 2)")
        require(synced == 2, f"Expected 2 synced jobs, got {synced}")

        job1 = db.get_p2_job("chk_sync_01")
        require(job1 is not None and job1["state"] == "unclaimed", "chk_sync_01 state mismatch")
        require(db.get_p2_job("chk_sync_02") is None, "In-flight email should not be in p2_jobs")
        require(db.get_p2_job("chk_sync_03") is None, "Spam email should not be in p2_jobs")

        resynced = db.sync_p2_intake()
        print(f"  -> Idempotent re-sync inserted: {resynced} jobs (expected 0)")
        require(resynced == 0, f"Expected 0 on idempotent resync, got {resynced}")
        print("  [PASS] Intake sync filters correctly and is strictly idempotent.")

        # -------------------------------------------------------------
        # Check 2: Single-Statement Atomic Batch Claiming
        # -------------------------------------------------------------
        print("\n[Check 2] Atomic Batch Claiming & Worker Isolation")
        _insert_p1_email(db, "chk_claim_01")
        _insert_p1_email(db, "chk_claim_02")
        _insert_p1_email(db, "chk_claim_03")
        db.sync_p2_intake()

        w1_jobs = db.claim_p2_jobs(batch_size=2, worker_id="worker_alpha")
        w2_jobs = db.claim_p2_jobs(batch_size=2, worker_id="worker_beta")

        print(
            f"  -> Worker Alpha claimed {len(w1_jobs)} jobs, "
            f"Worker Beta claimed {len(w2_jobs)} jobs"
        )
        require(len(w1_jobs) == 2, "Worker Alpha should claim 2 jobs")
        require(len(w2_jobs) == 2, "Worker Beta should claim 2 jobs")

        alpha_ids = {j["email_id"] for j in w1_jobs}
        beta_ids = {j["email_id"] for j in w2_jobs}
        require(
            alpha_ids.isdisjoint(beta_ids),
            "Worker claims overlapped! Double-claim bug detected.",
        )
        print("  [PASS] Single-statement atomic claiming guarantees zero overlap.")

        # -------------------------------------------------------------
        # Check 3: Stale Claim Sweeper & Dead-Letter Queue
        # -------------------------------------------------------------
        print("\n[Check 3] Crash Recovery: Stale Sweeper & Dead-Letter Queue")
        stale_time = (datetime.now(UTC) - timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")

        # Job A: 1 attempt -> reset to unclaimed
        with db.get_connection() as conn:
            conn.execute(
                "UPDATE p2_jobs SET claimed_at = ? WHERE email_id = 'chk_claim_01'",
                (stale_time,),
            )
        # Job B: 3 attempts -> dead_letter
        with db.get_connection() as conn:
            conn.execute(
                "UPDATE p2_jobs SET claimed_at = ?, attempts = 3 WHERE email_id = 'chk_claim_02'",
                (stale_time,),
            )

        recovered = db.recover_stale_p2_jobs(stale_minutes=15, max_retries=3)
        print(f"  -> Sweeper recovered: {recovered} crashed jobs")
        require(recovered == 2, f"Expected 2 recovered jobs, got {recovered}")

        job_a = db.get_p2_job("chk_claim_01")
        job_b = db.get_p2_job("chk_claim_02")
        require(
            job_a["state"] == "unclaimed" and job_a["worker_id"] is None,
            "Job A recovery failed",
        )
        require(
            job_b["state"] == "dead_letter" and "max retries" in job_b["error_message"].lower(),
            "Job B DLQ failed",
        )
        print("  [PASS] Stale claims reset cleanly; exceeded retries route to dead_letter.")

        # -------------------------------------------------------------
        # Check 4: End-to-End Worker Batch Execution & Invariant #10
        # -------------------------------------------------------------
        print("\n[Check 4] End-to-End Worker Run & Zero-Touch Phase 1 Invariant")
        _insert_p1_email(
            db,
            "chk_e2e_worker_01",
            subject="Bug report: crash in pipeline",
            body="Segmentation fault in data processor.",
        )

        processed = run_worker_once(
            db=db,
            config=test_config,
            worker_id="test_e2e_worker",
            batch_size=5,
            dry_run=True,
            offline=True,
        )
        print(f"  -> Processed batch count: {processed}")
        require(processed >= 1, "Expected at least 1 processed job")

        job_e2e = db.get_p2_job("chk_e2e_worker_01")
        require(
            job_e2e is not None and job_e2e["state"] in ("done", "hitl_pending"),
            "Job final state invalid",
        )
        print(f"  -> p2_jobs state: {job_e2e['state']}")

        # Hard Invariant #10 verification: email_triage status untouched
        p1_rec = db.get_record("chk_e2e_worker_01")
        require(
            p1_rec["status"] == "done",
            "Invariant #10 violated: email_triage.status was modified!",
        )
        require(
            p1_rec["routing_status"] == "gatekeeper_approved",
            "Invariant #10 violated: email_triage.routing_status was modified!",
        )
        print("  [PASS] Hard Invariant #10 upheld: Phase 1 database columns 100% untouched.")

        # -------------------------------------------------------------
        # Check 5: HITL Approval Re-Claiming
        # -------------------------------------------------------------
        print("\n[Check 5] HITL Approval Handoff & Re-Claiming")
        email_hitl = "chk_hitl_handoff_01"
        _insert_p1_email(db, email_hitl)
        db.sync_p2_intake()
        db.claim_p2_jobs(batch_size=1, worker_id="w_test")
        db.finish_p2_job(email_hitl, state="hitl_pending")

        with db.get_connection() as conn:
            conn.execute(
                "UPDATE email_triage SET hitl_status = 'pending' WHERE email_id = ?",
                (email_hitl,),
            )

        # Reviewer approves
        db.resolve_hitl_review(
            email_id=email_hitl,
            decision="approved",
            reviewed_by="security_admin",
            notes="Manually verified legitimate bug report",
        )

        job_hitl = db.get_p2_job(email_hitl)
        require(
            job_hitl["state"] == "hitl_resolved",
            f"Expected hitl_resolved, got {job_hitl['state']}",
        )

        reclaimed = db.claim_p2_jobs(batch_size=1, worker_id="w_reclaim")
        require(
            len(reclaimed) == 1 and reclaimed[0]["email_id"] == email_hitl,
            "Re-claiming failed",
        )
        print("  [PASS] HITL human approval transitions job to hitl_resolved for worker dispatch.")

    print("\n" + "=" * 70)
    print(" ALL 5/5 CHECKS PASSED SUCCESSFULLY!")
    print("=" * 70)


if __name__ == "__main__":
    run_checks()
