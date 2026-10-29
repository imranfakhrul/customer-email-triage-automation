"""Persistent Phase 2 Queue Worker daemon, atomic batch claiming, and crash recovery.

Milestone [P2-09]:
Polls for Phase 1 gatekeeper_approved records, atomically claims batches, executes the
standalone LangGraph Phase 2 stategraph, and dispatches to downstream destination adapters
or routes to HITL review.

Hard Invariants:
- Hard Invariant #10: Phase 1 columns (email_triage.status, routing_status, dispatch_target,
  masked_*) remain completely untouched.
- Hard Invariant #12: Claiming is ONE atomic SQL statement with subquery limit.
- Hard Invariant #13: Every outbound dispatch is preceded by an outbox ledger entry.
- Hard Invariant #3: Logs contain IDs, engine names, statuses, and exception class names only.
"""

from __future__ import annotations

import argparse
import copy
import logging
import signal
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

# Anchor project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from db.database import TriageDatabase  # noqa: E402
from pipeline import create_phase2_worker_pipeline  # noqa: E402
from state import EmailClassification, TriageState  # noqa: E402
from utils.adapters import register_active_adapters  # noqa: E402
from utils.config import get_config  # noqa: E402

logger = logging.getLogger("phase2_worker")


def _setup_logging() -> None:
    """Configures structured console logging if not already configured."""
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] [phase2_worker] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)


def run_worker_once(
    db: TriageDatabase | None = None,
    config: dict[str, Any] | None = None,
    worker_id: str | None = None,
    batch_size: int = 10,
    dry_run: bool = False,
    offline: bool = False,
) -> int:
    """Executes a single cycle of crash recovery, intake sync, and batch processing.

    Args:
        db: Optional TriageDatabase instance.
        config: Optional configuration dictionary.
        worker_id: Optional identifier for this worker run.
        batch_size: Number of jobs to claim in this batch.
        dry_run: Force dry-run dispatch mode.
        offline: Run in offline mode without external AI/APIs.

    Returns:
        Number of jobs processed in this cycle.
    """
    _setup_logging()
    db_inst = db or TriageDatabase()
    cfg = copy.deepcopy(config or get_config())
    wid = worker_id or f"worker_{uuid.uuid4().hex[:8]}"

    if dry_run and "dispatch" in cfg:
        cfg["dispatch"]["dry_run"] = True
    if offline and "classification" in cfg:
        cfg["classification"]["primary"] = "offline_heuristic"

    # PRR-02: Register active destination adapters from config
    register_active_adapters(cfg)

    # 1. Stale claim crash recovery
    stale_mins = int(cfg.get("system", {}).get("idempotency_stale_minutes", 15))
    max_retries = int(cfg.get("dispatch", {}).get("max_retries", 3))
    recovered = db_inst.recover_stale_p2_jobs(stale_minutes=stale_mins, max_retries=max_retries)
    if recovered > 0:
        logger.info("Crash recovery swept %d orphaned jobs", recovered)

    # 2. Intake synchronization from Phase 1
    newly_synced = db_inst.sync_p2_intake()
    if newly_synced > 0:
        logger.info("Intake synced %d new gatekeeper_approved records", newly_synced)

    # 3. Atomic batch claim
    claimed_jobs = db_inst.claim_p2_jobs(batch_size=batch_size, worker_id=wid)
    if not claimed_jobs:
        return 0

    logger.info("Worker %s claimed %d jobs for processing", wid, len(claimed_jobs))

    # 4. Compile standalone Phase 2 worker graph
    classifier_client = None
    if offline:
        from utils.classifier_client import ClassifierClient
        classifier_client = ClassifierClient(config=cfg)
        classifier_client.jev_enabled = False
        classifier_client.jev_api_key = None
        classifier_client.groq_api_key = None

    pipeline = create_phase2_worker_pipeline(
        db=db_inst,
        config=cfg,
        classifier_client=classifier_client,
        offline=offline,
    )

    processed_count = 0
    for job in claimed_jobs:
        email_id = job["email_id"]

        # PRR-01: Reconstitute prior classification if already classified and approved
        existing_classification = None
        if job.get("p2_category"):
            existing_classification = EmailClassification(
                category=job["p2_category"],
                priority=job.get("p2_priority", "Medium"),
                sentiment=job.get("p2_sentiment", "Neutral"),
                customer_emotion=job.get("p2_customer_emotion", "Calm"),
                summary=job.get("p2_summary", ""),
                suggested_team=job.get("p2_suggested_team", "Support"),
                confidence=float(job.get("p2_confidence") or 1.0),
            )

        hitl_status_val = job.get("hitl_status") or "none"

        initial_state: TriageState = {
            "email_id": email_id,
            "message_id": job.get("message_id") or f"<{email_id}@worker.local>",
            "thread_id": job.get("thread_id") or f"th_{email_id}",
            "sender_email": job.get("sender_email") or "unknown@example.com",
            "masked_subject": job.get("masked_subject") or "",
            "masked_body": job.get("masked_body") or "",
            "is_active_thread": bool(job.get("is_active_thread")),
            "gatekeeper_decision": "legitimate",
            "gatekeeper_confidence": float(job.get("gatekeeper_confidence") or 1.0),
            "classifier_used": job.get("classifier_used") or "jev",
            "routing_status": "gatekeeper_approved",
            "status": "done",
            "unmask_pii": False,
            "hitl_status": hitl_status_val,
            "classification": existing_classification,
            "p2_classifier_used": job.get("p2_classifier_used") or "offline_heuristic",
        }

        try:
            final_state = pipeline.invoke(initial_state)
            p2_status = final_state.get("p2_status")
            hitl_status = final_state.get("hitl_status")

            next_attempt_at: str | None = None
            error_message = final_state.get("error_message")

            if p2_status == "hitl_pending" or hitl_status == "pending":
                terminal_state = "hitl_pending"
                if not error_message:
                    error_message = "Requires HITL review"
            elif p2_status in ("dispatched", "simulated", "auto_approved"):
                terminal_state = "done"
            elif p2_status == "dead_letter":
                terminal_state = "dead_letter"
                if not error_message:
                    error_message = "Exceeded max dispatch attempts (dead-lettered)"
            elif p2_status in ("failed", "persist_failed"):
                terminal_state = "failed"
                if not error_message:
                    error_message = "Permanent dispatch failure"
            elif p2_status == "deferred":
                # PRR-03: Map deferred to retryable state ('unclaimed') with next_attempt_at backoff
                terminal_state = "unclaimed"
                dispatch_results = final_state.get("dispatch_results") or []
                reasons = [r.get("reason") for r in dispatch_results if r.get("reason")]
                primary_reason = reasons[0] if reasons else "deferred"

                # Calculate cooldown delay
                if primary_reason == "circuit_breaker":
                    delay_seconds = 900.0
                elif primary_reason == "daily_cap":
                    delay_seconds = 3600.0
                else:
                    # Exponential backoff based on attempts count
                    attempts_count = int(job.get("attempts") or 1)
                    backoff_base = float(cfg.get("dispatch", {}).get("backoff_base_seconds", 1.0))
                    backoff_max = float(cfg.get("dispatch", {}).get("backoff_max_seconds", 60.0))
                    delay_seconds = min(backoff_max, backoff_base * (2 ** min(attempts_count, 6)))

                next_dt = datetime.now(UTC) + timedelta(seconds=delay_seconds)
                next_attempt_at = next_dt.strftime("%Y-%m-%d %H:%M:%S")
                error_message = f"Deferred: {primary_reason}"
            else:
                terminal_state = "failed"
                error_message = f"Unhandled p2_status: {p2_status}"

            db_inst.finish_p2_job(
                email_id=email_id,
                state=terminal_state,
                error_message=error_message,
                next_attempt_at=next_attempt_at,
                worker_id=wid,
            )
            processed_count += 1
            logger.info("Processed job %s -> state: %s", email_id, terminal_state)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Worker failed job: %s with exception class: %s",
                email_id,
                exc.__class__.__name__,
            )
            db_inst.finish_p2_job(
                email_id=email_id,
                state="failed",
                error_message=exc.__class__.__name__,
                worker_id=wid,
            )
            processed_count += 1

    return processed_count


class Phase2Worker:
    """Continuous polling Phase 2 background worker daemon with graceful shutdown."""

    def __init__(
        self,
        db: TriageDatabase | None = None,
        config: dict[str, Any] | None = None,
        worker_id: str | None = None,
        batch_size: int = 10,
        poll_interval: float = 5.0,
        stale_minutes: int = 15,
        max_retries: int = 3,
        dry_run: bool = False,
        offline: bool = False,
    ) -> None:
        self.db = db or TriageDatabase()
        self.config = copy.deepcopy(config or get_config())
        self.worker_id = worker_id or f"worker_{uuid.uuid4().hex[:8]}"
        self.batch_size = batch_size
        self.poll_interval = poll_interval
        self.stale_minutes = stale_minutes
        self.max_retries = max_retries
        self.dry_run = dry_run
        self.offline = offline
        self.running = False

        if self.offline and "classification" in self.config:
            self.config["classification"]["primary"] = "offline_heuristic"
        if self.dry_run and "dispatch" in self.config:
            self.config["dispatch"]["dry_run"] = True

        # PRR-02: Register active destination adapters from config
        register_active_adapters(self.config)

    def stop(self) -> None:
        """Signals the worker loop to stop gracefully."""
        self.running = False

    def _signal_handler(self, signum: int, _frame: Any) -> None:
        logger.info("Received OS signal %d; initiating graceful shutdown...", signum)
        self.stop()

    def run(self, once: bool = False) -> int:
        """Runs the worker loop until stopped or when once=True after one cycle.

        Args:
            once: When True, runs a single polling cycle and exits.

        Returns:
            Total number of jobs processed.
        """
        _setup_logging()
        logger.info(
            "Phase 2 worker %s starting (batch_size=%d, poll_interval=%.1fs, dry_run=%s)",
            self.worker_id,
            self.batch_size,
            self.poll_interval,
            self.dry_run,
        )

        try:
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        except (ValueError, AttributeError):
            pass  # Non-main thread or unsupported environment

        self.running = True
        total_processed = 0

        while self.running:
            try:
                processed = run_worker_once(
                    db=self.db,
                    config=self.config,
                    worker_id=self.worker_id,
                    batch_size=self.batch_size,
                    dry_run=self.dry_run,
                    offline=self.offline,
                )
                total_processed += processed
            except Exception as exc:  # noqa: BLE001
                logger.error("Error in worker cycle: %s", exc.__class__.__name__)

            if once or not self.running:
                break

            # Responsive sleep in small intervals to honor graceful stop immediately
            elapsed = 0.0
            sleep_slice = 0.2
            while self.running and elapsed < self.poll_interval:
                time.sleep(sleep_slice)
                elapsed += sleep_slice

        logger.info(
            "Phase 2 worker %s terminated. Total jobs processed: %d",
            self.worker_id,
            total_processed,
        )
        return total_processed


def main() -> int:
    """CLI entrypoint for running the Phase 2 worker daemon."""
    parser = argparse.ArgumentParser(
        description="Customer Email Triage Automation — Phase 2 Background Queue Worker"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=10,
        help="Number of records to claim per batch (default: 10)",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=5.0,
        help="Polling sleep interval in seconds when queue is idle (default: 5.0)",
    )
    parser.add_argument(
        "--stale-minutes",
        type=int,
        default=15,
        help="Minutes before in-flight claims are considered crashed and recovered (default: 15)",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Maximum recovery retries before moving to dead_letter (default: 3)",
    )
    parser.add_argument(
        "--worker-id",
        type=str,
        default=None,
        help="Unique identifier for this worker instance (default: auto-generated)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single intake, recovery, and processing batch then exit 0",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Force simulated dry-run mode for downstream destination dispatches",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Enable live outbound API dispatches",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Run offline heuristics without making external LLM or API calls",
    )

    args = parser.parse_args()

    # Determine mode
    dry_run = True
    if args.live:
        dry_run = False
    elif args.dry_run:
        dry_run = True

    worker = Phase2Worker(
        batch_size=args.batch_size,
        poll_interval=args.poll_interval,
        stale_minutes=args.stale_minutes,
        max_retries=args.max_retries,
        worker_id=args.worker_id,
        dry_run=dry_run,
        offline=args.offline,
    )

    try:
        worker.run(once=args.once)
        return 0
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received; exiting cleanly.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
