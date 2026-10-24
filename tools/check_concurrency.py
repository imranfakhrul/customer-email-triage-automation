#!/usr/bin/env python3
"""Concurrency validation script for SQLite idempotency locking.

Tests atomic locking across 4 real processes and 8 concurrent threads on a temporary
database file. Validates that exactly 1 worker wins each race and 0 exceptions/crashes
occur across 30 trials of both brand new email locking and stale lock recovery.

Output format requirement:
    NEW EMAIL:  winners=<n> crashes=<n>   (over 30 trials, report the worst trial)
    STALE LOCK: winners=<n> crashes=<n>   (over 30 trials, report the worst trial)
    RESULT: PASS   (only if every trial had winners=1 and crashes=0), otherwise RESULT: FAIL
"""

from datetime import datetime, timedelta, timezone
import multiprocessing as mp
import os
import sys
import tempfile
import threading
from typing import Any, Dict, List, Tuple

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from db.database import TriageDatabase


def _thread_worker(
    db_path: str,
    email_id: str,
    is_stale: bool,
    start_barrier: Any,
    out_queue: mp.Queue,
) -> None:
    """Thread worker that executes check_and_acquire upon synchronization."""
    db = TriageDatabase(db_path=db_path)
    try:
        start_barrier.wait(timeout=10.0)
    except Exception:
        pass

    try:
        if is_stale:
            allowed, outcome, record = db.check_and_acquire(
                email_id=email_id,
                stale_minutes=10,
                max_retries=3,
            )
        else:
            allowed, outcome, record = db.check_and_acquire(
                email_id=email_id,
                thread_id="th_concurrency",
                sender_email="worker@company.com",
            )
        out_queue.put({"allowed": bool(allowed), "outcome": outcome, "crash": 0, "error": None})
    except Exception as exc:
        out_queue.put({"allowed": False, "outcome": None, "crash": 1, "error": str(exc)})


def _process_worker(
    db_path: str,
    email_id: str,
    is_stale: bool,
    proc_barrier: Any,
    out_queue: mp.Queue,
) -> None:
    """Process worker running 2 concurrent threads (4 processes * 2 threads = 8 workers)."""
    t_barrier = threading.Barrier(2)

    def _sub_worker():
        try:
            proc_barrier.wait(timeout=10.0)
        except Exception:
            pass
        _thread_worker(db_path, email_id, is_stale, t_barrier, out_queue)

    t1 = threading.Thread(target=_sub_worker)
    t2 = threading.Thread(target=_sub_worker)
    t1.start()
    t2.start()
    t1.join(timeout=15.0)
    t2.join(timeout=15.0)


def run_trial(db_path: str, email_id: str, is_stale: bool) -> Tuple[int, int]:
    """Executes a single concurrency trial with 4 processes and 8 threads."""
    out_queue = mp.Queue()
    proc_barrier = mp.Barrier(4)

    processes = [
        mp.Process(
            target=_process_worker,
            args=(db_path, email_id, is_stale, proc_barrier, out_queue),
        )
        for _ in range(4)
    ]

    for p in processes:
        p.start()

    for p in processes:
        p.join(timeout=15.0)

    results: List[Dict[str, Any]] = []
    while not out_queue.empty():
        try:
            results.append(out_queue.get_nowait())
        except Exception:
            break

    winners = sum(1 for r in results if r.get("allowed") is True)
    crashes = sum(r.get("crash", 0) for r in results)

    # Account for missing workers if any process died before reporting
    if len(results) < 8:
        crashes += 8 - len(results)

    return winners, crashes


def _is_worse(w1: int, c1: int, w2: int, c2: int) -> bool:
    """Determines if trial (w1, c1) is worse than (w2, c2).

    A trial is strictly worse if it had crashes, or if winners deviated from 1.
    """
    score1 = (c1 > 0, c1, abs(w1 - 1))
    score2 = (c2 > 0, c2, abs(w2 - 1))
    return score1 > score2


def main() -> int:
    temp_dir = tempfile.TemporaryDirectory()
    db_path = os.path.join(temp_dir.name, "concurrency_check.db")
    db = TriageDatabase(db_path=db_path)

    trials_count = 30

    # 1. NEW EMAIL Trials
    worst_new_winners = 1
    worst_new_crashes = 0
    all_new_passed = True

    for trial in range(trials_count):
        email_id = f"check_new_{trial}_{os.getpid()}"
        winners, crashes = run_trial(db_path, email_id, is_stale=False)
        if winners != 1 or crashes != 0:
            all_new_passed = False
            if _is_worse(winners, crashes, worst_new_winners, worst_new_crashes):
                worst_new_winners = winners
                worst_new_crashes = crashes

    # 2. STALE LOCK Trials
    worst_stale_winners = 1
    worst_stale_crashes = 0
    all_stale_passed = True

    for trial in range(trials_count):
        email_id = f"check_stale_{trial}_{os.getpid()}"
        db.check_and_acquire(email_id=email_id)
        # Backdate updated_at by 15 minutes (stale threshold is 10 minutes)
        stale_time = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()
        with db.get_connection() as conn:
            conn.execute(
                "UPDATE email_triage SET updated_at = ? WHERE email_id = ?",
                (stale_time, email_id),
            )

        winners, crashes = run_trial(db_path, email_id, is_stale=True)
        if winners != 1 or crashes != 0:
            all_stale_passed = False
            if _is_worse(winners, crashes, worst_stale_winners, worst_stale_crashes):
                worst_stale_winners = winners
                worst_stale_crashes = crashes

    # Clean up temp resources
    try:
        temp_dir.cleanup()
    except Exception:
        pass

    # Print output matching exact specification
    print(f"NEW EMAIL:  winners={worst_new_winners} crashes={worst_new_crashes}")
    print(f"STALE LOCK: winners={worst_stale_winners} crashes={worst_stale_crashes}")

    if all_new_passed and all_stale_passed:
        print("RESULT: PASS")
        return 0
    else:
        print("RESULT: FAIL")
        return 1


if __name__ == "__main__":
    sys.exit(main())
