"""SQLite idempotency store and triage database management.

Maintains a three-state (`processing`, `done`, `failed`) lifecycle for
each email, handles stale lock recovery (>10 minutes by default), and
tracks active email threads to allow thread-level continuity.
"""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from typing import Any, Dict, Generator, List, Optional, Tuple
from utils.config import get_config
from state import ALLOWED_CATEGORIES, ALLOWED_TEAMS


class PersistenceError(Exception):
    """Raised when an attempt to persist a triage record fails (e.g. 0 rows updated)."""
    pass


class HitlStateError(Exception):
    """Raised when an HITL review cannot be resolved because the record is not in 'pending' status."""
    pass


class TriageDatabase:
    """Manages the SQLite database for idempotency, retry tracking, and state persistence."""

    def __init__(self, db_path: Optional[str] = None):
        """Initializes database path and creates schema if not present.

        Args:
            db_path: Path to the SQLite database file. If None, loaded from config.yaml.
        """
        if db_path is None:
            config = get_config()
            db_path = config["system"]["database_path"]

        self.db_path = db_path
        parent = Path(self.db_path).parent
        if str(parent) != "." and not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)

        self._init_db()

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Provides a managed sqlite3 connection with WAL mode and row factory."""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initializes the email_triage table and indices, and migrates schema if needed."""
        with self.get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS email_triage (
                    email_id TEXT PRIMARY KEY,
                    message_id TEXT,
                    thread_id TEXT,
                    sender_email TEXT,
                    status TEXT NOT NULL CHECK(status IN ('processing', 'done', 'failed')),
                    retry_count INTEGER DEFAULT 0,
                    routing_status TEXT,
                    dispatch_target TEXT,
                    error_message TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    masked_subject TEXT,
                    masked_body TEXT,
                    is_active_thread INTEGER,
                    gatekeeper_decision TEXT,
                    gatekeeper_confidence REAL,
                    classifier_used TEXT
                );
                """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_thread_id ON email_triage(thread_id);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_status ON email_triage(status);"
            )

            # Migration for existing databases: add missing columns safely via ALTER TABLE
            cursor = conn.execute("PRAGMA table_info(email_triage);")
            existing_columns = {row["name"] for row in cursor.fetchall()}
            new_columns = [
                ("masked_subject", "TEXT"),
                ("masked_body", "TEXT"),
                ("is_active_thread", "INTEGER"),
                ("gatekeeper_decision", "TEXT"),
                ("gatekeeper_confidence", "REAL"),
                ("classifier_used", "TEXT"),
                # Phase 2 Classification & HITL columns
                ("p2_category", "TEXT"),
                ("p2_priority", "TEXT"),
                ("p2_sentiment", "TEXT"),
                ("p2_customer_emotion", "TEXT"),
                ("p2_summary", "TEXT"),
                ("p2_suggested_team", "TEXT"),
                ("p2_confidence", "REAL"),
                ("p2_classifier_used", "TEXT"),
                ("hitl_status", "TEXT"),
                ("hitl_reason", "TEXT"),
                ("hitl_notes", "TEXT"),
                ("reviewed_by", "TEXT"),
                ("reviewed_at", "TEXT"),
            ]
            for col_name, col_type in new_columns:
                if col_name not in existing_columns:
                    conn.execute(f"ALTER TABLE email_triage ADD COLUMN {col_name} {col_type};")

            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_hitl_status ON email_triage(hitl_status);"
            )

    def get_record(self, email_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a triage record by email_id.

        Args:
            email_id: Unique identifier of the incoming email.

        Returns:
            Dict representing the record, or None if not found.
        """
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM email_triage WHERE email_id = ?", (email_id,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_active_thread_records(
        self, thread_id: str, exclude_email_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieves completed records belonging to a thread.

        Args:
            thread_id: Thread conversation ID.
            exclude_email_id: Optional email_id to exclude (e.g., current message).

        Returns:
            List of completed records for this thread.
        """
        if not thread_id:
            return []

        with self.get_connection() as conn:
            if exclude_email_id:
                cursor = conn.execute(
                    """
                    SELECT * FROM email_triage
                    WHERE thread_id = ? AND email_id != ? AND routing_status = 'gatekeeper_approved'
                    ORDER BY updated_at DESC
                    """,
                    (thread_id, exclude_email_id),
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT * FROM email_triage
                    WHERE thread_id = ? AND routing_status = 'gatekeeper_approved'
                    ORDER BY updated_at DESC
                    """,
                    (thread_id,),
                )
            return [dict(r) for r in cursor.fetchall()]

    def is_active_thread(
        self, thread_id: str, exclude_email_id: Optional[str] = None
    ) -> bool:
        """Checks if a thread already has successfully completed triage records.

        Args:
            thread_id: Thread conversation ID.
            exclude_email_id: Optional email_id to exclude.

        Returns:
            True if previous completed emails exist in this thread, False otherwise.
        """
        records = self.get_active_thread_records(thread_id, exclude_email_id)
        return len(records) > 0

    def is_thread_participant(
        self, thread_id: str, sender_email: str, exclude_email_id: Optional[str] = None
    ) -> bool:
        """Checks if sender_email participated in previous completed records of this thread.

        Prevents thread spoofing / blind trust of thread headers from unknown parties.

        Args:
            thread_id: Thread conversation ID.
            sender_email: Email address of the inbound sender.
            exclude_email_id: Optional email_id to exclude.

        Returns:
            True if sender_email participated in prior completed messages of this thread.
        """
        records = self.get_active_thread_records(thread_id, exclude_email_id)
        sender_clean = (sender_email or "").strip().lower()
        if not sender_clean:
            return False
        for r in records:
            prev_sender = (r.get("sender_email") or "").strip().lower()
            if prev_sender and prev_sender == sender_clean:
                return True
        return False

    def get_gatekeeper_approved(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves emails completed with routing_status='gatekeeper_approved'.

        Phase 2 Note: Downstream dispatchers must pick up verified legitimate emails
        using this query or routing_status='gatekeeper_approved'. The idempotency check
        records these as finished (status='done') so retries do not re-trigger gatekeeping.

        Args:
            limit: Maximum number of records to return.

        Returns:
            List of database records ready for downstream ticket dispatching.
        """
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM email_triage
                WHERE status = 'done' AND routing_status = 'gatekeeper_approved'
                ORDER BY updated_at ASC
                LIMIT ?
                """,
                (limit,),
            )
            return [dict(r) for r in cursor.fetchall()]

    def check_and_acquire(
        self,
        email_id: str,
        thread_id: str = "",
        message_id: str = "",
        sender_email: str = "",
        stale_minutes: int = 10,
        max_retries: int = 3,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Performs idempotency check and attempts to acquire an atomic processing lock.

        Follows atomic database invariants:
        1. Brand new emails are acquired atomically via single-statement
           `INSERT ... ON CONFLICT(email_id) DO NOTHING` checking cursor.rowcount == 1.
        2. Stale locks are recovered atomically via conditional
           `UPDATE ... SET status='processing' WHERE email_id=? AND status='processing' AND updated_at < ? AND retry_count < ?`
           checking cursor.rowcount == 1 so exactly one concurrent worker wins.
        3. Retry-eligible failed emails are claimed atomically via conditional
           `UPDATE ... WHERE email_id=? AND status='failed' AND retry_count < ?`.
        4. Catches lock contention and integrity collisions cleanly, treating lost races as in-flight / duplicate.

        Args:
            email_id: Unique message/email identifier.
            thread_id: Thread conversation ID.
            message_id: Original message ID from headers.
            sender_email: Sender's email address.
            stale_minutes: Number of minutes before an in-progress record is considered stale.
            max_retries: Maximum allowable retry attempts before permanent failure.

        Returns:
            Tuple of:
            - allowed (bool): True if processing should proceed; False if it should be skipped.
            - outcome (str): Outcome description:
                * 'acquired_new': Fresh email successfully locked.
                * 'recovered_stale': Stale processing lock recovered.
                * 'retry_failed': Retry attempt granted for a previously failed email.
                * 'already_completed': Email already completed ('done').
                * 'in_flight': Currently locked and active under another worker.
                * 'max_retries_exceeded': Retry limit reached for stale/failed email.
            - record (Dict[str, Any]): Record snapshot.
        """
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        stale_cutoff = now - timedelta(minutes=stale_minutes)
        stale_cutoff_iso = stale_cutoff.isoformat()

        try:
            with self.get_connection() as conn:
                # 1. Atomic insertion for new email: single statement with ON CONFLICT DO NOTHING
                cursor = conn.execute(
                    """
                    INSERT INTO email_triage (
                        email_id, message_id, thread_id, sender_email,
                        status, retry_count, routing_status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'processing', 0, 'processing', ?, ?)
                    ON CONFLICT(email_id) DO NOTHING
                    """,
                    (email_id, message_id, thread_id, sender_email, now_iso, now_iso),
                )
                if cursor.rowcount == 1:
                    record = {
                        "email_id": email_id,
                        "message_id": message_id,
                        "thread_id": thread_id,
                        "sender_email": sender_email,
                        "status": "processing",
                        "retry_count": 0,
                        "routing_status": "processing",
                        "dispatch_target": None,
                        "error_message": None,
                        "created_at": now_iso,
                        "updated_at": now_iso,
                    }
                    return True, "acquired_new", record

                # 2. Row already exists: inspect current record state
                cursor = conn.execute(
                    "SELECT * FROM email_triage WHERE email_id = ?", (email_id,)
                )
                row = cursor.fetchone()
                if not row:
                    return False, "in_flight", {"email_id": email_id, "status": "processing"}

                record = dict(row)
                current_status = record.get("status")
                retry_count = int(record.get("retry_count") or 0)

                # Case 2: Already completed
                if current_status == "done":
                    return False, "already_completed", record

                # Parse updated_at timestamp to evaluate staleness
                updated_str = record.get("updated_at")
                try:
                    updated_at = datetime.fromisoformat(updated_str)
                    if updated_at.tzinfo is None:
                        updated_at = updated_at.replace(tzinfo=timezone.utc)
                except Exception:
                    updated_at = now

                elapsed_minutes = (now - updated_at).total_seconds() / 60.0

                # Case 3: In-flight processing
                if current_status == "processing":
                    if elapsed_minutes > stale_minutes:
                        # Lock is stale: attempt recovery if under max_retries
                        if retry_count < max_retries:
                            update_cur = conn.execute(
                                """
                                UPDATE email_triage
                                SET status = 'processing', retry_count = retry_count + 1, updated_at = ?, routing_status = 'stale_recovery'
                                WHERE email_id = ? AND status = 'processing' AND updated_at < ? AND retry_count < ?
                                """,
                                (now_iso, email_id, stale_cutoff_iso, max_retries),
                            )
                            if update_cur.rowcount == 1:
                                # Won recovery race
                                cur = conn.execute(
                                    "SELECT * FROM email_triage WHERE email_id = ?", (email_id,)
                                )
                                r = cur.fetchone()
                                if r:
                                    record = dict(r)
                                else:
                                    record["status"] = "processing"
                                    record["retry_count"] = retry_count + 1
                                    record["routing_status"] = "stale_recovery"
                                    record["updated_at"] = now_iso
                                return True, "recovered_stale", record
                            else:
                                # Lost race to another concurrent worker
                                cur = conn.execute(
                                    "SELECT * FROM email_triage WHERE email_id = ?", (email_id,)
                                )
                                r = cur.fetchone()
                                if r:
                                    record = dict(r)
                                if record.get("status") == "done":
                                    return False, "already_completed", record
                                elif record.get("status") == "failed":
                                    return False, "max_retries_exceeded", record
                                else:
                                    return False, "in_flight", record
                        else:
                            # Max retries exceeded on stale lock
                            conn.execute(
                                """
                                UPDATE email_triage
                                SET status = 'failed', error_message = 'Max retries exceeded on stale lock recovery', updated_at = ?
                                WHERE email_id = ? AND status = 'processing'
                                """,
                                (now_iso, email_id),
                            )
                            cur = conn.execute(
                                "SELECT * FROM email_triage WHERE email_id = ?", (email_id,)
                            )
                            r = cur.fetchone()
                            if r:
                                record = dict(r)
                            else:
                                record["status"] = "failed"
                                record["error_message"] = "Max retries exceeded on stale lock recovery"
                                record["updated_at"] = now_iso
                            return False, "max_retries_exceeded", record
                    else:
                        # In-flight and active within stale window
                        return False, "in_flight", record

                # Case 4: Previously failed
                if current_status == "failed":
                    if retry_count < max_retries:
                        update_cur = conn.execute(
                            """
                            UPDATE email_triage
                            SET status = 'processing', retry_count = retry_count + 1, updated_at = ?, routing_status = 'retry'
                            WHERE email_id = ? AND status = 'failed' AND retry_count < ?
                            """,
                            (now_iso, email_id, max_retries),
                        )
                        if update_cur.rowcount == 1:
                            cur = conn.execute(
                                "SELECT * FROM email_triage WHERE email_id = ?", (email_id,)
                            )
                            r = cur.fetchone()
                            if r:
                                record = dict(r)
                            else:
                                record["status"] = "processing"
                                record["retry_count"] = retry_count + 1
                                record["routing_status"] = "retry"
                                record["updated_at"] = now_iso
                            return True, "retry_failed", record
                        else:
                            # Lost race
                            cur = conn.execute(
                                "SELECT * FROM email_triage WHERE email_id = ?", (email_id,)
                            )
                            r = cur.fetchone()
                            if r:
                                record = dict(r)
                            if record.get("status") == "done":
                                return False, "already_completed", record
                            elif record.get("status") == "processing":
                                return False, "in_flight", record
                            else:
                                return False, "max_retries_exceeded", record
                    else:
                        return False, "max_retries_exceeded", record

                return False, "unknown_status", record

        except (sqlite3.OperationalError, sqlite3.IntegrityError):
            # Treat concurrency collisions or lock contention as a lost race
            try:
                record = self.get_record(email_id)
                if record:
                    if record.get("status") == "done":
                        return False, "already_completed", record
                    return False, "in_flight", record
            except Exception:
                pass
            return False, "in_flight", {"email_id": email_id, "status": "processing"}

    def mark_processing(self, email_id: str, retry_count: Optional[int] = None) -> None:
        """Sets status to processing and refreshes updated_at."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            if retry_count is not None:
                conn.execute(
                    """
                    UPDATE email_triage
                    SET status = 'processing', retry_count = ?, updated_at = ?
                    WHERE email_id = ?
                    """,
                    (retry_count, now_iso, email_id),
                )
            else:
                conn.execute(
                    """
                    UPDATE email_triage
                    SET status = 'processing', updated_at = ?
                    WHERE email_id = ?
                    """,
                    (now_iso, email_id),
                )

    def mark_done(
        self,
        email_id: str,
        routing_status: str = "routed",
        dispatch_target: Optional[str] = None,
        masked_subject: Optional[str] = None,
        masked_body: Optional[str] = None,
        is_active_thread: Optional[bool] = None,
        gatekeeper_decision: Optional[str] = None,
        gatekeeper_confidence: Optional[float] = None,
        classifier_used: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Sets status to done and updates routing status, target, and triage metadata in ONE statement.

        Raises:
            PersistenceError: If 0 rows are updated (e.g. email_id does not exist).
        """
        now_iso = datetime.now(timezone.utc).isoformat()

        # Check persist_masked_text configuration
        persist_text = True
        if config is not None:
            persist_text = config.get("system", {}).get("persist_masked_text", True)
        else:
            cfg = get_config()
            persist_text = cfg.get("system", {}).get("persist_masked_text", True)

        # Rule: masked_subject and masked_body persisted ONLY for gatekeeper_approved and manual_review
        if routing_status not in ("gatekeeper_approved", "manual_review") or not persist_text:
            masked_subject = None
            masked_body = None

        active_thread_int = None
        if is_active_thread is not None:
            active_thread_int = 1 if is_active_thread else 0

        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE email_triage
                SET status = 'done',
                    routing_status = ?,
                    dispatch_target = ?,
                    updated_at = ?,
                    masked_subject = ?,
                    masked_body = ?,
                    is_active_thread = ?,
                    gatekeeper_decision = ?,
                    gatekeeper_confidence = ?,
                    classifier_used = ?
                WHERE email_id = ?
                """,
                (
                    routing_status,
                    dispatch_target,
                    now_iso,
                    masked_subject,
                    masked_body,
                    active_thread_int,
                    gatekeeper_decision,
                    gatekeeper_confidence,
                    classifier_used,
                    email_id,
                ),
            )
            if cursor.rowcount == 0:
                raise PersistenceError(f"Email '{email_id}' not found to mark done")

    def mark_failed(
        self,
        email_id: str,
        error_message: str = "",
        routing_status: str = "failed",
    ) -> None:
        """Sets status to failed and logs error message."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            conn.execute(
                """
                UPDATE email_triage
                SET status = 'failed', error_message = ?, routing_status = ?, updated_at = ?
                WHERE email_id = ?
                """,
                (error_message, routing_status, now_iso, email_id),
            )

    def record_phase2_classification(
        self,
        email_id: str,
        classification: Optional[Any],
        p2_classifier_used: Optional[str] = None,
        hitl_status: str = "none",
        hitl_reason: Optional[str] = None,
    ) -> bool:
        """Persists Phase 2 deep classification and HITL review gating state into SQLite.

        Args:
            email_id: Unique message identifier.
            classification: EmailClassification object or dictionary or None.
            p2_classifier_used: Engine identifier ('jev', 'groq', 'offline_heuristic', 'fail_closed').
            hitl_status: Gating status ('none', 'pending', 'auto_approved', 'approved', 'rejected').
            hitl_reason: Specific explanation if diverted to HITL review.

        Returns:
            True on successful persistence, or False if email was already resolved by a human.

        Raises:
            PersistenceError: If email_id is not found in database or Phase 1 routing_status is not 'gatekeeper_approved'.
        """
        now_iso = datetime.now(timezone.utc).isoformat()

        cat = None
        prio = None
        sent = None
        emotion = None
        summary = None
        team = None
        conf = None

        if classification is not None:
            if hasattr(classification, "category"):
                cat = classification.category
                prio = classification.priority
                sent = classification.sentiment
                emotion = getattr(classification, "customer_emotion", "Calm")
                summary = classification.summary
                team = classification.suggested_team
                conf = classification.confidence
            elif isinstance(classification, dict):
                cat = classification.get("category")
                prio = classification.get("priority")
                sent = classification.get("sentiment")
                emotion = classification.get("customer_emotion", "Calm")
                summary = classification.get("summary")
                team = classification.get("suggested_team")
                conf = classification.get("confidence")

        with self.get_connection() as conn:
            cur = conn.execute(
                "SELECT routing_status, hitl_status FROM email_triage WHERE email_id = ?",
                (email_id,),
            )
            row = cur.fetchone()
            if row is None:
                raise PersistenceError(
                    f"Email '{email_id}' not found for Phase 2 classification update"
                )

            # Rule 5: Phase 1 routing_status must be 'gatekeeper_approved'
            if row["routing_status"] != "gatekeeper_approved":
                raise PersistenceError(
                    f"Email '{email_id}' has Phase 1 routing_status='{row['routing_status']}', "
                    f"expected 'gatekeeper_approved'"
                )

            # Rule 5: If hitl_status is already approved or rejected (a human decided), change nothing and return False
            current_hitl = row["hitl_status"]
            if current_hitl in ("approved", "rejected"):
                return False

            query = """
                UPDATE email_triage
                SET p2_category = ?,
                    p2_priority = ?,
                    p2_sentiment = ?,
                    p2_customer_emotion = ?,
                    p2_summary = ?,
                    p2_suggested_team = ?,
                    p2_confidence = ?,
                    p2_classifier_used = ?,
                    hitl_status = ?,
                    hitl_reason = ?,
                    updated_at = ?
                WHERE email_id = ?
            """
            params = (
                cat,
                prio,
                sent,
                emotion,
                summary,
                team,
                conf,
                p2_classifier_used,
                hitl_status,
                hitl_reason,
                now_iso,
                email_id,
            )
            cursor = conn.execute(query, params)
            if cursor.rowcount == 0:
                raise PersistenceError(
                    f"Email '{email_id}' not found for Phase 2 classification update"
                )
        return True

    def get_pending_hitl_reviews(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves emails currently awaiting Human-in-the-Loop review.

        WHERE hitl_status = 'pending' only, ORDER BY created_at ASC (oldest first),
        and selects explicit columns WITHOUT sender_email.

        Args:
            limit: Maximum number of pending records to return (default: 100).

        Returns:
            List of row dictionaries for pending reviews without sender_email.
        """
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT
                    email_id,
                    message_id,
                    thread_id,
                    status,
                    retry_count,
                    routing_status,
                    dispatch_target,
                    created_at,
                    updated_at,
                    masked_subject,
                    masked_body,
                    is_active_thread,
                    gatekeeper_decision,
                    gatekeeper_confidence,
                    classifier_used,
                    p2_category,
                    p2_priority,
                    p2_sentiment,
                    p2_customer_emotion,
                    p2_summary,
                    p2_suggested_team,
                    p2_confidence,
                    p2_classifier_used,
                    hitl_status,
                    hitl_reason,
                    hitl_notes,
                    reviewed_by,
                    reviewed_at
                FROM email_triage
                WHERE hitl_status = 'pending'
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def resolve_hitl_review(
        self,
        email_id: str,
        decision: str,
        reviewed_by: str,
        notes: str = "",
        override_category: Optional[str] = None,
        override_team: Optional[str] = None,
    ) -> bool:
        """Resolves a pending HITL review record (approve or reject with optional overrides).

        Args:
            email_id: Email identifier being reviewed.
            decision: 'approved' or 'rejected'.
            reviewed_by: Identifier/username of reviewer (non-empty, max 64 chars).
            notes: Operator review notes or reasoning (max 1000 chars, control chars removed).
                   Required for rejection.
            override_category: Optional category override in ALLOWED_CATEGORIES.
            override_team: Optional team override in ALLOWED_TEAMS.

        Returns:
            True if review record was successfully resolved.

        Raises:
            ValueError: If inputs fail validation.
            PersistenceError: If email_id was not found.
            HitlStateError: If email is not in 'pending' status.
        """
        clean_decision = str(decision).strip().lower()
        if clean_decision not in ("approved", "rejected"):
            raise ValueError(f"Invalid decision '{decision}'. Must be 'approved' or 'rejected'.")

        reviewed_by_clean = (reviewed_by or "").strip()
        if not reviewed_by_clean:
            raise ValueError("reviewed_by must be a non-empty string")
        if len(reviewed_by_clean) > 64:
            raise ValueError("reviewed_by must be at most 64 characters")

        if override_category is not None and override_category not in ALLOWED_CATEGORIES:
            raise ValueError(
                f"Invalid override_category '{override_category}'. Must be one of {ALLOWED_CATEGORIES}"
            )

        if override_team is not None and override_team not in ALLOWED_TEAMS:
            raise ValueError(
                f"Invalid override_team '{override_team}'. Must be one of {ALLOWED_TEAMS}"
            )

        # Control characters removed (keep standard whitespace: \n, \t, \r)
        clean_notes = "".join(
            ch for ch in (notes or "") if (ch >= " " and ch != "\x7f") or ch in "\n\t\r"
        )
        if len(clean_notes) > 1000:
            raise ValueError("notes must be at most 1000 characters")

        if clean_decision == "rejected" and not clean_notes.strip():
            raise ValueError("Rejection requires non-empty notes")

        now_iso = datetime.now(timezone.utc).isoformat()

        with self.get_connection() as conn:
            if clean_decision == "approved":
                cursor = conn.execute(
                    """
                    UPDATE email_triage
                    SET hitl_status = 'approved',
                        hitl_notes = ?,
                        reviewed_by = ?,
                        reviewed_at = ?,
                        p2_category = COALESCE(?, p2_category),
                        p2_suggested_team = COALESCE(?, p2_suggested_team),
                        updated_at = ?
                    WHERE email_id = ? AND hitl_status = 'pending'
                    """,
                    (
                        clean_notes,
                        reviewed_by_clean,
                        now_iso,
                        override_category,
                        override_team,
                        now_iso,
                        email_id,
                    ),
                )
            else:  # rejected
                cursor = conn.execute(
                    """
                    UPDATE email_triage
                    SET hitl_status = 'rejected',
                        hitl_notes = ?,
                        reviewed_by = ?,
                        reviewed_at = ?,
                        updated_at = ?
                    WHERE email_id = ? AND hitl_status = 'pending'
                    """,
                    (
                        clean_notes,
                        reviewed_by_clean,
                        now_iso,
                        now_iso,
                        email_id,
                    ),
                )

            if cursor.rowcount == 0:
                cur = conn.execute(
                    "SELECT hitl_status FROM email_triage WHERE email_id = ?",
                    (email_id,),
                )
                row = cur.fetchone()
                if row is None:
                    raise PersistenceError(f"Email '{email_id}' not found")
                current_status = row["hitl_status"]
                raise HitlStateError(
                    f"Email '{email_id}' is not in 'pending' status (current status: '{current_status}')"
                )

        return True

    def clear_all(self) -> None:
        """Clears all records in the email_triage table (used for testing)."""
        with self.get_connection() as conn:
            conn.execute("DELETE FROM email_triage;")
