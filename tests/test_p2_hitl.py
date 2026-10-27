"""Unit tests for [P2-02] Human-in-the-Loop (HITL) Review Queue and Gating."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from typing import List
from unittest.mock import MagicMock
import pytest
import yaml

from db.database import HitlStateError, PersistenceError, TriageDatabase
from nodes.hitl_queue import hitl_queue_node, should_route_after_hitl
from state import ALLOWED_CATEGORIES, ALLOWED_TEAMS, EmailClassification, TriageState
from utils.config import ConfigError, load_config


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db") as f:
        db = TriageDatabase(db_path=f.name)
        yield db


# ---------------------------------------------------------------------------
# 1. Gating & Policy Rules in hitl_queue_node
# ---------------------------------------------------------------------------


def test_hitl_confidence_boundary_below_threshold():
    """Confidence 0.84 is below default 0.85 threshold -> routes to pending."""
    classification = EmailClassification(
        category="General Query",
        priority="Medium",
        sentiment="Neutral",
        customer_emotion="Calm",
        summary="User asking for docs",
        suggested_team="Support",
        confidence=0.84,
    )
    state: TriageState = {
        "email_id": "test-th-01",
        "classification": classification,
        "routing_status": "gatekeeper_approved",
    }
    res = hitl_queue_node(state)
    assert res["hitl_status"] == "pending"
    assert res["p2_status"] == "hitl_pending"
    assert "routing_status" not in res
    assert "dispatch_target" not in res
    assert "below threshold" in res["hitl_reason"]
    assert should_route_after_hitl(res) == "end"


def test_hitl_confidence_boundary_at_or_above_threshold():
    """Confidence 0.85 with Calm/Medium inquiry -> machine auto-approves."""
    classification = EmailClassification(
        category="General Query",
        priority="Medium",
        sentiment="Neutral",
        customer_emotion="Calm",
        summary="User asking for docs",
        suggested_team="Support",
        confidence=0.85,
    )
    state: TriageState = {
        "email_id": "test-th-02",
        "classification": classification,
        "routing_status": "gatekeeper_approved",
    }
    res = hitl_queue_node(state)
    assert res["hitl_status"] == "auto_approved"
    assert res["p2_status"] == "auto_approved"
    assert res["hitl_reason"] is None
    assert should_route_after_hitl(res) == "continue"


def test_hitl_security_account_at_confidence_099_and_calm_goes_to_pending():
    """Security/Account at confidence 0.99 and Calm goes to pending via always_review_categories."""
    classification = EmailClassification(
        category="Security/Account",
        priority="High",
        sentiment="Neutral",
        customer_emotion="Calm",
        summary="Password reset link not working",
        suggested_team="Security",
        confidence=0.99,
    )
    state: TriageState = {
        "email_id": "test-sec-01",
        "classification": classification,
        "routing_status": "gatekeeper_approved",
    }
    res = hitl_queue_node(state)
    assert res["hitl_status"] == "pending"
    assert res["p2_status"] == "hitl_pending"
    assert "requires mandatory human review" in res["hitl_reason"]
    assert should_route_after_hitl(res) == "end"


def test_hitl_classifier_injection_result_goes_to_pending():
    """Adversarial prompt injection result from classifier goes to pending through hitl_queue_node."""
    classification = EmailClassification(
        category="Security/Account",
        priority="Critical",
        sentiment="Negative",
        customer_emotion="Angry",
        summary="Adversarial prompt injection pattern detected in message",
        suggested_team="Security",
        confidence=1.00,
    )
    state: TriageState = {
        "email_id": "test-inj-01",
        "classification": classification,
        "p2_classifier_used": "regex_filter",
        "routing_status": "gatekeeper_approved",
    }
    res = hitl_queue_node(state)
    assert res["hitl_status"] == "pending"
    assert res["p2_status"] == "hitl_pending"
    assert "Prompt injection pre-filter flagged" in res["hitl_reason"]
    assert should_route_after_hitl(res) == "end"


def test_hitl_escalation_rule_frustrated_and_high_priority():
    """Customer emotion Frustrated with High priority -> diverted to pending even with 0.98 confidence."""
    classification = EmailClassification(
        category="Billing Issue",
        priority="High",
        sentiment="Negative",
        customer_emotion="Frustrated",
        summary="Charged twice on monthly invoice",
        suggested_team="Billing",
        confidence=0.98,
    )
    state: TriageState = {
        "email_id": "test-esc-01",
        "classification": classification,
        "routing_status": "gatekeeper_approved",
    }
    res = hitl_queue_node(state)
    assert res["hitl_status"] == "pending"
    assert res["p2_status"] == "hitl_pending"
    assert "Escalated customer emotion (Frustrated) with High priority" in res["hitl_reason"]
    assert should_route_after_hitl(res) == "end"


def test_hitl_escalation_rule_angry_and_critical_priority():
    """Customer emotion Angry with Critical priority -> diverted to pending even with 0.99 confidence."""
    classification = EmailClassification(
        category="Complaint",
        priority="Critical",
        sentiment="Negative",
        customer_emotion="Angry",
        summary="Complete service outage and angry executive",
        suggested_team="Support",
        confidence=0.99,
    )
    state: TriageState = {
        "email_id": "test-esc-02",
        "classification": classification,
        "routing_status": "gatekeeper_approved",
    }
    res = hitl_queue_node(state)
    assert res["hitl_status"] == "pending"
    assert res["p2_status"] == "hitl_pending"
    assert "Escalated customer emotion (Angry) with Critical priority" in res["hitl_reason"]
    assert should_route_after_hitl(res) == "end"


def test_hitl_calm_high_priority_auto_approved():
    """Calm customer with High priority bug report -> automated dispatch auto_approved."""
    classification = EmailClassification(
        category="Bug Report",
        priority="High",
        sentiment="Neutral",
        customer_emotion="Calm",
        summary="500 internal server error on checkout",
        suggested_team="Engineering",
        confidence=0.92,
    )
    state: TriageState = {
        "email_id": "test-calm-01",
        "classification": classification,
        "routing_status": "gatekeeper_approved",
    }
    res = hitl_queue_node(state)
    assert res["hitl_status"] == "auto_approved"
    assert res["p2_status"] == "auto_approved"
    assert res["hitl_reason"] is None
    assert should_route_after_hitl(res) == "continue"


def test_hitl_category_other_diverts():
    """Category 'Other' -> diverted to pending regardless of confidence."""
    classification = EmailClassification(
        category="Other",
        priority="Low",
        sentiment="Neutral",
        customer_emotion="Calm",
        summary="Unclear message",
        suggested_team="Support",
        confidence=0.95,
    )
    state: TriageState = {
        "email_id": "test-other-01",
        "classification": classification,
        "routing_status": "gatekeeper_approved",
    }
    res = hitl_queue_node(state)
    assert res["hitl_status"] == "pending"
    assert res["p2_status"] == "hitl_pending"
    assert "Unclassified category (Other)" in res["hitl_reason"]
    assert should_route_after_hitl(res) == "end"


def test_hitl_missing_classification_fails_closed():
    """Missing/None classification -> fails closed to pending."""
    state: TriageState = {
        "email_id": "test-missing-01",
        "classification": None,
        "routing_status": "gatekeeper_approved",
    }
    res = hitl_queue_node(state)
    assert res["hitl_status"] == "pending"
    assert res["p2_status"] == "hitl_pending"
    assert "Missing or malformed classification" in res["hitl_reason"]
    assert should_route_after_hitl(res) == "end"


# ---------------------------------------------------------------------------
# 2. Database & Phase 1 Isolation Invariants
# ---------------------------------------------------------------------------


def test_phase1_routing_status_isolation_after_auto_and_human_review(temp_db):
    """Phase 1 routing_status is still 'gatekeeper_approved' after auto, human-approve, and human-reject."""
    # 1. Setup Phase 1 approved email
    temp_db.check_and_acquire("email-iso-01", "th-iso-1", "<msg01@ex.com>", "customer1@ex.com")
    temp_db.mark_done(
        email_id="email-iso-01",
        routing_status="gatekeeper_approved",
        dispatch_target="None",
    )

    # 2. Auto-approved email: record Phase 2 classification
    temp_db.record_phase2_classification(
        email_id="email-iso-01",
        classification={
            "category": "Bug Report",
            "priority": "Medium",
            "sentiment": "Neutral",
            "customer_emotion": "Calm",
            "summary": "Minor UI bug",
            "suggested_team": "Engineering",
            "confidence": 0.95,
        },
        hitl_status="auto_approved",
    )
    r1 = temp_db.get_record("email-iso-01")
    assert r1["routing_status"] == "gatekeeper_approved"
    assert r1["hitl_status"] == "auto_approved"

    # 3. Pending email that human approves
    temp_db.check_and_acquire("email-iso-02", "th-iso-2", "<msg02@ex.com>", "customer2@ex.com")
    temp_db.mark_done(
        email_id="email-iso-02",
        routing_status="gatekeeper_approved",
        dispatch_target="None",
    )
    temp_db.record_phase2_classification(
        email_id="email-iso-02",
        classification={"category": "Security/Account", "confidence": 0.99},
        hitl_status="pending",
        hitl_reason="Mandatory review",
    )
    temp_db.resolve_hitl_review(
        email_id="email-iso-02",
        decision="approved",
        reviewed_by="security_officer",
        notes="Legitimate account unlock request",
        override_category="Security/Account",
        override_team="Security",
    )
    r2 = temp_db.get_record("email-iso-02")
    assert r2["routing_status"] == "gatekeeper_approved"
    assert r2["hitl_status"] == "approved"
    assert r2["reviewed_by"] == "security_officer"

    # 4. Pending email that human rejects
    temp_db.check_and_acquire("email-iso-03", "th-iso-3", "<msg03@ex.com>", "customer3@ex.com")
    temp_db.mark_done(
        email_id="email-iso-03",
        routing_status="gatekeeper_approved",
        dispatch_target="None",
    )
    temp_db.record_phase2_classification(
        email_id="email-iso-03",
        classification={"category": "Other", "confidence": 0.20},
        hitl_status="pending",
        hitl_reason="Unclear text",
    )
    temp_db.resolve_hitl_review(
        email_id="email-iso-03",
        decision="rejected",
        reviewed_by="support_lead",
        notes="Malformed spam payload that evaded classifier",
    )
    r3 = temp_db.get_record("email-iso-03")
    assert r3["routing_status"] == "gatekeeper_approved"
    assert r3["hitl_status"] == "rejected"
    assert r3["reviewed_by"] == "support_lead"


def test_a5_active_thread_continuity_preserved_after_hitl_review(temp_db):
    """A5 thread detection still works after review (a reply in thread of a reviewed email is active)."""
    # Parent email in thread
    temp_db.check_and_acquire("email-parent", "thread-1234", "<parent@ex.com>", "user@ex.com")
    temp_db.mark_done(
        email_id="email-parent",
        routing_status="gatekeeper_approved",
    )
    temp_db.record_phase2_classification(
        email_id="email-parent",
        classification={"category": "Billing Issue", "confidence": 0.70},
        hitl_status="pending",
    )
    temp_db.resolve_hitl_review(
        email_id="email-parent",
        decision="approved",
        reviewed_by="reviewer1",
        notes="Approved billing question",
    )

    # Active thread check for subsequent email in thread
    records = temp_db.get_active_thread_records("thread-1234")
    assert len(records) == 1
    assert records[0]["email_id"] == "email-parent"
    assert records[0]["routing_status"] == "gatekeeper_approved"


def test_get_pending_hitl_reviews_omits_sender_email(temp_db):
    """get_pending_hitl_reviews selects explicit columns WITHOUT sender_email, sorted oldest first."""
    temp_db.check_and_acquire("em-p1", "th-1", "<m1@ex.com>", "secret_sender1@example.com")
    temp_db.mark_done(email_id="em-p1", routing_status="gatekeeper_approved")
    temp_db.record_phase2_classification(
        email_id="em-p1",
        classification={"category": "General Query", "confidence": 0.40},
        hitl_status="pending",
        hitl_reason="Low conf",
    )

    pending = temp_db.get_pending_hitl_reviews()
    assert len(pending) == 1
    row = pending[0]
    assert row["email_id"] == "em-p1"
    assert "sender_email" not in row
    assert "p2_category" in row
    assert "hitl_status" in row


def test_resolve_hitl_review_state_machine_and_status_checks(temp_db):
    """Resolving non-pending, missing, spam, and already-resolved email fails with right exception."""
    # 1. Missing email
    with pytest.raises(PersistenceError, match="not found"):
        temp_db.resolve_hitl_review("non-existent-email", "approved", "admin", "notes")

    # 2. Email present but hitl_status is 'none'
    temp_db.check_and_acquire("em-none", "th-n", "<mn@ex.com>", "u@ex.com")
    temp_db.mark_done("em-none", routing_status="gatekeeper_approved")
    with pytest.raises(HitlStateError, match="not in 'pending' status"):
        temp_db.resolve_hitl_review("em-none", "approved", "admin", "notes")

    # 3. Spam email (routing_status != 'gatekeeper_approved')
    temp_db.check_and_acquire("em-spam", "th-s", "<ms@ex.com>", "spam@ex.com")
    temp_db.mark_done("em-spam", routing_status="spam_diverted")
    with pytest.raises(PersistenceError, match="expected 'gatekeeper_approved'"):
        temp_db.record_phase2_classification("em-spam", None, hitl_status="pending")

    # 4. Already resolved email
    temp_db.check_and_acquire("em-resolved", "th-r", "<mr@ex.com>", "u@ex.com")
    temp_db.mark_done("em-resolved", routing_status="gatekeeper_approved")
    temp_db.record_phase2_classification(
        "em-resolved",
        {"category": "Other", "confidence": 0.5},
        hitl_status="pending",
    )
    # First resolution succeeds
    temp_db.resolve_hitl_review("em-resolved", "approved", "admin", "approved ok")
    # Second resolution fails with HitlStateError
    with pytest.raises(HitlStateError, match="not in 'pending' status"):
        temp_db.resolve_hitl_review("em-resolved", "approved", "admin2", "second approve")


def test_resolve_hitl_review_validation_errors(temp_db):
    """Invalid overrides, empty reviewer, missing reject notes, and oversize notes raise ValueError."""
    temp_db.check_and_acquire("em-val", "th-v", "<mv@ex.com>", "u@ex.com")
    temp_db.mark_done("em-val", routing_status="gatekeeper_approved")
    temp_db.record_phase2_classification(
        "em-val",
        {"category": "Other", "confidence": 0.5},
        hitl_status="pending",
    )

    # Empty reviewer
    with pytest.raises(ValueError, match="reviewed_by must be a non-empty string"):
        temp_db.resolve_hitl_review("em-val", "approved", "   ", "notes")

    # Reviewer > 64 chars
    with pytest.raises(ValueError, match="at most 64 characters"):
        temp_db.resolve_hitl_review("em-val", "approved", "a" * 65, "notes")

    # Invalid override_category
    with pytest.raises(ValueError, match="Invalid override_category"):
        temp_db.resolve_hitl_review("em-val", "approved", "admin", "notes", override_category="BogusCategory")

    # Invalid override_team
    with pytest.raises(ValueError, match="Invalid override_team"):
        temp_db.resolve_hitl_review("em-val", "approved", "admin", "notes", override_team="SecretOps")

    # Notes > 1000 chars
    with pytest.raises(ValueError, match="at most 1000 characters"):
        temp_db.resolve_hitl_review("em-val", "approved", "admin", "x" * 1001)

    # Rejection requires non-empty notes
    with pytest.raises(ValueError, match="Rejection requires non-empty notes"):
        temp_db.resolve_hitl_review("em-val", "rejected", "admin", "   ")

    # Verify that failed validations made zero changes (still pending)
    record = temp_db.get_record("em-val")
    assert record["hitl_status"] == "pending"


def test_hitl_review_concurrent_race_8_threads(temp_db):
    """An 8-thread race on one pending email has exactly one winner and seven HitlStateError."""
    temp_db.check_and_acquire("em-race", "th-race", "<m-race@ex.com>", "user@ex.com")
    temp_db.mark_done("em-race", routing_status="gatekeeper_approved")
    temp_db.record_phase2_classification(
        "em-race",
        {"category": "Other", "confidence": 0.5},
        hitl_status="pending",
    )

    barrier = threading.Barrier(8)
    results = []
    errors = []

    def worker(worker_id: int):
        try:
            barrier.wait()
            res = temp_db.resolve_hitl_review(
                email_id="em-race",
                decision="approved",
                reviewed_by=f"reviewer_{worker_id}",
                notes=f"Approved by reviewer {worker_id}",
            )
            results.append((worker_id, res))
        except Exception as e:
            errors.append((worker_id, e))

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(worker, i) for i in range(8)]
        for f in futures:
            f.result()

    assert len(results) == 1
    assert len(errors) == 7
    for _, err in errors:
        assert isinstance(err, HitlStateError)
        assert "not in 'pending' status" in str(err)


def test_rerunning_phase2_cannot_undo_human_decision(temp_db):
    """Re-running Phase 2 cannot undo a human decision (record_phase2_classification returns False)."""
    temp_db.check_and_acquire("em-undo", "th-u", "<mu@ex.com>", "user@ex.com")
    temp_db.mark_done("em-undo", routing_status="gatekeeper_approved")
    temp_db.record_phase2_classification(
        "em-undo",
        {"category": "Other", "confidence": 0.5},
        hitl_status="pending",
    )
    temp_db.resolve_hitl_review(
        "em-undo",
        "approved",
        "human_admin",
        "Human confirmed category",
        override_category="Bug Report",
        override_team="Engineering",
    )

    # Machine classifier runs again later
    changed = temp_db.record_phase2_classification(
        "em-undo",
        {"category": "General Query", "confidence": 0.99},
        hitl_status="auto_approved",
    )
    assert changed is False

    # Verify human decision was preserved intact
    record = temp_db.get_record("em-undo")
    assert record["hitl_status"] == "approved"
    assert record["p2_category"] == "Bug Report"
    assert record["p2_suggested_team"] == "Engineering"
    assert record["reviewed_by"] == "human_admin"


def test_hitl_database_persistence_failure_b4_safeguard():
    """If DB persistence throws an error, hitl_queue_node safely fails closed with persist_failed."""
    mock_db = MagicMock()
    mock_db.record_phase2_classification.side_effect = PersistenceError("DB locked")

    classification = EmailClassification(
        category="Bug Report",
        priority="Low",
        sentiment="Neutral",
        customer_emotion="Calm",
        summary="Minor typo",
        suggested_team="Engineering",
        confidence=0.95,
    )
    state: TriageState = {
        "email_id": "test-db-fail",
        "classification": classification,
    }
    res = hitl_queue_node(state, db=mock_db)
    assert res["hitl_status"] == "none"
    assert res["p2_status"] == "persist_failed"
    assert res["dispatch_status"] == "failed"
    assert should_route_after_hitl(res) == "end"


# ---------------------------------------------------------------------------
# 3. Configuration Validation Tests
# ---------------------------------------------------------------------------


def _valid_base_config():
    return {
        "system": {
            "database_path": "triage.db",
            "idempotency_stale_minutes": 10,
            "max_dispatch_retries": 3,
            "audit_log_enabled": True,
            "persist_masked_text": True,
        },
        "privacy": {
            "spacy_model": "en_core_web_sm",
            "tech_terms_file": "config/tech_terms.txt",
            "default_phone_region": "US",
            "tech_context_words": ["pipeline", "job"],
            "sensitive_keywords": ["subpoena"],
            "max_code_density": 4,
        },
        "security": {
            "regex_scan_head": 10000,
            "regex_scan_tail": 2000,
        },
        "gatekeeper": {
            "timeout_seconds": 5.0,
            "max_retries": 2,
            "api_key_env": "JEV_API_KEY",
            "fallback_model": "openai/gpt-oss-20b",
            "groq_api_key_env": "GROQ_API_KEY",
            "jev": {
                "model": "jev-1.13.0",
                "api_url": "https://api.typesafe.ai/v1/systemone",
                "hi_threshold": 0.85,
                "lo_threshold": 0.15,
                "max_body_chars": 20000,
            },
        },
        "llm": {
            "model": "openai/gpt-oss-120b",
            "temperature": 0.1,
            "confidence_threshold": 0.70,
            "groq_api_key_env": "GROQ_API_KEY",
        },
    }


def test_config_validation_bad_hitl_threshold(tmp_path):
    """Bad hitl_threshold (<= 0 or > 1 or string) makes load_config raise ConfigError."""
    base_cfg = _valid_base_config()
    base_cfg["classification"] = {"hitl_threshold": 1.5}

    bad_file = tmp_path / "bad_config.yaml"
    bad_file.write_text(yaml.dump(base_cfg))

    with pytest.raises(ConfigError, match="'classification.hitl_threshold' must satisfy 0 < value <= 1"):
        load_config(str(bad_file))


def test_config_validation_bad_always_review_categories(tmp_path):
    """Unknown category in always_review_categories makes load_config raise ConfigError."""
    base_cfg = _valid_base_config()
    base_cfg["classification"] = {
        "hitl_threshold": 0.85,
        "always_review_categories": ["Security/Account", "FakeCategory"],
    }

    bad_file = tmp_path / "bad_cat.yaml"
    bad_file.write_text(yaml.dump(base_cfg))

    with pytest.raises(ConfigError, match="items must be known categories"):
        load_config(str(bad_file))


# ---------------------------------------------------------------------------
# 4. CLI Tool Subprocess Tests (scripts/hitl_cli.py)
# ---------------------------------------------------------------------------


def test_hitl_cli_full_workflow(tmp_path):
    """Tests hitl_cli.py list, show, approve, reject commands and exit codes (0, 2, 3)."""
    db_file = tmp_path / "test_cli.db"
    db = TriageDatabase(db_path=str(db_file))

    # Seed pending email
    db.check_and_acquire("cli-em-01", "th-cli", "<msg@cli.com>", "customer_raw@example.com")
    db.mark_done(
        email_id="cli-em-01",
        routing_status="gatekeeper_approved",
        masked_subject="Masked Subject for CLI",
        masked_body="Masked body text for customer issue.",
    )
    db.record_phase2_classification(
        email_id="cli-em-01",
        classification={
            "category": "Billing Issue",
            "priority": "High",
            "sentiment": "Negative",
            "customer_emotion": "Frustrated",
            "summary": "Customer billing dispute",
            "suggested_team": "Billing",
            "confidence": 0.90,
        },
        hitl_status="pending",
        hitl_reason="Escalated customer emotion (Frustrated) with High priority",
    )

    env = os.environ.copy()
    env["DATABASE_PATH"] = str(db_file)
    cli_path = str(Path(__file__).resolve().parent.parent / "scripts" / "hitl_cli.py")

    # 1. list (text)
    p_list = subprocess.run(
        [sys.executable, cli_path, "list"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert p_list.returncode == 0
    assert "cli-em-01" in p_list.stdout
    assert "Billing Issue" in p_list.stdout
    # PII Invariant: sender email never in output
    assert "customer_raw@example.com" not in p_list.stdout

    # 2. list (--json)
    p_json = subprocess.run(
        [sys.executable, cli_path, "list", "--json"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert p_json.returncode == 0
    items = json.loads(p_json.stdout)
    assert len(items) == 1
    assert items[0]["email_id"] == "cli-em-01"
    assert "sender_email" not in items[0]
    assert items[0]["category"] == "Billing Issue"

    # 3. show valid pending
    p_show = subprocess.run(
        [sys.executable, cli_path, "show", "cli-em-01"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert p_show.returncode == 0
    assert "Masked Subject for CLI" in p_show.stdout
    assert "customer_raw@example.com" not in p_show.stdout

    # 4. show non-existent -> exit 3
    p_show_missing = subprocess.run(
        [sys.executable, cli_path, "show", "missing-id"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert p_show_missing.returncode == 3

    # 5. approve missing --by -> exit 2
    p_app_err = subprocess.run(
        [sys.executable, cli_path, "approve", "cli-em-01"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert p_app_err.returncode == 2

    # 6. approve invalid category -> exit 2
    p_app_bad_cat = subprocess.run(
        [sys.executable, cli_path, "approve", "cli-em-01", "--by", "alice", "--category", "InvalidCat"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert p_app_bad_cat.returncode == 2

    # 7. approve valid -> exit 0
    p_app_ok = subprocess.run(
        [
            sys.executable,
            cli_path,
            "approve",
            "cli-em-01",
            "--by",
            "alice",
            "--notes",
            "Approved refund",
            "--category",
            "Refund Request",
            "--team",
            "Billing",
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert p_app_ok.returncode == 0

    # 8. approve again (already resolved) -> exit 3
    p_app_again = subprocess.run(
        [sys.executable, cli_path, "approve", "cli-em-01", "--by", "alice"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert p_app_again.returncode == 3

    # 9. Seed another pending email for reject test
    db.check_and_acquire("cli-em-02", "th-cli-2", "<msg2@cli.com>", "customer2@example.com")
    db.mark_done("cli-em-02", routing_status="gatekeeper_approved")
    db.record_phase2_classification(
        email_id="cli-em-02",
        classification={"category": "Other", "confidence": 0.10},
        hitl_status="pending",
    )

    # 10. reject missing notes -> exit 2
    p_rej_no_notes = subprocess.run(
        [sys.executable, cli_path, "reject", "cli-em-02", "--by", "bob"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert p_rej_no_notes.returncode == 2

    # 11. reject valid -> exit 0
    p_rej_ok = subprocess.run(
        [sys.executable, cli_path, "reject", "cli-em-02", "--by", "bob", "--notes", "Spam attempt"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert p_rej_ok.returncode == 0
