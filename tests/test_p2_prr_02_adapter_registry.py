"""Tests for PRR-02: Production Adapter Registration & Auto-Discovery.

Validates that:
1. register_active_adapters() instantiates and registers adapters for all
   destinations marked as enabled in configuration.
2. Disabled destinations are not registered.
3. Repeated calls are idempotent and preserve existing adapter instances.
4. dispatcher_node() automatically triggers lazy adapter registration when
   adapters=None and an enabled destination is dispatched in live mode.
5. Phase 2 worker registers active adapters on startup.
"""

from typing import Any

import pytest

from db.database import TriageDatabase
from nodes.dispatcher import dispatcher_node
from scripts.phase2_worker import Phase2Worker, run_worker_once
from state import EmailClassification
from utils.adapters import (
    CRMAdapter,
    FreeScoutAdapter,
    GitHubAdapter,
    WebhookAdapter,
    get_adapter,
    register_active_adapters,
    reset_adapters,
)


@pytest.fixture(autouse=True)
def clean_registry() -> Any:
    """Ensures a clean adapter registry before and after each test."""
    reset_adapters()
    yield
    reset_adapters()


@pytest.fixture
def temp_db(tmp_path: Any) -> TriageDatabase:
    """Creates a temporary SQLite database initialized with schema."""
    db_path = tmp_path / "test_prr_02.db"
    return TriageDatabase(db_path=str(db_path))


def _sample_config(
    github_enabled: bool = False,
    freescout_enabled: bool = False,
    crm_enabled: bool = False,
    webhook_enabled: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Generates a test configuration with controllable destination flags."""
    return {
        "dispatch": {
            "dry_run": dry_run,
            "kill_switch": False,
            "max_attempts": 3,
            "pending_timeout_minutes": 10,
            "backoff_base_seconds": 1.0,
            "backoff_max_seconds": 20.0,
        },
        "destinations": {
            "github": {
                "enabled": github_enabled,
                "daily_cap": 200,
                "use_masked_text_only": True,
                "target": "my-org/my-repo",
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
            "freescout": {
                "enabled": freescout_enabled,
                "daily_cap": 1000,
                "use_masked_text_only": False,
                "unmask_pii": True,
                "target": "https://support.example.com",
                "api_key_env": "TEST_FREESCOUT_API_KEY",
                "mailbox_id": 1,
                "allowed_hosts": ["support.example.com"],
                "request_timeout_seconds": 15.0,
                "precheck_duplicates": False,
                "circuit_breaker": {"failure_threshold": 5, "cooldown_seconds": 900},
            },
            "crm": {
                "enabled": crm_enabled,
                "daily_cap": 500,
                "use_masked_text_only": False,
                "unmask_pii": True,
                "target": "https://api.hubapi.com",
                "api_key_env": "TEST_CRM_API_KEY",
                "allowed_hosts": ["api.hubapi.com"],
                "request_timeout_seconds": 15.0,
                "precheck_duplicates": False,
                "circuit_breaker": {"failure_threshold": 5, "cooldown_seconds": 900},
            },
            "webhook": {
                "enabled": webhook_enabled,
                "daily_cap": 200,
                "use_masked_text_only": False,
                "unmask_pii": False,
                "target": "https://events.example.com/alerts",
                "secret_env": "TEST_WEBHOOK_SECRET_KEY",
                "allowed_hosts": ["events.example.com"],
                "request_timeout_seconds": 10.0,
                "circuit_breaker": {"failure_threshold": 5, "cooldown_seconds": 900},
            },
        },
    }


class TestRegisterActiveAdapters:
    """Unit tests for register_active_adapters function."""

    def test_no_destinations_enabled_registers_nothing(self) -> None:
        """When all destinations are enabled: false, no adapters are registered."""
        cfg = _sample_config()
        registered = register_active_adapters(cfg)

        assert registered == {}
        assert get_adapter("github") is None
        assert get_adapter("freescout") is None
        assert get_adapter("crm") is None
        assert get_adapter("webhook") is None

    def test_single_destination_enabled_registers_only_that_adapter(self) -> None:
        """When only github is enabled, only GitHubAdapter is instantiated and registered."""
        cfg = _sample_config(github_enabled=True)
        registered = register_active_adapters(cfg)

        assert "github" in registered
        assert isinstance(registered["github"], GitHubAdapter)
        assert get_adapter("github") is registered["github"]
        assert get_adapter("freescout") is None
        assert get_adapter("crm") is None
        assert get_adapter("webhook") is None

    def test_all_destinations_enabled_registers_all_adapters(self) -> None:
        """When all destinations are enabled, all 4 canonical adapters are registered."""
        cfg = _sample_config(
            github_enabled=True,
            freescout_enabled=True,
            crm_enabled=True,
            webhook_enabled=True,
        )
        registered = register_active_adapters(cfg)

        assert len(registered) == 4
        assert isinstance(registered["github"], GitHubAdapter)
        assert isinstance(registered["freescout"], FreeScoutAdapter)
        assert isinstance(registered["crm"], CRMAdapter)
        assert isinstance(registered["webhook"], WebhookAdapter)

        assert get_adapter("github") is registered["github"]
        assert get_adapter("freescout") is registered["freescout"]
        assert get_adapter("crm") is registered["crm"]
        assert get_adapter("webhook") is registered["webhook"]

    def test_repeated_calls_are_idempotent(self) -> None:
        """Calling register_active_adapters multiple times preserves existing instances."""
        cfg = _sample_config(github_enabled=True, webhook_enabled=True)
        reg1 = register_active_adapters(cfg)
        reg2 = register_active_adapters(cfg)

        assert reg1["github"] is reg2["github"]
        assert reg1["webhook"] is reg2["webhook"]


class TestDispatcherLazyAdapterRegistration:
    """Unit tests verifying dispatcher lazy auto-registration of active adapters."""

    def test_dispatcher_lazy_registers_adapter_when_registry_empty(
        self, temp_db: TriageDatabase
    ) -> None:
        """When adapters=None and registry is empty, dispatcher auto-registers enabled adapters.

        Before PRR-02, this deferred with 'adapter_unavailable'. With PRR-02,
        the adapter is registered and evaluated by safety rails (e.g. adapter_not_configured
        if API key is missing).
        """
        email_id = "em_lazy_gh_001"
        temp_db.check_and_acquire(
            email_id=email_id,
            message_id="<lazy-gh@test.local>",
            thread_id="th_lazy_gh",
            sender_email="tester@example.com",
        )
        temp_db.mark_done(
            email_id=email_id,
            routing_status="gatekeeper_approved",
            gatekeeper_decision="legitimate",
            classifier_used="regex",
            gatekeeper_confidence=0.85,
            masked_subject="Bug: Database connection pool leak",
            masked_body="Steps to reproduce connection exhaustion",
        )
        temp_db.record_phase2_classification(
            email_id=email_id,
            classification=EmailClassification(
                category="Bug Report",
                priority="Critical",
                sentiment="Negative",
                customer_emotion="Frustrated",
                summary="DB pool leak",
                suggested_team="Engineering",
                confidence=0.95,
            ),
            p2_classifier_used="heuristic",
            hitl_status="auto_approved",
        )

        cfg = _sample_config(github_enabled=True, dry_run=False)

        # Ensure global registry has no github adapter beforehand
        assert get_adapter("github") is None

        # Execute dispatcher without passing explicit adapters dict
        res = dispatcher_node(
            {"email_id": email_id},
            db=temp_db,
            config=cfg,
            adapters=None,
        )

        # After execution, the github adapter must have been registered
        assert get_adapter("github") is not None
        assert isinstance(get_adapter("github"), GitHubAdapter)

        # The reason must NOT be 'adapter_unavailable' (it is deferred for adapter_not_configured
        # because TEST_GITHUB_TOKEN is not in env, which is the correct Rail 4 check)
        assert len(res["dispatch_results"]) > 0
        assert res["dispatch_results"][0]["reason"] != "adapter_unavailable"
        assert res["dispatch_results"][0]["reason"] == "adapter_not_configured"


class TestWorkerAdapterRegistration:
    """Unit tests verifying Phase 2 worker registers adapters at initialization."""

    def test_worker_run_once_registers_active_adapters(
        self, temp_db: TriageDatabase
    ) -> None:
        """run_worker_once registers active adapters before executing jobs."""
        cfg = _sample_config(github_enabled=True, dry_run=True)
        assert get_adapter("github") is None

        run_worker_once(db=temp_db, config=cfg)

        assert get_adapter("github") is not None
        assert isinstance(get_adapter("github"), GitHubAdapter)

    def test_phase2_worker_instance_registers_active_adapters(
        self, temp_db: TriageDatabase
    ) -> None:
        """Phase2Worker __init__ registers active adapters."""
        cfg = _sample_config(webhook_enabled=True, dry_run=True)
        assert get_adapter("webhook") is None

        worker = Phase2Worker(db=temp_db, config=cfg)
        assert worker is not None

        assert get_adapter("webhook") is not None
        assert isinstance(get_adapter("webhook"), WebhookAdapter)
