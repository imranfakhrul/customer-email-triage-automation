"""Test suite verifying Phase 2 architecture documentation, diagrams, and operator runbooks."""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
ARCH_P2_PATH = BASE_DIR / "docs" / "architecture_phase2.md"
HITL_RUNBOOK_PATH = BASE_DIR / "docs" / "hitl_runbook.md"
README_PATH = BASE_DIR / "README.md"


def test_docs_architecture_phase2_exists_and_complete():
    """Verify docs/architecture_phase2.md documents all components, states, and diagrams."""
    assert ARCH_P2_PATH.exists(), f"Architecture doc missing at {ARCH_P2_PATH}"
    doc_text = ARCH_P2_PATH.read_text(encoding="utf-8")

    # 1. Check Mermaid diagrams
    assert "```mermaid" in doc_text, "Missing Mermaid diagrams in architecture_phase2.md"
    assert "sequenceDiagram" in doc_text, "Missing sequence diagram in architecture_phase2.md"
    assert "stateDiagram" in doc_text or "stateDiagram-v2" in doc_text, (
        "Missing state diagram in architecture_phase2.md"
    )

    # 2. Check 10-category taxonomy
    categories = [
        "Bug Report",
        "Feature Request",
        "Demo Request",
        "Pricing Inquiry",
        "Billing Issue",
        "Refund Request",
        "Security/Account",
        "Complaint",
        "General Query",
        "Other",
    ]
    for cat in categories:
        assert cat in doc_text, f"Category '{cat}' missing from architecture_phase2.md"

    # 3. Check 4 destinations
    destinations = ["github", "freescout", "crm", "webhook"]
    for dest in destinations:
        assert dest in doc_text, f"Destination '{dest}' missing from architecture_phase2.md"

    # 4. Check all p2_jobs states
    p2_states = [
        "unclaimed",
        "claimed",
        "dispatching",
        "done",
        "failed",
        "dead_letter",
        "hitl_pending",
        "hitl_resolved",
    ]
    for st in p2_states:
        assert st in doc_text, f"p2_jobs state '{st}' missing from architecture_phase2.md"

    # 5. Check outbox ledger & selective unmasking
    assert "p2_dispatch_log" in doc_text, "p2_dispatch_log missing from architecture_phase2.md"
    assert "CREDIT_CARD" in doc_text, (
        "CREDIT_CARD masking invariant missing from architecture_phase2.md"
    )
    assert "API_KEY" in doc_text, "API_KEY masking invariant missing from architecture_phase2.md"
    assert "token_map" in doc_text, "token_map invariant missing from architecture_phase2.md"


def test_docs_hitl_runbook_exists_and_complete():
    """Verify docs/hitl_runbook.md documents operator commands, triggers, and recovery."""
    assert HITL_RUNBOOK_PATH.exists(), f"HITL runbook missing at {HITL_RUNBOOK_PATH}"
    runbook_text = HITL_RUNBOOK_PATH.read_text(encoding="utf-8")

    # 1. Check CLI subcommands
    subcommands = ["list", "show", "approve", "override", "reject"]
    for cmd in subcommands:
        assert f"{cmd}" in runbook_text, f"Subcommand '{cmd}' missing from hitl_runbook.md"

    # 2. Check triggers
    triggers = ["Security/Account", "Angry", "Other"]
    for trigger in triggers:
        assert trigger in runbook_text, f"Trigger '{trigger}' missing from hitl_runbook.md"

    # 3. Check recovery and reconciliation
    assert "dead_letter" in runbook_text, "dead_letter handling missing from hitl_runbook.md"
    assert "unknown" in runbook_text, (
        "unknown ledger state reconciliation missing from hitl_runbook.md"
    )


def test_readme_documents_phase2_features_and_cli():
    """Verify README.md documents Phase 2 CLI flags, scripts, and benchmark."""
    assert README_PATH.exists(), f"README.md missing at {README_PATH}"
    readme_text = README_PATH.read_text(encoding="utf-8")

    assert "--phase2" in readme_text, "--phase2 benchmark flag missing from README.md"
    assert "phase2_worker.py" in readme_text, "phase2_worker.py missing from README.md"
    assert "hitl_cli.py" in readme_text, "hitl_cli.py missing from README.md"
    assert "architecture_phase2.md" in readme_text, (
        "Reference to architecture_phase2.md missing from README.md"
    )
    assert "hitl_runbook.md" in readme_text, (
        "Reference to hitl_runbook.md missing from README.md"
    )


def test_documented_scripts_exist_and_valid():
    """Ensure scripts referenced in Phase 2 documentation actually exist."""
    referenced_scripts = [
        "scripts/phase2_worker.py",
        "scripts/hitl_cli.py",
        "tools/run_worker.sh",
        "scripts/github_smoke_test.py",
        "scripts/freescout_smoke_test.py",
        "scripts/crm_smoke_test.py",
        "scripts/webhook_smoke_test.py",
    ]
    for script_rel in referenced_scripts:
        script_path = BASE_DIR / script_rel
        assert script_path.exists(), f"Documented script does not exist: {script_rel}"
