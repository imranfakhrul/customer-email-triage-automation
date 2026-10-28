#!/usr/bin/env python3
"""Customer Email Triage Automation — Milestone [P2-11] Verification Script.

Validates:
1. docs/architecture_phase2.md completeness & Mermaid diagrams
2. docs/hitl_runbook.md completeness & operator procedures
3. README.md documentation synchronization
4. README.md test count vs collected pytest count
5. Execution of tests/test_p2_documentation.py suite
"""

import os
import re
import subprocess  # nosec B404
import sys
from collections.abc import Callable
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def run_check(description: str, fn: Callable[[], None]) -> None:
    print(f"\n[*] {description}...")
    try:
        fn()
        print(f"    [PASS] {description}")
    except (ValueError, RuntimeError, subprocess.CalledProcessError) as e:
        print(f"    [FAIL] {description}: {e}")
        sys.exit(1)


def check_architecture_phase2_doc() -> None:
    doc_path = PROJECT_ROOT / "docs" / "architecture_phase2.md"
    if not doc_path.exists():
        raise RuntimeError(f"Missing {doc_path}")
    content = doc_path.read_text(encoding="utf-8")

    if "flowchart" not in content:
        raise ValueError("Missing flowchart Mermaid diagram")
    if "stateDiagram" not in content and "stateDiagram-v2" not in content:
        raise ValueError("Missing stateDiagram Mermaid diagram")
    if "sequenceDiagram" not in content:
        raise ValueError("Missing sequenceDiagram Mermaid diagram")

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
        if cat not in content:
            raise ValueError(f"Missing category: {cat}")

    destinations = ["github", "freescout", "crm", "webhook"]
    for dest in destinations:
        if dest not in content:
            raise ValueError(f"Missing destination: {dest}")

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
        if st not in content:
            raise ValueError(f"Missing p2_jobs state: {st}")


def check_hitl_runbook_doc() -> None:
    runbook_path = PROJECT_ROOT / "docs" / "hitl_runbook.md"
    if not runbook_path.exists():
        raise RuntimeError(f"Missing {runbook_path}")
    content = runbook_path.read_text(encoding="utf-8")

    subcommands = ["list", "show", "approve", "override", "reject"]
    for cmd in subcommands:
        if cmd not in content:
            raise ValueError(f"Missing subcommand in runbook: {cmd}")

    if "dead_letter" not in content:
        raise ValueError("Missing DLQ remediation in runbook")
    if "unknown" not in content:
        raise ValueError("Missing unknown ledger reconciliation in runbook")


def check_readme_synchronization() -> None:
    readme_path = PROJECT_ROOT / "README.md"
    if not readme_path.exists():
        raise RuntimeError(f"Missing {readme_path}")
    content = readme_path.read_text(encoding="utf-8")

    if "--phase2" not in content:
        raise ValueError("Missing --phase2 in README.md")
    if "phase2_worker.py" not in content:
        raise ValueError("Missing phase2_worker.py in README.md")
    if "hitl_cli.py" not in content:
        raise ValueError("Missing hitl_cli.py in README.md")
    if "architecture_phase2.md" not in content:
        raise ValueError("Missing architecture_phase2.md link in README.md")
    if "hitl_runbook.md" not in content:
        raise ValueError("Missing hitl_runbook.md link in README.md")


def check_readme_test_count_parity() -> None:
    readme_path = PROJECT_ROOT / "README.md"
    content = readme_path.read_text(encoding="utf-8")
    matches = re.findall(r"\((\d+)\s+tests", content)
    if not matches:
        raise ValueError("No test counts found in README.md")
    readme_count = int(matches[0])

    env = dict(os.environ)
    env["PYTEST_COLLECT_GUARD"] = "1"
    res = subprocess.run(  # nosec B603
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    m = re.search(r"(\d+)\s+tests?\s+collected", res.stdout)
    if not m:
        raise ValueError(f"Failed to parse pytest count:\n{res.stdout}")
    actual_count = int(m.group(1))

    if readme_count != actual_count:
        raise ValueError(
            f"README count ({readme_count}) != Pytest collected count ({actual_count})"
        )


def check_documentation_pytest_suite() -> None:
    res = subprocess.run(  # nosec B603
        [sys.executable, "-m", "pytest", "tests/test_p2_documentation.py", "-v"],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        check=True,
    )
    print(res.stdout)


def main() -> None:
    print("=" * 70)
    print(" Customer Email Triage Automation — Milestone [P2-11] Verification")
    print("=" * 70)

    run_check("docs/architecture_phase2.md Completeness & Diagrams", check_architecture_phase2_doc)
    run_check("docs/hitl_runbook.md Completeness & Procedures", check_hitl_runbook_doc)
    run_check("README.md Documentation Synchronization", check_readme_synchronization)
    run_check("README.md Test Count Exact Parity", check_readme_test_count_parity)
    run_check("Execution of tests/test_p2_documentation.py Suite", check_documentation_pytest_suite)

    print("\n" + "=" * 70)
    print(" [SUCCESS] ALL 5 CHECKS PASSED FOR MILESTONE [P2-11]!")
    print("=" * 70)


if __name__ == "__main__":
    main()
