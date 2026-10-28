"""Unit and integration tests for Phase 2 Synthetic Benchmark Suite.

Milestone [P2-10]:
Validates:
1. Complete execution of 50 synthetic benchmark scenarios in data/benchmark_phase2.json.
2. 100% field assertions across categories, priorities, destinations, and HITL states.
3. Offline deterministic heuristic pipeline execution.
4. CLI argument handling for --phase2 in main.py.
"""

from __future__ import annotations

import json
import sys

from utils.config import BASE_DIR


def test_benchmark_phase2_dataset_schema():
    """Verifies that data/benchmark_phase2.json exists, contains 50 scenarios with valid schemas."""
    dataset_path = BASE_DIR / "data" / "benchmark_phase2.json"
    assert dataset_path.exists(), f"Benchmark dataset missing at {dataset_path}"

    with open(dataset_path, encoding="utf-8") as f:
        data = json.load(f)

    assert len(data) == 50, f"Expected exactly 50 scenarios, found {len(data)}"

    seen_ids = set()
    for item in data:
        assert "id" in item
        assert item["id"] not in seen_ids, f"Duplicate scenario ID: {item['id']}"
        seen_ids.add(item["id"])

        assert "email_id" in item
        assert "email_subject" in item
        assert "email_body" in item
        assert "sender_email" in item
        assert "expected" in item
        assert isinstance(item["expected"], dict)
        assert "hitl_status" in item["expected"]


def test_main_cli_phase2_argument(monkeypatch):
    """Verifies that main.py parses the --phase2 CLI flag."""
    import main

    called = False

    def mock_run_phase2(*args, **kwargs):
        nonlocal called
        called = True
        return True

    monkeypatch.setattr(main, "run_phase2_benchmark_suite", mock_run_phase2)
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "--phase2", "--offline"],
    )

    main.main()
    assert called is True


def test_phase2_benchmark_suite_runner():
    """Runs the full Phase 2 benchmark suite runner from main.py and asserts all 50 pass."""
    import main

    success = main.run_phase2_benchmark_suite(offline=True)
    assert success is True
