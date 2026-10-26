"""Test to ensure test count in README.md strictly equals pytest collected count."""

import os
from pathlib import Path
import re
import subprocess
import sys
import pytest

BASE_DIR = Path(__file__).resolve().parent.parent
README_PATH = BASE_DIR / "README.md"


def test_readme_test_count_matches_pytest_collected():
    """Verify test count written in README.md equals pytest's collected count."""
    # Recursion guard for inner subprocess collection
    if os.environ.get("PYTEST_COLLECT_GUARD") == "1":
        pytest.skip("Skipping during inner pytest collection")

    assert README_PATH.exists(), f"README.md missing at {README_PATH}"
    readme_text = README_PATH.read_text(encoding="utf-8")

    matches = re.findall(r"\((\d+)\s+tests", readme_text)
    assert matches, "No '(<count> tests' pattern found in README.md"
    readme_counts = [int(m) for m in matches]

    assert len(set(readme_counts)) == 1, (
        f"Inconsistent test counts in README: {set(readme_counts)}"
    )
    expected_count = readme_counts[0]

    env = dict(os.environ)
    env["PYTEST_COLLECT_GUARD"] = "1"
    res = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=str(BASE_DIR),
        capture_output=True,
        text=True,
        env=env,
    )
    assert res.returncode == 0, f"pytest --collect-only failed:\n{res.stderr}\n{res.stdout}"

    m = re.search(r"(\d+)\s+tests?\s+collected", res.stdout)
    assert m, f"Could not parse collected test count from pytest output:\n{res.stdout}"
    actual_count = int(m.group(1))

    assert expected_count == actual_count, (
        f"README.md test count ({expected_count}) does not match pytest collected count ({actual_count})"
    )
