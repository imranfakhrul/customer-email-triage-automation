"""Test to ensure no stale or inaccurate marketing claims exist in code or documentation.

Invariants:
The following phrases must NOT appear in README.md, main.py, pipeline.py, nodes/, or utils/:
- bypass
- sub-second
- enterprise-grade
- 100% complete
- 100% tested
- JevAIClient
- zero downtime
"""

from pathlib import Path
import re
import pytest

BASE_DIR = Path(__file__).resolve().parent.parent

FORBIDDEN_PHRASES = [
    "bypass",
    "sub-second",
    "enterprise-grade",
    "100% complete",
    "100% tested",
    "JevAIClient",
    "zero downtime",
]

TARGET_FILES = [
    BASE_DIR / "README.md",
    BASE_DIR / "main.py",
    BASE_DIR / "pipeline.py",
]

TARGET_DIRS = [
    BASE_DIR / "nodes",
    BASE_DIR / "utils",
]


def get_all_target_files():
    files = list(TARGET_FILES)
    for d in TARGET_DIRS:
        if d.exists():
            for p in d.rglob("*.py"):
                if "__pycache__" not in str(p):
                    files.append(p)
    return files


@pytest.mark.parametrize("phrase", FORBIDDEN_PHRASES)
def test_no_stale_claims_in_target_files(phrase):
    """Ensure forbidden marketing and stale claim phrases do not appear in key files."""
    files = get_all_target_files()
    violations = []

    pattern = re.compile(r"\b" + re.escape(phrase) + r"\b", re.IGNORECASE)
    # Special check for JevAIClient (case-sensitive identifier)
    if phrase == "JevAIClient":
        pattern = re.compile(re.escape(phrase))

    for f in files:
        if not f.exists():
            continue
        text = f.read_text(encoding="utf-8")
        matches = list(pattern.finditer(text))
        if matches:
            lines = text.splitlines()
            for m in matches:
                line_no = text[: m.start()].count("\n") + 1
                matched_line = lines[line_no - 1].strip() if line_no <= len(lines) else ""
                violations.append(f"{f.name}:{line_no} -> '{matched_line}'")

    assert not violations, (
        f"Forbidden phrase '{phrase}' found in:\n" + "\n".join(violations)
    )
