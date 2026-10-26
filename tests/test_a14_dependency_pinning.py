"""Tests for [A14] Pin All Dependency Versions.

Ensures:
1. Every package in requirements.txt is pinned with exact '==' syntax.
2. No loose range or unpinned packages exist.
3. Core project dependencies are all accounted for.
4. Dockerfile pins the spaCy model release wheel and avoids unpinned downloads.
"""

from pathlib import Path
import re
import pytest

BASE_DIR = Path(__file__).resolve().parent.parent
REQUIREMENTS_PATH = BASE_DIR / "requirements.txt"
REQUIREMENTS_DEV_PATH = BASE_DIR / "requirements-dev.txt"
DOCKERFILE_PATH = BASE_DIR / "Dockerfile"

REQUIRED_PACKAGES = {
    "pydantic",
    "langgraph",
    "langchain",
    "langchain-groq",
    "python-dotenv",
    "pyyaml",
    "spacy",
    "requests",
    "phonenumbers",
}


def get_requirement_lines() -> list[str]:
    assert REQUIREMENTS_PATH.exists(), f"requirements.txt missing at {REQUIREMENTS_PATH}"
    lines = []
    for line in REQUIREMENTS_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def test_requirements_file_not_empty():
    lines = get_requirement_lines()
    assert len(lines) >= 9, f"Expected at least 9 dependencies, found {len(lines)}"


def test_all_requirements_pinned_with_exact_equal():
    """Verify every requirement uses exact '==' pinning."""
    lines = get_requirement_lines()
    exact_pin_pattern = re.compile(r"^[a-zA-Z0-9_\-]+==[0-9]+(\.[0-9]+)*.*$")
    for line in lines:
        assert exact_pin_pattern.match(line), (
            f"Package line '{line}' is not pinned with exact '==<version>'"
        )


def test_no_range_or_unpinned_operators():
    """Ensure no loose version specifiers (>=, <=, ~=, >, <, !=) or bare names."""
    lines = get_requirement_lines()
    for line in lines:
        assert not re.search(r"[><~^]", line), (
            f"Package line '{line}' contains loose/range operator"
        )
        assert "==" in line, f"Package line '{line}' missing '==' pinning"


def test_core_dependencies_present():
    """Verify all 9 core dependencies are present in requirements.txt."""
    lines = get_requirement_lines()
    pkg_names = {line.split("==")[0].strip().lower() for line in lines}
    for req in REQUIRED_PACKAGES:
        assert req.lower() in pkg_names, f"Expected core package '{req}' missing from requirements.txt"


def test_dockerfile_pins_spacy_model_wheel():
    """Verify Dockerfile installs the exact release wheel for en_core_web_sm."""
    assert DOCKERFILE_PATH.exists(), f"Dockerfile missing at {DOCKERFILE_PATH}"
    content = DOCKERFILE_PATH.read_text(encoding="utf-8")

    # Ensure unpinned dynamic download is not used
    assert "python -m spacy download en_core_web_sm" not in content, (
        "Dockerfile should not use unpinned 'python -m spacy download en_core_web_sm'"
    )

    # Ensure direct wheel release URL for 3.8.0 is pinned
    expected_wheel = (
        "https://github.com/explosion/spacy-models/releases/download/"
        "en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl"
    )
    assert expected_wheel in content, (
        f"Dockerfile must install pinned spaCy model release wheel: {expected_wheel}"
    )


def test_requirements_dev_file_and_pinning():
    """Verify requirements-dev.txt includes -r requirements.txt and pins pytest exactly."""
    assert REQUIREMENTS_DEV_PATH.exists(), f"requirements-dev.txt missing at {REQUIREMENTS_DEV_PATH}"
    dev_content = REQUIREMENTS_DEV_PATH.read_text(encoding="utf-8")
    lines = [line.strip() for line in dev_content.splitlines() if line.strip() and not line.strip().startswith("#")]

    assert any(line == "-r requirements.txt" for line in lines), (
        "requirements-dev.txt must include '-r requirements.txt'"
    )

    exact_pin_pattern = re.compile(r"^[a-zA-Z0-9_\-]+==[0-9]+(\.[0-9]+)*.*$")
    pytest_pinned = False
    for line in lines:
        if line.startswith("-r"):
            continue
        assert exact_pin_pattern.match(line), (
            f"Package line '{line}' in requirements-dev.txt is not pinned with exact '==<version>'"
        )
        if line.startswith("pytest=="):
            pytest_pinned = True
    assert pytest_pinned, "requirements-dev.txt must pin pytest with exact '==<version>'"


def test_dockerfile_supports_with_tests_arg():
    """Verify Dockerfile defines ARG WITH_TESTS=true and conditionally installs requirements-dev.txt."""
    content = DOCKERFILE_PATH.read_text(encoding="utf-8")
    assert "ARG WITH_TESTS=true" in content, "Dockerfile must define ARG WITH_TESTS=true"
    assert "requirements-dev.txt" in content, "Dockerfile must reference requirements-dev.txt"
    assert 'if [ "$WITH_TESTS" = "true" ]' in content or "if [ \"$WITH_TESTS\" = 'true' ]" in content, (
        "Dockerfile must conditionally install dev dependencies based on WITH_TESTS"
    )

