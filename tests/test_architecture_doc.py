"""Test suite enforcing that docs/ARCHITECTURE.md, AGENTS.md, and GEMINI.md stay up-to-date."""

import sqlite3
import tempfile
import typing
from urllib.parse import urlparse

import yaml

import state
from db.database import TriageDatabase
from utils.config import BASE_DIR

ARCH_DOC_PATH = BASE_DIR / "docs" / "ARCHITECTURE.md"
AGENTS_DOC_PATH = BASE_DIR / "AGENTS.md"
GEMINI_SYMLINK_PATH = BASE_DIR / "GEMINI.md"
CONFIG_PATH = BASE_DIR / "config.yaml"


def test_architecture_doc_exists_and_nodes_present():
    """Verify docs/ARCHITECTURE.md documents every nodes/*.py module (except __init__.py)."""
    assert ARCH_DOC_PATH.exists(), f"Architecture doc missing at {ARCH_DOC_PATH}"
    doc_text = ARCH_DOC_PATH.read_text(encoding="utf-8")

    nodes_dir = BASE_DIR / "nodes"
    node_files = sorted(
        p.name for p in nodes_dir.glob("*.py") if p.name != "__init__.py"
    )
    assert len(node_files) > 0, "No node files found in nodes/"

    missing_nodes = []
    for node_file in node_files:
        if node_file not in doc_text:
            missing_nodes.append(node_file)

    assert not missing_nodes, (
        f"docs/ARCHITECTURE.md is missing documentation for node files: {missing_nodes}"
    )


def test_architecture_doc_contains_all_state_keys():
    """Verify docs/ARCHITECTURE.md contains every key of TriageState enclosed in backticks."""
    assert ARCH_DOC_PATH.exists(), f"Architecture doc missing at {ARCH_DOC_PATH}"
    doc_text = ARCH_DOC_PATH.read_text(encoding="utf-8")

    state_keys = sorted(typing.get_type_hints(state.TriageState).keys())
    assert len(state_keys) > 0, "No keys found in TriageState"

    missing_keys = []
    for key in state_keys:
        expected = f"`{key}`"
        if expected not in doc_text:
            missing_keys.append(key)

    assert not missing_keys, (
        f"docs/ARCHITECTURE.md missing TriageState keys: {missing_keys}"
    )


def test_architecture_doc_contains_all_db_columns_and_tables():
    """Verify docs/ARCHITECTURE.md contains every email_triage column and table name."""
    assert ARCH_DOC_PATH.exists(), f"Architecture doc missing at {ARCH_DOC_PATH}"
    doc_text = ARCH_DOC_PATH.read_text(encoding="utf-8")

    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        TriageDatabase(db_path=tmp.name)
        with sqlite3.connect(tmp.name) as conn:
            cur = conn.execute("PRAGMA table_info(email_triage);")
            columns = [row[1] for row in cur.fetchall()]

            cur_tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
            )
            tables = [row[0] for row in cur_tables.fetchall()]

    assert "email_triage" in tables, "email_triage table was not created"

    missing_tables = [t for t in tables if f"`{t}`" not in doc_text]
    assert not missing_tables, (
        f"docs/ARCHITECTURE.md is missing table documentation: {missing_tables}"
    )

    missing_columns = []
    for col in columns:
        expected = f"`{col}`"
        if expected not in doc_text:
            missing_columns.append(col)

    assert not missing_columns, (
        f"docs/ARCHITECTURE.md missing email_triage columns: {missing_columns}"
    )


def test_architecture_doc_contains_all_config_sections():
    """Verify docs/ARCHITECTURE.md contains every top-level section of config.yaml in backticks."""
    assert ARCH_DOC_PATH.exists(), f"Architecture doc missing at {ARCH_DOC_PATH}"
    assert CONFIG_PATH.exists(), f"Config file missing at {CONFIG_PATH}"

    doc_text = ARCH_DOC_PATH.read_text(encoding="utf-8")
    config_data = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    sections = sorted(config_data.keys())

    missing_sections = []
    for sec in sections:
        expected = f"`{sec}`"
        if expected not in doc_text:
            missing_sections.append(sec)

    assert not missing_sections, (
        f"docs/ARCHITECTURE.md missing config sections: {missing_sections}"
    )


def test_architecture_doc_contains_all_https_hosts_from_config():
    """Verify docs/ARCHITECTURE.md documents every https host from config.yaml api_url values."""
    assert ARCH_DOC_PATH.exists(), f"Architecture doc missing at {ARCH_DOC_PATH}"
    assert CONFIG_PATH.exists(), f"Config file missing at {CONFIG_PATH}"

    doc_text = ARCH_DOC_PATH.read_text(encoding="utf-8")
    config_data = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))

    def extract_api_urls(obj):
        urls = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if "api_url" in k and isinstance(v, str) and v.startswith("https://"):
                    urls.append(v)
                else:
                    urls.extend(extract_api_urls(v))
        elif isinstance(obj, list):
            for item in obj:
                urls.extend(extract_api_urls(item))
        return urls

    api_urls = extract_api_urls(config_data)
    assert api_urls, "No https api_url found in config.yaml"

    hosts = {urlparse(u).netloc for u in api_urls}
    missing_hosts = []
    for host in hosts:
        if f"`{host}`" not in doc_text and host not in doc_text:
            missing_hosts.append(host)

    assert not missing_hosts, (
        f"docs/ARCHITECTURE.md is missing documentation for API hosts: {missing_hosts}"
    )


def test_agents_and_gemini_guidance_files():
    """Verify AGENTS.md and GEMINI.md exist, line count <= 150, contain ./check.sh, and resolve."""
    assert AGENTS_DOC_PATH.exists(), f"AGENTS.md missing at {AGENTS_DOC_PATH}"
    assert GEMINI_SYMLINK_PATH.exists(), f"GEMINI.md missing at {GEMINI_SYMLINK_PATH}"

    agents_content = AGENTS_DOC_PATH.read_text(encoding="utf-8")
    line_count = len(agents_content.splitlines())
    assert line_count <= 150, f"AGENTS.md is too long ({line_count} lines > 150 lines)"
    assert "./check.sh" in agents_content, "AGENTS.md does not mention './check.sh'"

    resolved_gemini = GEMINI_SYMLINK_PATH.resolve()
    resolved_agents = AGENTS_DOC_PATH.resolve()
    assert resolved_gemini == resolved_agents, (
        f"GEMINI.md ({resolved_gemini}) does not resolve to AGENTS.md ({resolved_agents})"
    )
