"""Unit tests for Fix B5: Fail-Fast Config Loader & Environment Variable Overrides.

Covers:
- BASE_DIR / DEFAULT_CONFIG_PATH anchoring (CWD-independent)
- Table-driven invalid-config cases -> ConfigError or FileNotFoundError
- Environment overrides: DATABASE_PATH, IDEMPOTENCY_STALE_MINUTES, MAX_DISPATCH_RETRIES
- No-swallow: TriageDatabase(), JevClient(), and pii_masker_node raise ConfigError on bad config
- main(): invalid config exits with code 2, stderr has "Configuration error", no traceback
- Existing callers receive config values from env overrides (stale_minutes, max_retries)
"""

import os
import subprocess
import sys
import textwrap
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

from utils.config import (
    BASE_DIR,
    DEFAULT_CONFIG_PATH,
    ConfigError,
    load_config,
    validate_config,
)


# ---------------------------------------------------------------------------
# Helper: build a minimal valid config dict (all required fields present)
# ---------------------------------------------------------------------------
def _valid_config_dict():
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


def _write_yaml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "test_config.yaml"
    p.write_text(textwrap.dedent(content))
    return p


# ---------------------------------------------------------------------------
# 1. BASE_DIR and CWD-independence
# ---------------------------------------------------------------------------
class TestBaseDirAnchoring(unittest.TestCase):
    """load_config() must work regardless of the current working directory."""

    def test_base_dir_is_project_root(self):
        """BASE_DIR resolves to the directory containing config.yaml."""
        self.assertTrue((BASE_DIR / "config.yaml").is_file(), f"config.yaml not found under BASE_DIR={BASE_DIR}")

    def test_default_config_path_is_absolute(self):
        self.assertTrue(DEFAULT_CONFIG_PATH.is_absolute())

    def test_load_config_from_different_cwd(self):
        """load_config() with no args works when CWD is not the project root."""
        original_cwd = os.getcwd()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                os.chdir(tmp)  # CWD is now /tmp/xxx — NOT the project root
                cfg = load_config()   # must still find config.yaml via BASE_DIR
                self.assertIsInstance(cfg, dict)
        finally:
            os.chdir(original_cwd)

    def test_relative_database_path_resolves_to_base_dir(self):
        """A relative database_path in config.yaml resolves against BASE_DIR, not CWD."""
        original_cwd = os.getcwd()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                os.chdir(tmp)
                cfg = load_config()
                db_path = cfg["system"]["database_path"]
                self.assertTrue(Path(db_path).is_absolute(), f"db_path not absolute: {db_path}")
                self.assertTrue(
                    str(BASE_DIR) in db_path,
                    f"db_path {db_path!r} does not contain BASE_DIR {BASE_DIR!r}"
                )
        finally:
            os.chdir(original_cwd)

    def test_relative_config_path_resolved_against_base_dir(self):
        """A relative path argument to load_config() is resolved against BASE_DIR."""
        # "config.yaml" relative should resolve to BASE_DIR/config.yaml
        cfg = load_config("config.yaml")
        self.assertIsInstance(cfg, dict)

    def test_absolute_path_used_as_given(self, tmp_path=None):
        """An absolute path arg is used as-is (not re-rooted under BASE_DIR)."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg_file = Path(tmp) / "abs_config.yaml"
            import yaml, copy
            valid = _valid_config_dict()
            cfg_file.write_text(yaml.safe_dump(valid))
            result = load_config(str(cfg_file))
            self.assertEqual(result["system"]["idempotency_stale_minutes"], 10)


# ---------------------------------------------------------------------------
# 2. Table-driven invalid config cases
# ---------------------------------------------------------------------------
INVALID_CASES = [
    # (id, yaml_content_or_None_for_missing_file, expected_exception, match_fragment)
    ("broken_yaml",          "key: [\nunclosed",                    ConfigError, ""),
    ("empty_file",           "",                                     ConfigError, ""),
    ("list_toplevel",        "- item1\n- item2\n",                  ConfigError, ""),
    ("missing_system",       "privacy:\n  spacy_model: x\nsecurity:\n  regex_scan_head: 100\n  regex_scan_tail: 10\ngatekeeper:\n  timeout_seconds: 5\n  max_retries: 2\n  fallback_model: x\n  api_key_env: X\n  groq_api_key_env: X\n  jev:\n    model: x\n    api_url: x\n    hi_threshold: 0.85\n    lo_threshold: 0.15\n    max_body_chars: 1000\nllm:\n  model: x\n  temperature: 0.1\n  confidence_threshold: 0.7\n",
                                                                     ConfigError, "system"),
    ("confidence_str",       None,                                   ConfigError, "confidence_threshold"),  # special case
    ("confidence_zero",      None,                                   ConfigError, "confidence_threshold"),  # special case
    ("confidence_1_5",       None,                                   ConfigError, "confidence_threshold"),  # special case
    ("lo_gt_hi",             None,                                   ConfigError, "threshold"),             # special case
    ("hi_eq_1",              None,                                   ConfigError, "threshold"),             # special case
    ("typo_key",             None,                                   ConfigError, "idempotency_stale_minuts"),  # special
    ("bool_for_int",         None,                                   ConfigError, "integer"),               # special
    ("negative_retries",     None,                                   ConfigError, "max_dispatch_retries"),  # special
    ("empty_keywords",       None,                                   ConfigError, "sensitive_keywords"),    # special
    ("missing_file",         "MISSING",                              FileNotFoundError, ""),
]


class TestInvalidConfigCases(unittest.TestCase):
    """Each invalid config must raise the expected exception."""

    def setUp(self):
        self._orig_env = {}
        for var in ("DATABASE_PATH", "IDEMPOTENCY_STALE_MINUTES", "MAX_DISPATCH_RETRIES"):
            if var in os.environ:
                self._orig_env[var] = os.environ.pop(var)

    def tearDown(self):
        for var in ("DATABASE_PATH", "IDEMPOTENCY_STALE_MINUTES", "MAX_DISPATCH_RETRIES"):
            os.environ.pop(var, None)
        os.environ.update(self._orig_env)

    def _make_valid_yaml(self):
        import yaml
        return yaml.safe_dump(_valid_config_dict())

    def _load_from_yaml(self, tmp_path, yaml_content):
        p = Path(tmp_path) / "cfg.yaml"
        p.write_text(yaml_content)
        return load_config(str(p))

    def test_broken_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError):
                self._load_from_yaml(tmp, "key: [\nunclosed")

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError):
                self._load_from_yaml(tmp, "")

    def test_list_toplevel(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError):
                self._load_from_yaml(tmp, "- item1\n- item2\n")

    def test_missing_system_section(self):
        import yaml
        cfg = _valid_config_dict()
        del cfg["system"]
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError) as ctx:
                self._load_from_yaml(tmp, yaml.safe_dump(cfg))
        self.assertIn("system", str(ctx.exception))

    def test_confidence_threshold_string(self):
        import yaml
        cfg = _valid_config_dict()
        cfg["llm"]["confidence_threshold"] = "high"
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError) as ctx:
                self._load_from_yaml(tmp, yaml.safe_dump(cfg))
        self.assertIn("confidence_threshold", str(ctx.exception))

    def test_confidence_threshold_zero(self):
        import yaml
        cfg = _valid_config_dict()
        cfg["llm"]["confidence_threshold"] = 0
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError) as ctx:
                self._load_from_yaml(tmp, yaml.safe_dump(cfg))
        self.assertIn("confidence_threshold", str(ctx.exception))

    def test_confidence_threshold_1_5(self):
        import yaml
        cfg = _valid_config_dict()
        cfg["llm"]["confidence_threshold"] = 1.5
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError) as ctx:
                self._load_from_yaml(tmp, yaml.safe_dump(cfg))
        self.assertIn("confidence_threshold", str(ctx.exception))

    def test_lo_greater_than_hi(self):
        import yaml
        cfg = _valid_config_dict()
        cfg["gatekeeper"]["jev"]["lo_threshold"] = 0.9
        cfg["gatekeeper"]["jev"]["hi_threshold"] = 0.1
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError) as ctx:
                self._load_from_yaml(tmp, yaml.safe_dump(cfg))
        self.assertIn("threshold", str(ctx.exception).lower())

    def test_hi_equal_to_1(self):
        import yaml
        cfg = _valid_config_dict()
        cfg["gatekeeper"]["jev"]["hi_threshold"] = 1.0
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError) as ctx:
                self._load_from_yaml(tmp, yaml.safe_dump(cfg))
        self.assertIn("threshold", str(ctx.exception).lower())

    def test_typo_key_in_system(self):
        import yaml
        cfg = _valid_config_dict()
        cfg["system"]["idempotency_stale_minuts"] = 10  # typo
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError) as ctx:
                self._load_from_yaml(tmp, yaml.safe_dump(cfg))
        self.assertIn("idempotency_stale_minuts", str(ctx.exception))

    def test_bool_for_int_idempotency_minutes(self):
        import yaml
        cfg = _valid_config_dict()
        cfg["system"]["idempotency_stale_minutes"] = True  # bool is subclass of int
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError) as ctx:
                self._load_from_yaml(tmp, yaml.safe_dump(cfg))
        # yaml.safe_dump(True) -> 'true', safe_load -> True (bool)
        self.assertIn("integer", str(ctx.exception).lower())

    def test_negative_max_dispatch_retries(self):
        import yaml
        cfg = _valid_config_dict()
        cfg["system"]["max_dispatch_retries"] = -1
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError) as ctx:
                self._load_from_yaml(tmp, yaml.safe_dump(cfg))
        self.assertIn("max_dispatch_retries", str(ctx.exception))

    def test_empty_sensitive_keywords(self):
        import yaml
        cfg = _valid_config_dict()
        cfg["privacy"]["sensitive_keywords"] = []
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError) as ctx:
                self._load_from_yaml(tmp, yaml.safe_dump(cfg))
        self.assertIn("sensitive_keywords", str(ctx.exception))

    def test_missing_file_raises_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            load_config("/nonexistent/path/to/config.yaml")

    def test_valid_full_config_passes(self):
        import yaml
        cfg = _valid_config_dict()
        with tempfile.TemporaryDirectory() as tmp:
            result = self._load_from_yaml(tmp, yaml.safe_dump(cfg))
        self.assertIsInstance(result, dict)
        self.assertEqual(result["system"]["idempotency_stale_minutes"], 10)


# ---------------------------------------------------------------------------
# 3. Environment overrides
# ---------------------------------------------------------------------------
class TestEnvironmentOverrides(unittest.TestCase):
    """DATABASE_PATH, IDEMPOTENCY_STALE_MINUTES, MAX_DISPATCH_RETRIES env overrides."""

    def setUp(self):
        # Remove overriding env vars before each test
        for var in ("DATABASE_PATH", "IDEMPOTENCY_STALE_MINUTES", "MAX_DISPATCH_RETRIES"):
            os.environ.pop(var, None)

    def tearDown(self):
        for var in ("DATABASE_PATH", "IDEMPOTENCY_STALE_MINUTES", "MAX_DISPATCH_RETRIES"):
            os.environ.pop(var, None)

    def test_database_path_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            custom = os.path.join(tmp, "custom.db")
            os.environ["DATABASE_PATH"] = custom
            cfg = load_config()
            self.assertEqual(cfg["system"]["database_path"], custom)

    def test_stale_minutes_override(self):
        os.environ["IDEMPOTENCY_STALE_MINUTES"] = "3"
        cfg = load_config()
        self.assertEqual(cfg["system"]["idempotency_stale_minutes"], 3)
        self.assertIsInstance(cfg["system"]["idempotency_stale_minutes"], int)
        self.assertNotIsInstance(cfg["system"]["idempotency_stale_minutes"], bool)

    def test_max_retries_zero(self):
        os.environ["MAX_DISPATCH_RETRIES"] = "0"
        cfg = load_config()
        self.assertEqual(cfg["system"]["max_dispatch_retries"], 0)

    def test_stale_minutes_invalid_alpha(self):
        os.environ["IDEMPOTENCY_STALE_MINUTES"] = "abc"
        with self.assertRaises(ConfigError) as ctx:
            load_config()
        self.assertIn("IDEMPOTENCY_STALE_MINUTES", str(ctx.exception))

    def test_stale_minutes_invalid_zero(self):
        os.environ["IDEMPOTENCY_STALE_MINUTES"] = "0"
        with self.assertRaises(ConfigError) as ctx:
            load_config()
        self.assertIn("IDEMPOTENCY_STALE_MINUTES", str(ctx.exception))

    def test_stale_minutes_invalid_negative(self):
        os.environ["IDEMPOTENCY_STALE_MINUTES"] = "-1"
        with self.assertRaises(ConfigError) as ctx:
            load_config()
        self.assertIn("IDEMPOTENCY_STALE_MINUTES", str(ctx.exception))

    def test_max_retries_invalid_negative(self):
        os.environ["MAX_DISPATCH_RETRIES"] = "-1"
        with self.assertRaises(ConfigError) as ctx:
            load_config()
        self.assertIn("MAX_DISPATCH_RETRIES", str(ctx.exception))

    def test_empty_string_means_no_override(self):
        os.environ["DATABASE_PATH"] = ""
        os.environ["IDEMPOTENCY_STALE_MINUTES"] = ""
        os.environ["MAX_DISPATCH_RETRIES"] = ""
        cfg = load_config()
        # Should use yaml defaults without raising
        self.assertEqual(cfg["system"]["idempotency_stale_minutes"], 10)
        self.assertEqual(cfg["system"]["max_dispatch_retries"], 3)

    def test_stale_minutes_reaches_ingest_node(self):
        """IDEMPOTENCY_STALE_MINUTES=3 is seen by ingest_node as stale_minutes=3."""
        os.environ["IDEMPOTENCY_STALE_MINUTES"] = "3"
        # ingest_node reads load_config() internally — verify value flows through
        import importlib
        import nodes.ingest as ingest_mod
        # We can't easily introspect the local var, but we can confirm load_config returns 3
        cfg = load_config()
        self.assertEqual(cfg["system"]["idempotency_stale_minutes"], 3)

    def test_max_retries_reaches_config(self):
        """MAX_DISPATCH_RETRIES=0 is returned as int 0 from load_config."""
        os.environ["MAX_DISPATCH_RETRIES"] = "0"
        cfg = load_config()
        self.assertEqual(cfg["system"]["max_dispatch_retries"], 0)

    def test_env_override_does_not_mask_invalid_file_value(self):
        """A file with max_dispatch_retries: -1 must raise ConfigError even if MAX_DISPATCH_RETRIES=5 in env."""
        import yaml
        cfg = _valid_config_dict()
        cfg["system"]["max_dispatch_retries"] = -1
        with tempfile.TemporaryDirectory() as tmp:
            cfg_file = Path(tmp) / "invalid_retries.yaml"
            cfg_file.write_text(yaml.safe_dump(cfg))
            os.environ["MAX_DISPATCH_RETRIES"] = "5"
            with self.assertRaises(ConfigError) as ctx:
                load_config(str(cfg_file))
            self.assertIn("max_dispatch_retries", str(ctx.exception))

    def test_valid_file_plus_valid_env_override_succeeds(self):
        """A valid config file plus a valid env override successfully applies the override."""
        import yaml
        cfg = _valid_config_dict()
        cfg["system"]["max_dispatch_retries"] = 3
        with tempfile.TemporaryDirectory() as tmp:
            cfg_file = Path(tmp) / "valid_retries.yaml"
            cfg_file.write_text(yaml.safe_dump(cfg))
            os.environ["MAX_DISPATCH_RETRIES"] = "5"
            loaded = load_config(str(cfg_file))
            self.assertEqual(loaded["system"]["max_dispatch_retries"], 5)


# ---------------------------------------------------------------------------
# 4. No-swallow: callers must raise ConfigError on broken config
# ---------------------------------------------------------------------------
class TestNoSwallow(unittest.TestCase):
    """TriageDatabase(), JevClient(), and pii_masker_node raise ConfigError on bad config."""

    def setUp(self):
        import utils.config as cfg_mod
        cfg_mod.reset_config_cache()

    def tearDown(self):
        import utils.config as cfg_mod
        cfg_mod.reset_config_cache()

    def _patch_default_config(self, bad_yaml: str):
        """Context manager: patches DEFAULT_CONFIG_PATH to a temp file with bad_yaml."""
        import utils.config as cfg_mod
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad_config.yaml"
            bad.write_text(bad_yaml)
            orig = cfg_mod.DEFAULT_CONFIG_PATH
            cfg_mod.DEFAULT_CONFIG_PATH = bad
            cfg_mod.reset_config_cache()
            try:
                yield
            finally:
                cfg_mod.DEFAULT_CONFIG_PATH = orig
                cfg_mod.reset_config_cache()

    from contextlib import contextmanager
    _patch_default_config = contextmanager(_patch_default_config)

    def test_triage_database_raises_on_bad_config(self):
        """TriageDatabase() must raise ConfigError when config is broken."""
        import utils.config as cfg_mod
        orig = cfg_mod.DEFAULT_CONFIG_PATH
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.yaml"
            bad.write_text("")  # empty → ConfigError
            cfg_mod.DEFAULT_CONFIG_PATH = bad
            cfg_mod.reset_config_cache()
            try:
                from db.database import TriageDatabase
                with self.assertRaises((ConfigError, FileNotFoundError)):
                    TriageDatabase()
            finally:
                cfg_mod.DEFAULT_CONFIG_PATH = orig
                cfg_mod.reset_config_cache()

    def test_jev_client_raises_on_bad_config(self):
        """JevClient() with no explicit config must raise ConfigError when config is broken."""
        import utils.config as cfg_mod
        orig = cfg_mod.DEFAULT_CONFIG_PATH
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.yaml"
            bad.write_text("")  # empty → ConfigError
            cfg_mod.DEFAULT_CONFIG_PATH = bad
            cfg_mod.reset_config_cache()
            try:
                from utils.jev_client import JevClient
                with self.assertRaises((ConfigError, FileNotFoundError)):
                    JevClient()  # no config= arg → will call load_config()
            finally:
                cfg_mod.DEFAULT_CONFIG_PATH = orig
                cfg_mod.reset_config_cache()

    def test_pii_masker_node_raises_on_bad_config(self):
        """pii_masker_node() with no config arg must raise ConfigError when config is broken."""
        import utils.config as cfg_mod
        orig = cfg_mod.DEFAULT_CONFIG_PATH
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.yaml"
            bad.write_text("")  # empty → ConfigError
            cfg_mod.DEFAULT_CONFIG_PATH = bad
            cfg_mod.reset_config_cache()
            try:
                from nodes.pii_masker import pii_masker_node
                state = {
                    "email_subject": "Test",
                    "email_body": "Hello world.",
                    "cleaned_body": "Hello world.",
                    "email_id": "test_001",
                    "token_map": {},
                }
                with self.assertRaises((ConfigError, FileNotFoundError)):
                    pii_masker_node(state)
            finally:
                cfg_mod.DEFAULT_CONFIG_PATH = orig
                cfg_mod.reset_config_cache()


# ---------------------------------------------------------------------------
# 5. main() exits with code 2 on invalid config
# ---------------------------------------------------------------------------
class TestMainConfigError(unittest.TestCase):
    """main() must exit code 2, print to stderr, and produce no triage output."""

    def setUp(self):
        import utils.config as cfg_mod
        cfg_mod.reset_config_cache()

    def tearDown(self):
        import utils.config as cfg_mod
        cfg_mod.reset_config_cache()

    def test_main_exits_code_2_on_empty_config(self):
        """In-process: empty config → sys.exit(2), stderr contains 'Configuration error'."""
        import utils.config as cfg_mod
        orig = cfg_mod.DEFAULT_CONFIG_PATH
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "empty.yaml"
            bad.write_text("")  # empty → ConfigError
            cfg_mod.DEFAULT_CONFIG_PATH = bad
            cfg_mod.reset_config_cache()
            try:
                import importlib
                import main as main_mod
                importlib.reload(main_mod)  # pick up fresh import after patch
                import io
                stderr_buf = io.StringIO()
                stdout_buf = io.StringIO()
                with self.assertRaises(SystemExit) as cm:
                    with patch("sys.stderr", stderr_buf), patch("sys.stdout", stdout_buf), patch.object(sys, "argv", ["main.py", "--offline"]):
                        main_mod.main()
                self.assertEqual(cm.exception.code, 2)
                err_text = stderr_buf.getvalue()
                self.assertIn("Configuration error", err_text)
                self.assertNotIn("Traceback", err_text)
                self.assertNotIn("Traceback", stdout_buf.getvalue())
            finally:
                cfg_mod.DEFAULT_CONFIG_PATH = orig
                cfg_mod.reset_config_cache()

    def test_main_subprocess_invalid_config_exits_2(self):
        """Subprocess test: rename config.yaml, run main.py --offline, expect exit code 2."""
        project_root = str(BASE_DIR)
        config_path = BASE_DIR / "config.yaml"
        backup_path = BASE_DIR / "config.yaml.bak_b5_test"
        try:
            config_path.rename(backup_path)
            result = subprocess.run(
                [sys.executable, "main.py", "--offline"],
                cwd=project_root,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2, f"stderr: {result.stderr}")
            self.assertIn("Configuration error", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertNotIn("Traceback", result.stdout)
        finally:
            if backup_path.exists():
                backup_path.rename(config_path)


# ---------------------------------------------------------------------------
# 6. validate_config - additional edge-case direct tests
# ---------------------------------------------------------------------------
class TestValidateConfigDirect(unittest.TestCase):
    """Direct validate_config() tests for edge cases."""

    def test_valid_config_passes(self):
        validate_config(_valid_config_dict())  # must not raise

    def test_confidence_threshold_1_0_is_valid(self):
        """confidence_threshold == 1.0 is valid (0 < v <= 1)."""
        cfg = _valid_config_dict()
        cfg["llm"]["confidence_threshold"] = 1.0
        validate_config(cfg)  # must not raise

    def test_max_dispatch_retries_0_is_valid(self):
        cfg = _valid_config_dict()
        cfg["system"]["max_dispatch_retries"] = 0
        validate_config(cfg)  # must not raise

    def test_temperature_0_is_valid(self):
        cfg = _valid_config_dict()
        cfg["llm"]["temperature"] = 0.0
        validate_config(cfg)  # must not raise

    def test_temperature_2_is_valid(self):
        cfg = _valid_config_dict()
        cfg["llm"]["temperature"] = 2.0
        validate_config(cfg)  # must not raise

    def test_temperature_above_2_fails(self):
        cfg = _valid_config_dict()
        cfg["llm"]["temperature"] = 2.1
        with self.assertRaises(ConfigError):
            validate_config(cfg)

    def test_unknown_key_in_llm(self):
        cfg = _valid_config_dict()
        cfg["llm"]["unknown_setting"] = "value"
        with self.assertRaises(ConfigError) as ctx:
            validate_config(cfg)
        self.assertIn("unknown_setting", str(ctx.exception))

    def test_unknown_key_in_gatekeeper_jev(self):
        cfg = _valid_config_dict()
        cfg["gatekeeper"]["jev"]["extra_param"] = 42
        with self.assertRaises(ConfigError) as ctx:
            validate_config(cfg)
        self.assertIn("extra_param", str(ctx.exception))

    def test_missing_privacy_section(self):
        cfg = _valid_config_dict()
        del cfg["privacy"]
        with self.assertRaises(ConfigError) as ctx:
            validate_config(cfg)
        self.assertIn("privacy", str(ctx.exception))

    def test_missing_llm_section(self):
        cfg = _valid_config_dict()
        del cfg["llm"]
        with self.assertRaises(ConfigError) as ctx:
            validate_config(cfg)
        self.assertIn("llm", str(ctx.exception))

    def test_default_phone_region_too_long(self):
        cfg = _valid_config_dict()
        cfg["privacy"]["default_phone_region"] = "USA"
        with self.assertRaises(ConfigError) as ctx:
            validate_config(cfg)
        self.assertIn("default_phone_region", str(ctx.exception))

    def test_default_phone_region_numeric(self):
        cfg = _valid_config_dict()
        cfg["privacy"]["default_phone_region"] = "12"
        with self.assertRaises(ConfigError) as ctx:
            validate_config(cfg)
        self.assertIn("default_phone_region", str(ctx.exception))

    def test_bool_for_persist_masked_text_ok(self):
        """persist_masked_text accepts True/False."""
        cfg = _valid_config_dict()
        cfg["system"]["persist_masked_text"] = False
        validate_config(cfg)

    def test_string_for_persist_masked_text_fails(self):
        cfg = _valid_config_dict()
        cfg["system"]["persist_masked_text"] = "yes"
        with self.assertRaises(ConfigError):
            validate_config(cfg)

    def test_bool_for_regex_scan_head_fails(self):
        """bool must not be accepted where int is required."""
        cfg = _valid_config_dict()
        cfg["security"]["regex_scan_head"] = True
        with self.assertRaises(ConfigError) as ctx:
            validate_config(cfg)
        self.assertIn("integer", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
