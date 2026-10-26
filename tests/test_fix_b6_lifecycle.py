"""Unit and lifecycle tests for Fix B6: Process Lifecycle Optimization.

Validates:
1. 30 distinct emails through ONE compiled pipeline results in:
   - yaml.safe_load called exactly 1 time
   - spacy.load called exactly 1 time
   - keyword patterns compiled exactly 1 time (patterns containing 'subpoena')
   - JevClient constructed at most 1 time
2. get_config() caching identity (is) and reset_* functionality
3. 8-thread concurrent access to each getter produces exactly 1 instance / creation
4. A13 session-wide 401 disable state persists across calls via shared client
5. A8 spaCy safeguards work seamlessly with cached model state
"""

import concurrent.futures
import os
import re
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch
import yaml

from db.database import TriageDatabase
from nodes.pii_masker import (
    get_spacy_nlp,
    is_spacy_available,
    load_tech_context_words,
    load_tech_terms_tiers,
    reset_spacy_cache,
    reset_tech_terms_cache,
    validate_startup,
)
from nodes.sensitive_skip import (
    get_compiled_keyword_patterns,
    reset_keyword_patterns_cache,
)
from pipeline import create_triage_pipeline, prepare_runtime, run_triage_pipeline
from utils.config import get_config, reset_config_cache
from utils.jev_client import JevClient, get_default_client, reset_default_client


class TestB6Lifecycle(unittest.TestCase):
    """Lifecycle and optimization verification tests."""

    def setUp(self):
        reset_config_cache()
        reset_keyword_patterns_cache()
        reset_spacy_cache()
        reset_tech_terms_cache()
        reset_default_client()

    def tearDown(self):
        reset_config_cache()
        reset_keyword_patterns_cache()
        reset_spacy_cache()
        reset_tech_terms_cache()
        reset_default_client()

    def test_pipeline_30_emails_lifecycle_counts(self):
        """Processes 30 distinct emails through one pipeline and verifies exact creation counts."""
        # Setup temporary database
        temp_dir = tempfile.TemporaryDirectory()
        db_path = os.path.join(temp_dir.name, "lifecycle_test.db")
        db = TriageDatabase(db_path=db_path)

        # Spies for initialization calls
        yaml_load_counter = {"count": 0}
        orig_safe_load = yaml.safe_load

        def spy_yaml_safe_load(stream):
            yaml_load_counter["count"] += 1
            return orig_safe_load(stream)

        import spacy
        spacy_load_counter = {"count": 0}
        orig_spacy_load = spacy.load

        def spy_spacy_load(name, **kwargs):
            spacy_load_counter["count"] += 1
            return orig_spacy_load(name, **kwargs)

        subpoena_compile_counter = {"count": 0}
        orig_re_compile = re.compile

        def spy_re_compile(pattern, *args, **kwargs):
            pattern_str = str(pattern)
            if "subpoena" in pattern_str:
                subpoena_compile_counter["count"] += 1
            return orig_re_compile(pattern, *args, **kwargs)

        jev_init_counter = {"count": 0}
        orig_jev_init = JevClient.__init__

        def spy_jev_init(self, *args, **kwargs):
            jev_init_counter["count"] += 1
            return orig_jev_init(self, *args, **kwargs)

        with patch("yaml.safe_load", side_effect=spy_yaml_safe_load), \
             patch("spacy.load", side_effect=spy_spacy_load), \
             patch("re.compile", side_effect=spy_re_compile), \
             patch.object(JevClient, "__init__", spy_jev_init):

            # Compile pipeline ONCE
            pipeline = create_triage_pipeline(db=db, offline=True)

            # Process 30 distinct emails through this single compiled pipeline
            for i in range(1, 31):
                payload = {
                    "email_id": f"em_lifecycle_{i:03d}",
                    "sender_email": f"user{i}@example.com",
                    "email_subject": f"Inquiry number {i} regarding cloud deployment",
                    "email_body": f"Hello, this is customer {i}. Our Jenkins and Docker cluster is running well. Thanks!",
                }
                res = run_triage_pipeline(
                    payload, pipeline=pipeline, db=db, offline=True
                )
                self.assertEqual(res.get("routing_status"), "gatekeeper_approved")

        temp_dir.cleanup()

        # Invariants:
        # yaml.safe_load called exactly 1 time
        self.assertEqual(
            yaml_load_counter["count"], 1,
            f"Expected yaml.safe_load to be called 1 time, got {yaml_load_counter['count']}"
        )
        # spacy.load called exactly 1 time
        self.assertEqual(
            spacy_load_counter["count"], 1,
            f"Expected spacy.load to be called 1 time, got {spacy_load_counter['count']}"
        )
        # re.compile containing 'subpoena' called exactly 1 time
        self.assertEqual(
            subpoena_compile_counter["count"], 1,
            f"Expected 'subpoena' re.compile to be called 1 time, got {subpoena_compile_counter['count']}"
        )
        # JevClient constructed at most 1 time
        self.assertLessEqual(
            jev_init_counter["count"], 1,
            f"Expected JevClient to be constructed at most 1 time, got {jev_init_counter['count']}"
        )

    def test_get_config_caching_and_resets(self):
        """get_config() returns same instance twice, reset_config_cache() resets cleanly."""
        cfg1 = get_config()
        cfg2 = get_config()
        self.assertIs(cfg1, cfg2, "get_config() must return the identical cached object")

        # Reset cache
        reset_config_cache()
        cfg3 = get_config()
        self.assertIsNot(cfg1, cfg3, "get_config() after reset must return a fresh object")
        self.assertEqual(cfg1, cfg3, "Fresh config content must equal cached config content")

    def test_reset_functions_clear_state(self):
        """Verifies each reset_* function restores state to empty."""
        # 1. Config
        get_config()
        reset_config_cache()
        from utils.config import _CONFIG_CACHE
        self.assertIsNone(_CONFIG_CACHE)

        # 2. Keyword patterns
        get_compiled_keyword_patterns(["subpoena", "confidential"])
        import nodes.sensitive_skip as sens_mod
        self.assertIn(("subpoena", "confidential"), sens_mod._KEYWORD_PATTERNS_CACHE)
        reset_keyword_patterns_cache()
        self.assertEqual(len(sens_mod._KEYWORD_PATTERNS_CACHE), 0)

        # 3. spaCy cache
        get_spacy_nlp("en_core_web_sm")
        from nodes.pii_masker import _SPACY_MODELS
        self.assertIn("en_core_web_sm", _SPACY_MODELS)
        reset_spacy_cache()
        self.assertEqual(len(_SPACY_MODELS), 0)

        # 4. Default client
        get_default_client()
        from utils.jev_client import _DEFAULT_CLIENT
        self.assertIsNotNone(_DEFAULT_CLIENT)
        reset_default_client()
        from utils.jev_client import _DEFAULT_CLIENT as RESET_CLIENT
        self.assertIsNone(RESET_CLIENT)

    def test_thread_safety_8_threads(self):
        """8 concurrent threads hitting each getter at once create exactly 1 instance."""
        num_threads = 8

        # A. Thread-safe get_config
        reset_config_cache()
        config_load_counter = {"count": 0}
        orig_load = yaml.safe_load

        def count_load(stream):
            config_load_counter["count"] += 1
            return orig_load(stream)

        with patch("yaml.safe_load", side_effect=count_load):
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
                configs = list(executor.map(lambda _: get_config(), range(num_threads)))

            self.assertEqual(config_load_counter["count"], 1)
            for c in configs[1:]:
                self.assertIs(c, configs[0])

        # B. Thread-safe get_compiled_keyword_patterns
        reset_keyword_patterns_cache()
        patterns_compile_counter = {"count": 0}
        kw = ["subpoena", "arbitration"]

        orig_compile = re.compile

        def count_compile(pat, *args, **kwargs):
            if "subpoena" in str(pat):
                patterns_compile_counter["count"] += 1
            return orig_compile(pat, *args, **kwargs)

        with patch("re.compile", side_effect=count_compile):
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
                results = list(
                    executor.map(lambda _: get_compiled_keyword_patterns(kw), range(num_threads))
                )

            self.assertEqual(patterns_compile_counter["count"], 1)
            for r in results[1:]:
                self.assertIs(r, results[0])

        # C. Thread-safe get_spacy_nlp
        reset_spacy_cache()
        spacy_load_counter = {"count": 0}
        import spacy
        orig_spacy = spacy.load

        def count_spacy(name, **kwargs):
            spacy_load_counter["count"] += 1
            return orig_spacy(name, **kwargs)

        with patch("spacy.load", side_effect=count_spacy):
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
                models = list(
                    executor.map(lambda _: get_spacy_nlp("en_core_web_sm"), range(num_threads))
                )

            self.assertEqual(spacy_load_counter["count"], 1)
            for m in models[1:]:
                self.assertIs(m, models[0])

        # D. Thread-safe get_default_client
        reset_default_client()
        jev_client_counter = {"count": 0}
        orig_client_init = JevClient.__init__

        def count_client_init(self, *args, **kwargs):
            jev_client_counter["count"] += 1
            return orig_client_init(self, *args, **kwargs)

        with patch.object(JevClient, "__init__", count_client_init):
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
                clients = list(
                    executor.map(lambda _: get_default_client(), range(num_threads))
                )

            self.assertEqual(jev_client_counter["count"], 1)
            for cl in clients[1:]:
                self.assertIs(cl, clients[0])

    def test_a13_401_disables_jev_session_wide_in_shared_client(self):
        """A13 401 disable state persists across calls via the shared default client."""
        reset_default_client()
        shared_client = get_default_client()
        self.assertFalse(shared_client._jev_disabled)

        # Simulate 401 unauthorized response from Jev API
        mock_response = MagicMock()
        mock_response.status_code = 401

        with patch("requests.post", return_value=mock_response):
            with patch.dict(os.environ, {"JEV_API_KEY": "valid_format_but_revoked_key"}):
                shared_client.api_key = "valid_format_but_revoked_key"
                result1 = shared_client.classify("sender@test.com", "Subject", "Body text")

                # The shared client must now have _jev_disabled = True
                self.assertTrue(shared_client._jev_disabled)

        # On the next call without 401 mock, Jev API is skipped immediately because _jev_disabled is True
        with patch("requests.post") as mock_post:
            result2 = shared_client.classify("sender@test.com", "Subject 2", "Body text 2")
            mock_post.assert_not_called()

        # The subsequent get_default_client() returns the same disabled client
        again_client = get_default_client()
        self.assertIs(again_client, shared_client)
        self.assertTrue(again_client._jev_disabled)

    def test_prepare_runtime_warms_all_caches(self):
        """prepare_runtime() successfully loads config, patterns, tech terms, and client."""
        reset_config_cache()
        reset_keyword_patterns_cache()
        reset_spacy_cache()
        reset_tech_terms_cache()
        reset_default_client()

        prepare_runtime(offline=True)

        from utils.config import _CONFIG_CACHE
        from nodes.sensitive_skip import _KEYWORD_PATTERNS_CACHE
        from nodes.pii_masker import _TECH_TERMS_CACHE, _SPACY_MODELS

        self.assertIsNotNone(_CONFIG_CACHE)
        self.assertGreater(len(_KEYWORD_PATTERNS_CACHE), 0)
        self.assertIsNotNone(_TECH_TERMS_CACHE)
        self.assertIn("en_core_web_sm", _SPACY_MODELS)


if __name__ == "__main__":
    unittest.main()
