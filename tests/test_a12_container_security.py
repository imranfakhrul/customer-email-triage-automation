"""Unit tests for Fix A12: Container Security & Environment File Locations.

Validates that:
1. Dockerfile specifies non-root user creation (appuser with UID 1000) and USER appuser.
2. docker-compose.yml mounts only ./data:/app/data and does not mount the entire repository.
3. .dockerignore excludes SQLite database files (*.db, *.db-wal, *.db-shm).
4. README.md specifies secure chown -R 1000:1000 data rather than insecure chmod 777.
5. DATABASE_PATH environment override correctly resolves and configures the database location.
"""

import os
from pathlib import Path
import unittest
from unittest.mock import patch
import yaml

from utils.config import BASE_DIR, get_config, reset_config_cache


class TestA12ContainerSecurity(unittest.TestCase):
    """Verifies container security hardening and configuration invariants."""

    def test_dockerfile_creates_and_switches_to_non_root_user(self):
        """Dockerfile must create appuser (UID 1000) and switch to USER appuser before CMD."""
        dockerfile_path = BASE_DIR / "Dockerfile"
        self.assertTrue(dockerfile_path.exists(), "Dockerfile must exist")
        content = dockerfile_path.read_text(encoding="utf-8")

        self.assertIn("useradd", content)
        self.assertIn("appuser", content)
        self.assertIn("USER appuser", content)

        # Invariant: USER appuser must precede CMD
        user_idx = content.find("USER appuser")
        cmd_idx = content.find("CMD")
        self.assertGreater(user_idx, 0)
        self.assertGreater(cmd_idx, user_idx, "USER appuser must be set before CMD")

    def test_docker_compose_mounts_data_only(self):
        """docker-compose.yml must mount only ./data:/app/data and omit full repository mount."""
        compose_path = BASE_DIR / "docker-compose.yml"
        self.assertTrue(compose_path.exists(), "docker-compose.yml must exist")
        with open(compose_path, "r", encoding="utf-8") as f:
            compose_cfg = yaml.safe_load(f)

        services = compose_cfg.get("services", {})
        self.assertIn("email-triage", services)
        service = services["email-triage"]

        volumes = service.get("volumes", [])
        # Must contain ./data:/app/data
        self.assertIn("./data:/app/data", volumes)

        # Must NOT contain whole repository mounts like ./:/app or .:/app
        for v in volumes:
            mount_src = v.split(":")[0].strip()
            self.assertNotIn(mount_src, (".", "./"), "docker-compose must not mount entire repository read-write")

        # Invariant: DATABASE_PATH points to /app/data/triage.db
        env_vars = service.get("environment", [])
        has_db_path = any("DATABASE_PATH=/app/data/triage.db" in str(e) for e in env_vars)
        self.assertTrue(has_db_path, "docker-compose must set DATABASE_PATH=/app/data/triage.db")

    def test_dockerignore_excludes_sqlite_databases(self):
        """.dockerignore must exclude *.db, *.db-wal, *.db-shm to avoid baking host databases into images."""
        dockerignore_path = BASE_DIR / ".dockerignore"
        self.assertTrue(dockerignore_path.exists(), ".dockerignore must exist")
        content = dockerignore_path.read_text(encoding="utf-8")

        self.assertIn("*.db", content)
        self.assertIn("*.db-wal", content)
        self.assertIn("*.db-shm", content)

    def test_readme_advises_chown_instead_of_chmod_777(self):
        """README.md must advise chown -R 1000:1000 data and never recommend chmod 777."""
        readme_path = BASE_DIR / "README.md"
        content = readme_path.read_text(encoding="utf-8")

        self.assertNotIn("chmod 777 data", content, "chmod 777 data must be removed from documentation")
        self.assertIn("chown -R 1000:1000 data", content, "README must advise chown -R 1000:1000 data")

    def test_database_path_env_var_applied_in_runtime_config(self):
        """Runtime get_config() must honor DATABASE_PATH environment override."""
        reset_config_cache()
        test_custom_db = "data/custom_triage.db"
        with patch.dict(os.environ, {"DATABASE_PATH": test_custom_db}):
            cfg = get_config()
            expected_abs = str((BASE_DIR / test_custom_db).resolve())
            self.assertEqual(cfg["system"]["database_path"], expected_abs)
        reset_config_cache()

    def test_docker_compose_restart_policy_is_no(self):
        """docker-compose.yml must specify restart: 'no' since Phase 1 executes as a batch job."""
        compose_path = BASE_DIR / "docker-compose.yml"
        self.assertTrue(compose_path.exists(), "docker-compose.yml must exist")
        with open(compose_path, "r", encoding="utf-8") as f:
            compose_cfg = yaml.safe_load(f)

        service = compose_cfg.get("services", {}).get("email-triage", {})
        restart_policy = str(service.get("restart", "")).lower()
        self.assertIn(restart_policy, ("no", "false"), "docker-compose restart policy must be 'no'")

