"""Configuration loader and environment secret resolver.

Follows the strict *_env pattern to ensure zero secrets are stored in
plaintext config files.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional
import yaml
from dotenv import load_dotenv

# Automatically load environment variables from .env if present
load_dotenv(override=True)


def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """Loads and returns the YAML configuration file.

    Args:
        config_path: Path to the YAML configuration file.

    Returns:
        Dict containing parsed configuration.

    Raises:
        FileNotFoundError: If the configuration file is not found.
        yaml.YAMLError: If the YAML file contains invalid syntax.
    """
    path = Path(config_path)
    if not path.is_file():
        raise FileNotFoundError(f"Configuration file not found at: {config_path}")

    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    return config or {}


def get_env_var(
    var_name: Optional[str], default: Optional[str] = None
) -> Optional[str]:
    """Retrieves an environment variable by name.

    Args:
        var_name: Name of the environment variable.
        default: Default value if the environment variable is not set.

    Returns:
        The environment variable value or the default.
    """
    if not var_name:
        return default
    return os.environ.get(var_name, default)


def resolve_destination_config(
    team_name: str,
    config: Optional[Dict[str, Any]] = None,
    config_path: str = "config.yaml",
) -> Optional[Dict[str, Any]]:
    """Retrieves and resolves credentials for a specific destination team.

    Replaces any `*_env` field with its corresponding live environment variable
    value. For example, if destination config contains `token_env: GITHUB_TOKEN`,
    the returned dict will include `resolved_token: <value_of_GITHUB_TOKEN>`.

    Args:
        team_name: Name of the team (e.g., 'Engineering', 'Support', 'Sales', 'Billing').
        config: Optional pre-loaded config dict. If None, loaded from config_path.
        config_path: Path to config.yaml if config is None.

    Returns:
        Resolved destination dict or None if team is not configured.
    """
    if config is None:
        config = load_config(config_path)

    destinations = config.get("destinations", {})
    team_config = destinations.get(team_name)
    if not team_config:
        return None

    resolved = dict(team_config)
    # Automatically resolve any *_env fields to live environment secrets
    for key, value in team_config.items():
        if key.endswith("_env") and isinstance(value, str):
            secret_key = key[:-4]  # e.g., 'token_env' -> 'token'
            resolved[f"resolved_{secret_key}"] = get_env_var(value)

    return resolved
