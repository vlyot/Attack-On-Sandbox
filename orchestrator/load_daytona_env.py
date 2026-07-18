"""
Reads auth credentials from the Daytona CLI config file and prints shell
export statements, or sets them directly in os.environ when imported.

Usage (shell):
    eval "$(python orchestrator/load_daytona_env.py)"

Usage (Python):
    from orchestrator.load_daytona_env import inject_env
    inject_env()
"""

from __future__ import annotations

import json
import os
from pathlib import Path

_CONFIG_PATH = Path.home() / "AppData" / "Roaming" / "daytona" / "config.json"


def _read_credentials() -> dict[str, str]:
    if not _CONFIG_PATH.exists():
        raise FileNotFoundError(f"Daytona config not found at {_CONFIG_PATH}")

    with _CONFIG_PATH.open() as fh:
        cfg = json.load(fh)

    profile = cfg["profiles"][0]
    token = profile["api"]["token"]["accessToken"]
    org_id = profile["activeOrganizationId"]

    return {
        "DAYTONA_JWT_TOKEN": token,
        "DAYTONA_ORGANIZATION_ID": org_id,
        "DAYTONA_API_URL": "https://app.daytona.io/api",
    }


def inject_env() -> None:
    """Set Daytona credentials in os.environ (call before importing daytona_client)."""
    for key, value in _read_credentials().items():
        os.environ.setdefault(key, value)


if __name__ == "__main__":
    creds = _read_credentials()
    for key, value in creds.items():
        print(f'export {key}="{value}"')
