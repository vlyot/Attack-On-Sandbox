"""
Daytona sandbox lifecycle wrapper for Attack on Sandbox.

All sandbox operations go through this module — the orchestrator never
imports daytona_sdk directly. Functions are synchronous; the SDK uses
a sync API under the hood.

Auth: reads DAYTONA_JWT_TOKEN + DAYTONA_ORGANIZATION_ID from the environment
(set these from the Daytona config file or CI secrets).
"""

from __future__ import annotations

import os
import ssl
import time
import urllib.error
import urllib.request
import warnings
from pathlib import Path

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    from daytona_sdk import Daytona, DaytonaConfig
    from daytona_sdk.common.daytona import CreateSandboxFromSnapshotParams
    from daytona_sdk.common.process import SessionExecuteRequest

# ---------------------------------------------------------------------------
# Client singleton — initialised once at import time.
# Reads DAYTONA_JWT_TOKEN + DAYTONA_ORGANIZATION_ID from env.
# ---------------------------------------------------------------------------

def _make_client() -> Daytona:
    jwt = os.environ.get("DAYTONA_JWT_TOKEN")
    org = os.environ.get("DAYTONA_ORGANIZATION_ID")
    api_url = os.environ.get("DAYTONA_API_URL", "https://app.daytona.io/api")

    if not jwt or not org:
        raise EnvironmentError(
            "DAYTONA_JWT_TOKEN and DAYTONA_ORGANIZATION_ID must be set. "
            "Run: python orchestrator/load_daytona_env.py to populate them from the CLI config."
        )

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return Daytona(DaytonaConfig(jwt_token=jwt, organization_id=org, api_url=api_url))


_client: Daytona | None = None


def _get_client() -> Daytona:
    global _client
    if _client is None:
        _client = _make_client()
    return _client


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_REMOTE_APP_DIR = "/home/daytona/app"
_FLASK_PORT = 5000
_INSTALL_CMD = f"pip install -q -r {_REMOTE_APP_DIR}/requirements.txt"
_FLASK_SESSION_ID = "flask-server"
_START_CMD = f"python {_REMOTE_APP_DIR}/app.py"

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_sandbox() -> str:
    """Create a new public Daytona sandbox and return its ID.

    public=True makes the preview URL accessible without Auth0 — necessary
    for the orchestrator and dashboard to fire real HTTP requests against it.
    The sandbox starts empty — call deploy_app + start_app after this.
    """
    sandbox = _get_client().create(
        CreateSandboxFromSnapshotParams(public=True, auto_stop_interval=0)
    )
    return sandbox.id


def deploy_app(sandbox_id: str, source_dir: str) -> None:
    """Upload every file in source_dir into the sandbox at /home/daytona/app/.

    Skips directories, __pycache__, and *.pyc files. Preserves relative
    path structure so app.py and requirements.txt land in the right place.
    """
    sandbox = _get_client().get(sandbox_id)
    source = Path(source_dir)

    for file_path in sorted(source.rglob("*")):
        if file_path.is_dir():
            continue
        if "__pycache__" in file_path.parts:
            continue
        if file_path.suffix == ".pyc":
            continue

        relative = file_path.relative_to(source)
        remote_path = f"{_REMOTE_APP_DIR}/{relative.as_posix()}"
        content_bytes = file_path.read_bytes()
        sandbox.fs.upload_file(content_bytes, remote_path)


def start_app(sandbox_id: str) -> None:
    """Install dependencies and launch Flask as a background process.

    pip install runs synchronously with a long timeout (pip on a cold
    sandbox can take 2-3 minutes). Flask is launched via a persistent session
    so it keeps running after exec returns. Blocks until the health endpoint
    responds (up to 60s).
    """
    sandbox = _get_client().get(sandbox_id)
    sandbox.process.exec(_INSTALL_CMD, timeout=300)
    _launch_flask(sandbox)
    _wait_for_health(sandbox_id, timeout=60)


def get_sandbox_info(sandbox_id: str) -> dict:
    """Return {region, created_at, cpu, memory} for the sandbox_ready event payload.

    Sourced directly from the SDK's Sandbox object (sandbox.target is Daytona's
    name for what the dashboard displays as "region").
    """
    sandbox = _get_client().get(sandbox_id)
    return {
        "region": sandbox.target,
        "created_at": sandbox.created_at,
        "cpu": sandbox.cpu,
        "memory": sandbox.memory,
    }


def get_url(sandbox_id: str) -> str:
    """Return the public https:// preview URL for the running Flask service.

    The URL is suitable for real HTTP traffic — not localhost.
    """
    sandbox = _get_client().get(sandbox_id)
    preview = sandbox.get_preview_link(_FLASK_PORT)
    return preview.url


def upload_file(sandbox_id: str, remote_path: str, content: str) -> None:
    """Write a single file into the sandbox (UTF-8 encoded).

    Used by the orchestrator to push a patched app.py without redeploying
    the entire source tree.
    """
    sandbox = _get_client().get(sandbox_id)
    sandbox.fs.upload_file(content.encode("utf-8"), remote_path)


def restart_app(sandbox_id: str) -> None:
    """Kill the running Flask process and restart it.

    Uses pkill by process name — no PID tracking required. Blocks until
    the health endpoint responds again after restart.
    """
    sandbox = _get_client().get(sandbox_id)
    sandbox.process.exec("pkill -f app.py || true", timeout=10)
    # Delete the old session so the new one starts clean
    try:
        sandbox.process.delete_session(_FLASK_SESSION_ID)
    except Exception:
        pass
    time.sleep(1)
    _launch_flask(sandbox)
    _wait_for_health(sandbox_id, timeout=60)


def delete_sandbox(sandbox_id: str) -> None:
    """Tear down the sandbox. Always call this in a finally block."""
    client = _get_client()
    sandbox = client.get(sandbox_id)
    client.delete(sandbox)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _launch_flask(sandbox) -> None:
    """Launch Flask as a persistent async session command.

    Uses the session API with run_async=True so the SDK returns immediately
    without waiting for the process to exit. The session keeps Flask running
    after exec returns.
    """
    try:
        sandbox.process.create_session(_FLASK_SESSION_ID)
    except Exception:
        # Session may already exist from a previous start — that's fine.
        pass

    sandbox.process.execute_session_command(
        _FLASK_SESSION_ID,
        SessionExecuteRequest(command=_START_CMD, run_async=True),
    )


# Daytona preview proxy uses a wildcard cert that may not chain correctly
# on all systems. We skip SSL verification for health checks only.
_NO_SSL = ssl.create_default_context()
_NO_SSL.check_hostname = False
_NO_SSL.verify_mode = ssl.CERT_NONE


def _wait_for_health(sandbox_id: str, timeout: int = 30) -> None:
    """Poll GET / on the sandbox until Flask responds or timeout expires."""
    url = get_url(sandbox_id) + "/"
    deadline = time.time() + timeout
    last_error: Exception | None = None

    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3, context=_NO_SSL) as resp:
                if resp.status < 500:
                    return
        except urllib.error.HTTPError as exc:
            if exc.code < 500:
                return
            last_error = exc
        except Exception as exc:
            last_error = exc
        time.sleep(1)

    raise TimeoutError(
        f"Flask did not respond on {url} within {timeout}s. "
        f"Last error: {last_error}"
    )
