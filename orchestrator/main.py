"""
Attack on Sandbox — orchestrator entry point (Phase 5: live integration).

Runs the fixed adversarial loop with real streaming ai& API calls. In mock
mode (MOCK = True) the target app still runs as a local subprocess, exactly
as in Phase 4 — this keeps local dev/testing free and fast. In real mode
(MOCK = False) the target app runs in a live Daytona sandbox instead.

Usage:
    python orchestrator/main.py
"""

from __future__ import annotations

import difflib
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

load_dotenv()

from orchestrator.agents import attacker_agent, defender_agent
from orchestrator.events import (
    make_agent_thinking,
    make_attack_sent,
    make_iteration_complete,
    make_iteration_start,
    make_llm_usage,
    make_narration_chunk,
    make_patch_applied,
    make_sandbox_ready,
    make_stream_chunk,
    make_verified,
    write_event,
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
TARGET_APP_DIR = ROOT / "target-app"
APP_SOURCE_PATH = TARGET_APP_DIR / "app.py"
DB_PATH = TARGET_APP_DIR / "notes.db"
EVENTS_PATH = ROOT / "events.json"
SANDBOX_ID_PATH = ROOT / "orchestrator" / ".sandbox_id"

LOCAL_APP_URL = "http://localhost:5000"
NARRATION_DELAY_S = 0.022

MOCK = False
RUN_STRETCH = True
ITERATIONS = ["sqli", "idor"] + (["missing_auth"] if RUN_STRETCH else [])

_HEALTH_TIMEOUT_S = 30
_SHUTDOWN_TIMEOUT_S = 5


# ---------------------------------------------------------------------------
# Setup / teardown — local subprocess (mock mode only)
# ---------------------------------------------------------------------------

def reset_events_log() -> None:
    """Delete events.json so each run starts as a clean replay stream."""
    if EVENTS_PATH.exists():
        EVENTS_PATH.unlink()


def reset_target_source() -> None:
    """Restore target-app/app.py to the committed vulnerable baseline via git."""
    subprocess.run(
        ["git", "checkout", "--", str(APP_SOURCE_PATH)],
        cwd=str(ROOT),
        check=False,
    )


def reset_target_db() -> None:
    """Delete notes.db so each run starts from the seeded state."""
    if DB_PATH.exists():
        DB_PATH.unlink()


def _wait_for_health(timeout: int = _HEALTH_TIMEOUT_S) -> None:
    """Poll GET / on the local target app until Flask responds or timeout expires."""
    url = f"{LOCAL_APP_URL}/"
    deadline = time.time() + timeout
    last_error: Optional[Exception] = None

    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status < 500:
                    return
        except urllib.error.HTTPError as exc:
            if exc.code < 500:
                return
            last_error = exc
        except Exception as exc:
            last_error = exc
        time.sleep(0.5)

    raise TimeoutError(
        f"Target app did not respond on {url} within {timeout}s. Last error: {last_error}"
    )


def start_target_app() -> subprocess.Popen:
    """Launch the local target app as a subprocess and block until it's healthy."""
    proc = subprocess.Popen(
        [sys.executable, "app.py"],
        cwd=str(TARGET_APP_DIR),
    )
    try:
        _wait_for_health()
    except TimeoutError:
        proc.terminate()
        raise
    return proc


def stop_target_app(proc: subprocess.Popen) -> None:
    """Terminate the target app subprocess, killing it if it won't stop cleanly."""
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=_SHUTDOWN_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=_SHUTDOWN_TIMEOUT_S)


def restart_target_app(proc: subprocess.Popen) -> subprocess.Popen:
    """Restart the target app so it picks up a freshly-written patch.

    Re-running app.py also re-seeds the database (init_db() runs on every
    direct invocation), so a full process restart resets both source and data
    in one step.
    """
    stop_target_app(proc)
    return start_target_app()


# ---------------------------------------------------------------------------
# Setup / teardown — live Daytona sandbox (real mode only)
# ---------------------------------------------------------------------------

def _read_persisted_sandbox_id() -> Optional[str]:
    """Return the sandbox ID left by a prior setup.py pre-warm run, if any."""
    if SANDBOX_ID_PATH.exists():
        sandbox_id = SANDBOX_ID_PATH.read_text(encoding="utf-8").strip()
        return sandbox_id or None
    return None


def _clear_persisted_sandbox_id() -> None:
    if SANDBOX_ID_PATH.exists():
        SANDBOX_ID_PATH.unlink()


def start_sandbox(emit_ready_event: bool = True) -> tuple[str, str]:
    """Reuse a sandbox pre-warmed by setup.py if one exists, else create one.

    Reusing an already-warm sandbox is what lets setup.py's 10-30s create +
    deploy + start cost happen during the presenter's verbal intro instead of
    as dead air right when the demo starts (see ROADMAP.md Phase 5).
    Returns (sandbox_id, url) — the caller should hold on to url rather than
    calling daytona_client.get_url again, to avoid a redundant API call.
    """
    from orchestrator import daytona_client

    sandbox_id = _read_persisted_sandbox_id()
    if sandbox_id is None:
        sandbox_id = daytona_client.create_sandbox()
        daytona_client.deploy_app(sandbox_id, str(TARGET_APP_DIR))
        daytona_client.start_app(sandbox_id)
    else:
        # Pre-warmed sandbox: re-upload the clean source so any defender
        # patches from a previous run don't carry over into this one.
        clean_source = APP_SOURCE_PATH.read_text(encoding="utf-8")
        daytona_client.upload_file(
            sandbox_id, "/home/daytona/app/app.py", clean_source
        )
        daytona_client.restart_app(sandbox_id)

    url = daytona_client.get_url(sandbox_id)

    if emit_ready_event:
        info = daytona_client.get_sandbox_info(sandbox_id)
        emit(make_sandbox_ready(
            sandbox_id=sandbox_id,
            url=url,
            region=info["region"],
            created_at=info["created_at"],
            cpu=info["cpu"],
            memory=info["memory"],
            iteration=0,
            vulnerability_class="",
        ))

    return sandbox_id, url


def stop_sandbox(sandbox_id: str) -> None:
    """Tear the sandbox down and clear any persisted sandbox-id file."""
    from orchestrator import daytona_client

    daytona_client.delete_sandbox(sandbox_id)
    _clear_persisted_sandbox_id()


# ---------------------------------------------------------------------------
# HTTP + patching
# ---------------------------------------------------------------------------

def send_request(exploit: dict, base_url: str = LOCAL_APP_URL) -> dict:
    """Fire an {method, url, headers, body} request against base_url.

    Resolves a relative url (mock/model responses often return paths like
    "/login") against base_url; leaves an absolute url untouched.
    Returns {status, body}.
    """
    url = exploit["url"]
    if not url.startswith("http://") and not url.startswith("https://"):
        url = base_url + (url if url.startswith("/") else f"/{url}")

    response = requests.request(
        method=exploit["method"],
        url=url,
        headers=exploit.get("headers") or {},
        json=exploit.get("body"),
        timeout=10,
    )

    try:
        body = response.json()
    except ValueError:
        body = response.text

    return {"status": response.status_code, "body": body}


def apply_patch(patched_source: str) -> str:
    """Write patched_source to app.py, returning a unified diff against the prior contents."""
    old_source = APP_SOURCE_PATH.read_text(encoding="utf-8")
    diff = "".join(
        difflib.unified_diff(
            old_source.splitlines(keepends=True),
            patched_source.splitlines(keepends=True),
            fromfile="app.py (before)",
            tofile="app.py (after)",
        )
    )
    APP_SOURCE_PATH.write_text(patched_source, encoding="utf-8")
    return diff


# ---------------------------------------------------------------------------
# Event emission
# ---------------------------------------------------------------------------

def emit(event: dict) -> None:
    write_event(event, str(EVENTS_PATH))


def make_narration_callback(agent: str, iteration: int, vulnerability_class: str):
    """Build the on_narration_chunk callback passed to attacker_agent/defender_agent.

    Owns the 22ms/char typewriter pacing — agents.py deliberately does not.
    Runs identically in mock and real mode, replaying the final parsed
    narration once the (real or mock) response is available.
    """

    def _on_chunk(char: str) -> None:
        emit(make_narration_chunk(agent, char, iteration, vulnerability_class))
        time.sleep(NARRATION_DELAY_S)

    return _on_chunk


def make_raw_chunk_callback(agent: str, iteration: int, vulnerability_class: str):
    """Build the on_raw_chunk callback passed to attacker_agent/defender_agent.

    Only invoked in real (non-mock) mode, as raw SSE text deltas arrive —
    no artificial delay, since real network pacing already paces it. This is
    what lets the dashboard show the raw JSON streaming in before the
    response has finished parsing into a clean narration card.
    """

    def _on_chunk(chunk: str) -> None:
        emit(make_stream_chunk(agent, chunk, iteration, vulnerability_class))

    return _on_chunk


# ---------------------------------------------------------------------------
# Iteration sequence
# ---------------------------------------------------------------------------

def run_iteration(iteration: int, vulnerability_class: str, target: dict) -> None:
    """Run one full attack -> patch -> verify cycle.

    target: {"mode": "local", "proc": subprocess.Popen, "url": str} or
            {"mode": "daytona", "sandbox_id": str, "url": str}
    Mutates target["proc"] in place for local mode (subprocess is replaced
    on restart); target["url"] is refreshed for daytona mode in case a
    restart changes the preview URL (it doesn't currently, but this keeps
    the call sites honest about where the URL comes from).
    """
    emit(make_iteration_start(iteration, vulnerability_class))

    source = APP_SOURCE_PATH.read_text(encoding="utf-8")
    app_url = target["url"]

    emit(make_agent_thinking(
        "attacker", "Scanning for vulnerabilities...", iteration, vulnerability_class
    ))
    exploit, attacker_usage = attacker_agent(
        app_url,
        vulnerability_class,
        source,
        make_narration_callback("attacker", iteration, vulnerability_class),
        on_raw_chunk=make_raw_chunk_callback("attacker", iteration, vulnerability_class),
        mock=MOCK,
    )
    if attacker_usage is not None:
        emit(make_llm_usage(
            "attacker",
            attacker_usage["prompt_tokens"],
            attacker_usage["completion_tokens"],
            attacker_usage["total_tokens"],
            iteration,
            vulnerability_class,
        ))

    response = send_request(exploit, base_url=app_url)
    exploit_request = {
        "method": exploit["method"],
        "url": exploit["url"],
        "headers": exploit["headers"],
        "body": exploit["body"],
    }
    emit(make_attack_sent(
        exploit_request, response, exploit["agent_reasoning"], iteration, vulnerability_class
    ))

    emit(make_agent_thinking(
        "defender", "Analysing the breach...", iteration, vulnerability_class
    ))
    patch, defender_usage = defender_agent(
        exploit_request,
        response,
        source,
        make_narration_callback("defender", iteration, vulnerability_class),
        on_raw_chunk=make_raw_chunk_callback("defender", iteration, vulnerability_class),
        mock=MOCK,
    )
    if defender_usage is not None:
        emit(make_llm_usage(
            "defender",
            defender_usage["prompt_tokens"],
            defender_usage["completion_tokens"],
            defender_usage["total_tokens"],
            iteration,
            vulnerability_class,
        ))

    diff = apply_patch(patch["patched_source"])

    if target["mode"] == "local":
        target["proc"] = restart_target_app(target["proc"])
    else:
        from orchestrator import daytona_client

        daytona_client.upload_file(
            target["sandbox_id"], "/home/daytona/app/app.py", patch["patched_source"]
        )
        daytona_client.restart_app(target["sandbox_id"])

    emit(make_patch_applied(
        diff, patch["patched_source"], patch["agent_reasoning"], iteration, vulnerability_class
    ))

    verify_response = send_request(exploit_request, base_url=app_url)
    exploit_blocked = verify_response["status"] >= 400
    emit(make_verified(exploit_request, verify_response, exploit_blocked, iteration, vulnerability_class))

    emit(make_iteration_complete(iteration, vulnerability_class))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    reset_events_log()
    reset_target_source()

    if MOCK:
        reset_target_db()
        proc = start_target_app()
        target = {"mode": "local", "proc": proc, "url": LOCAL_APP_URL}
        try:
            for i, vulnerability_class in enumerate(ITERATIONS, start=1):
                print(f"[iteration {i}] {vulnerability_class} — starting")
                run_iteration(i, vulnerability_class, target)
                print(f"[iteration {i}] {vulnerability_class} — complete")
        finally:
            stop_target_app(target["proc"])
        return

    from orchestrator.load_daytona_env import inject_env as inject_daytona_env

    inject_daytona_env()

    sandbox_id, url = start_sandbox()
    target = {"mode": "daytona", "sandbox_id": sandbox_id, "url": url}
    try:
        for i, vulnerability_class in enumerate(ITERATIONS, start=1):
            print(f"[iteration {i}] {vulnerability_class} — starting")
            run_iteration(i, vulnerability_class, target)
            print(f"[iteration {i}] {vulnerability_class} — complete")
    finally:
        stop_sandbox(sandbox_id)


if __name__ == "__main__":
    main()
