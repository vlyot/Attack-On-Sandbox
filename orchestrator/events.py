"""
Event system for Attack on Sandbox.

Single shared data contract between the orchestrator and the dashboard.
All state transitions are appended as newline-delimited JSON to events.json.
"""

import json
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _base(type_: str, iteration: int, vulnerability_class: str) -> dict:
    return {
        "type": type_,
        "timestamp": _now(),
        "iteration": iteration,
        "vulnerability_class": vulnerability_class,
    }


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

def write_event(event: dict, path: str = "events.json") -> None:
    """Append a single JSON event line to the event log."""
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(event) + "\n")


# ---------------------------------------------------------------------------
# Event constructors
# ---------------------------------------------------------------------------

def make_sandbox_ready(
    sandbox_id: str,
    url: str,
    region: str,
    created_at: str,
    cpu: int,
    memory: int,
    iteration: int,
    vulnerability_class: str,
) -> dict:
    """Sandbox is live and the Flask health check has responded."""
    event = _base("sandbox_ready", iteration, vulnerability_class)
    event["payload"] = {
        "sandbox_id": sandbox_id,
        "url": url,
        "region": region,
        "created_at": created_at,
        "spec": {"cpu": cpu, "memory": memory},
    }
    return event


def make_sandbox_destroyed(
    sandbox_id: str,
    iteration: int,
    vulnerability_class: str,
) -> dict:
    """Sandbox has been torn down. Dashboard moves this to the history log."""
    event = _base("sandbox_destroyed", iteration, vulnerability_class)
    event["payload"] = {"sandbox_id": sandbox_id}
    return event


def make_iteration_start(iteration: int, vulnerability_class: str) -> dict:
    """First event of each adversarial loop iteration."""
    return _base("iteration_start", iteration, vulnerability_class)


def make_agent_thinking(
    agent: str,
    label: str,
    iteration: int,
    vulnerability_class: str,
) -> dict:
    """
    Written synchronously before each AI API call — zero extra cost.
    agent: 'attacker' | 'defender'
    label: static string shown while the model is running.
    """
    event = _base("agent_thinking", iteration, vulnerability_class)
    event["payload"] = {"agent": agent, "label": label}
    return event


def make_narration_chunk(
    agent: str,
    char: str,
    iteration: int,
    vulnerability_class: str,
) -> dict:
    """
    One event per character of the narration field, replayed after parsing.
    Produces the typewriter effect on the dashboard at 22 ms/char.
    """
    if len(char) != 1:
        raise ValueError(f"char must be exactly one character, got {char!r}")
    event = _base("narration_chunk", iteration, vulnerability_class)
    event["payload"] = {"agent": agent, "char": char}
    return event


def make_stream_chunk(
    agent: str,
    chunk: str,
    iteration: int,
    vulnerability_class: str,
) -> dict:
    """
    One event per raw SSE text fragment received from a real (non-mock)
    streaming model call, before the assembled JSON is parsed. Unlike
    narration_chunk, chunk length is unconstrained — real deltas arrive in
    arbitrary-sized fragments, not one character at a time.
    """
    event = _base("stream_chunk", iteration, vulnerability_class)
    event["payload"] = {"agent": agent, "chunk": chunk}
    return event


def make_llm_usage(
    agent: str,
    prompt_tokens: int,
    completion_tokens: int,
    total_tokens: int,
    iteration: int,
    vulnerability_class: str,
) -> dict:
    """Written once per real (non-mock) model call, after the stream completes."""
    event = _base("llm_usage", iteration, vulnerability_class)
    event["payload"] = {
        "agent": agent,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
    }
    return event


def make_attack_sent(
    request: dict,
    response: dict,
    agent_reasoning: dict,
    iteration: int,
    vulnerability_class: str,
) -> dict:
    """
    Written after the orchestrator fires the real HTTP exploit request.
    request:  {method, url, headers, body}
    response: {status, body}
    agent_reasoning: {narration, technical}
    """
    event = _base("attack_sent", iteration, vulnerability_class)
    event["payload"] = {
        "request": request,
        "response": response,
        "agent_reasoning": agent_reasoning,
    }
    return event


def make_patch_applied(
    diff: str,
    patched_source: str,
    agent_reasoning: dict,
    iteration: int,
    vulnerability_class: str,
) -> dict:
    """
    Written after the patch is deployed.
    diff is computed by the orchestrator via difflib, not taken from the model.
    """
    event = _base("patch_applied", iteration, vulnerability_class)
    event["payload"] = {
        "diff": diff,
        "patched_source": patched_source,
        "agent_reasoning": agent_reasoning,
    }
    return event


def make_verified(
    request: dict,
    response: dict,
    exploit_blocked: bool,
    iteration: int,
    vulnerability_class: str,
) -> dict:
    """
    Written after replaying the original exploit against the patched app.
    exploit_blocked is set by the orchestrator from the HTTP response — not model-generated.
    """
    if not isinstance(exploit_blocked, bool):
        raise TypeError(f"exploit_blocked must be bool, got {type(exploit_blocked).__name__}")
    event = _base("verified", iteration, vulnerability_class)
    event["payload"] = {
        "request": request,
        "response": response,
        "exploit_blocked": exploit_blocked,
    }
    return event


def make_iteration_complete(iteration: int, vulnerability_class: str) -> dict:
    """Final event of each adversarial loop iteration."""
    return _base("iteration_complete", iteration, vulnerability_class)
