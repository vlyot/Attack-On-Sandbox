"""
Tests for orchestrator/agents.py.

Every test patches agents._get_client (or runs mock=True) — no real
network access, no AIAND_API_KEY required. Real-mode calls are streaming
(stream=True), so the fake client yields an iterator of fake chunk objects
mirroring the OpenAI SDK's ChatCompletionChunk shape rather than returning
a single non-streaming response object.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
from openai import APIConnectionError, APIStatusError

from orchestrator import agents
from orchestrator.events import make_attack_sent, make_patch_applied


@pytest.fixture(autouse=True)
def no_api_key(monkeypatch):
    monkeypatch.delenv("AIAND_API_KEY", raising=False)
    agents._client = None
    yield
    agents._client = None


def _collecting_callback():
    chars = []
    return chars, chars.append


def _fake_chunk(delta_content: str | None, usage: MagicMock | None = None) -> MagicMock:
    """One fake ChatCompletionChunk: either a content delta or a usage trailer."""
    chunk = MagicMock()
    if delta_content is not None:
        delta = MagicMock()
        delta.content = delta_content
        choice = MagicMock()
        choice.delta = delta
        chunk.choices = [choice]
    else:
        chunk.choices = []
    chunk.usage = usage
    return chunk


def _fake_usage(prompt: int = 100, completion: int = 20, total: int = 120) -> MagicMock:
    usage = MagicMock()
    usage.prompt_tokens = prompt
    usage.completion_tokens = completion
    usage.total_tokens = total
    return usage


def _fake_stream(payload: dict, chunk_size: int = 8, usage: MagicMock | None = None) -> list:
    """Build a fake streaming response: the JSON payload split into content
    deltas of chunk_size characters, followed by a usage-only trailer chunk
    (mirroring stream_options={"include_usage": True})."""
    text = json.dumps(payload)
    deltas = [text[i : i + chunk_size] for i in range(0, len(text), chunk_size)]
    chunks = [_fake_chunk(d) for d in deltas]
    chunks.append(_fake_chunk(None, usage=usage or _fake_usage()))
    return chunks


def _status_error(status_code: int) -> APIStatusError:
    request = httpx.Request("POST", "https://api.aiand.com/v1/chat/completions")
    response = httpx.Response(status_code=status_code, request=request)
    return APIStatusError("boom", response=response, body=None)


# ---------------------------------------------------------------------------
# Attacker — mock mode
# ---------------------------------------------------------------------------

def test_attacker_agent_mock_sqli_shape():
    _, cb = _collecting_callback()
    result, usage = agents.attacker_agent("http://x", "sqli", "src", cb, mock=True)
    assert set(result.keys()) == {"method", "url", "headers", "body", "agent_reasoning"}
    assert set(result["agent_reasoning"].keys()) == {"narration", "technical"}
    assert usage is None


def test_attacker_agent_mock_idor_shape():
    _, cb = _collecting_callback()
    result, usage = agents.attacker_agent("http://x", "idor", "src", cb, mock=True)
    assert set(result.keys()) == {"method", "url", "headers", "body", "agent_reasoning"}
    assert set(result["agent_reasoning"].keys()) == {"narration", "technical"}
    assert usage is None


def test_attacker_agent_mock_unknown_vuln_raises():
    _, cb = _collecting_callback()
    with pytest.raises(ValueError):
        agents.attacker_agent("http://x", "xss", "src", cb, mock=True)


def test_attacker_agent_mock_calls_narration_callback_per_char():
    chars, cb = _collecting_callback()
    result, _ = agents.attacker_agent("http://x", "sqli", "src", cb, mock=True)
    narration = result["agent_reasoning"]["narration"]
    assert "".join(chars) == narration
    assert len(chars) == len(narration)


def test_attacker_agent_mock_no_api_key_needed():
    _, cb = _collecting_callback()
    agents.attacker_agent("http://x", "sqli", "src", cb, mock=True)  # no raise


def test_attacker_agent_mock_mode_ignores_on_raw_chunk():
    _, narration_cb = _collecting_callback()
    raw_chunks, raw_cb = _collecting_callback()
    agents.attacker_agent(
        "http://x", "sqli", "src", narration_cb, on_raw_chunk=raw_cb, mock=True
    )
    assert raw_chunks == []


# ---------------------------------------------------------------------------
# Defender — mock mode
# ---------------------------------------------------------------------------

def test_defender_agent_mock_login_url_shape():
    _, cb = _collecting_callback()
    request = {"method": "POST", "url": "http://x/login", "headers": {}, "body": {}}
    response = {"status": 200, "body": {}}
    result, usage = agents.defender_agent(request, response, "src", cb, mock=True)
    assert isinstance(result["patched_source"], str) and result["patched_source"]
    assert set(result["agent_reasoning"].keys()) == {"narration", "technical"}
    assert usage is None


def test_defender_agent_mock_notes_url_shape():
    _, cb = _collecting_callback()
    request = {"method": "GET", "url": "http://x/notes/2", "headers": {}, "body": None}
    response = {"status": 200, "body": {}}
    result, usage = agents.defender_agent(request, response, "src", cb, mock=True)
    assert isinstance(result["patched_source"], str) and result["patched_source"]
    assert set(result["agent_reasoning"].keys()) == {"narration", "technical"}
    assert usage is None


def test_defender_agent_mock_calls_narration_callback_per_char():
    chars, cb = _collecting_callback()
    request = {"method": "POST", "url": "http://x/login", "headers": {}, "body": {}}
    response = {"status": 200, "body": {}}
    result, _ = agents.defender_agent(request, response, "src", cb, mock=True)
    narration = result["agent_reasoning"]["narration"]
    assert "".join(chars) == narration
    assert len(chars) == len(narration)


def test_defender_agent_mock_no_api_key_needed():
    _, cb = _collecting_callback()
    request = {"method": "POST", "url": "http://x/reset", "headers": {}, "body": None}
    response = {"status": 200, "body": {}}
    agents.defender_agent(request, response, "src", cb, mock=True)  # no raise


def test_defender_agent_mock_patched_source_is_full_file_not_a_fragment():
    """patched_source must be a complete file replacement (per the real API's
    contract), not a bare route handler — regression test for a bug where mock
    data was a fragment and overwriting app.py with it broke the app."""
    real_source = (
        Path(__file__).resolve().parent.parent / "target-app" / "app.py"
    ).read_text(encoding="utf-8")
    _, cb = _collecting_callback()
    request = {"method": "POST", "url": "http://x/login", "headers": {}, "body": {}}
    response = {"status": 200, "body": {}}

    result, _ = agents.defender_agent(request, response, real_source, cb, mock=True)
    patched = result["patched_source"]

    assert "from flask import Flask" in patched
    assert "def get_note" in patched
    assert "def update_note" in patched
    assert "def reset" in patched
    assert "SELECT * FROM users WHERE username = ? AND password = ?" in patched
    compile(patched, "<patched app.py>", "exec")


def test_defender_agent_mock_idor_patch_preserves_rest_of_file():
    real_source = (
        Path(__file__).resolve().parent.parent / "target-app" / "app.py"
    ).read_text(encoding="utf-8")
    _, cb = _collecting_callback()
    request = {"method": "GET", "url": "http://x/notes/2", "headers": {}, "body": None}
    response = {"status": 200, "body": {}}

    result, _ = agents.defender_agent(request, response, real_source, cb, mock=True)
    patched = result["patched_source"]

    assert 'row["owner_id"] != auth_id' in patched
    assert "def login" in patched
    assert "def reset" in patched
    compile(patched, "<patched app.py>", "exec")


# ---------------------------------------------------------------------------
# Real call path (client mocked, streaming)
# ---------------------------------------------------------------------------

_ATTACKER_PAYLOAD = {
    "method": "POST",
    "url": "http://x/login",
    "headers": {},
    "body": {"username": "a"},
    "agent_reasoning": {"narration": "In.", "technical": "Details."},
}

_DEFENDER_PAYLOAD = {
    "patched_source": "patched code",
    "agent_reasoning": {"narration": "Found it.", "technical": "Details."},
}


def test_attacker_agent_real_call_success():
    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = _fake_stream(_ATTACKER_PAYLOAD)
    with patch.object(agents, "_get_client", return_value=fake_client):
        _, cb = _collecting_callback()
        result, usage = agents.attacker_agent("http://x", "sqli", "src", cb, mock=False)

    assert result == _ATTACKER_PAYLOAD
    assert usage == {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}
    fake_client.chat.completions.create.assert_called_once()
    _, kwargs = fake_client.chat.completions.create.call_args
    assert kwargs["response_format"] == {"type": "json_object"}
    assert kwargs["stream"] is True
    assert kwargs["stream_options"] == {"include_usage": True}


def test_defender_agent_real_call_success():
    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = _fake_stream(_DEFENDER_PAYLOAD)
    with patch.object(agents, "_get_client", return_value=fake_client):
        _, cb = _collecting_callback()
        request = {"method": "GET", "url": "http://x/notes/1", "headers": {}, "body": None}
        response = {"status": 200, "body": {}}
        result, usage = agents.defender_agent(request, response, "src", cb, mock=False)

    assert result == _DEFENDER_PAYLOAD
    assert usage is not None
    fake_client.chat.completions.create.assert_called_once()


def test_attacker_agent_real_call_prompt_includes_vulnerability_class():
    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = _fake_stream(_ATTACKER_PAYLOAD)
    with patch.object(agents, "_get_client", return_value=fake_client):
        _, cb = _collecting_callback()
        agents.attacker_agent("http://x", "sqli", "src", cb, mock=False)

    _, kwargs = fake_client.chat.completions.create.call_args
    all_content = " ".join(m["content"] for m in kwargs["messages"])
    assert "sqli" in all_content


def test_defender_agent_real_call_prompt_excludes_vulnerability_hints():
    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = _fake_stream(_DEFENDER_PAYLOAD)
    with patch.object(agents, "_get_client", return_value=fake_client):
        _, cb = _collecting_callback()
        request = {"method": "GET", "url": "http://x/notes/1", "headers": {}, "body": None}
        response = {"status": 200, "body": {"id": 1}}
        agents.defender_agent(request, response, "src", cb, mock=False)

    _, kwargs = fake_client.chat.completions.create.call_args
    all_content = " ".join(m["content"] for m in kwargs["messages"]).lower()
    for hint in ("sqli", "idor", "missing_auth", "vulnerability class"):
        assert hint not in all_content


# ---------------------------------------------------------------------------
# Streaming: raw chunk forwarding + usage
# ---------------------------------------------------------------------------

def test_attacker_agent_streaming_forwards_raw_chunks():
    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = _fake_stream(_ATTACKER_PAYLOAD, chunk_size=6)
    expected_text = json.dumps(_ATTACKER_PAYLOAD)
    expected_deltas = [expected_text[i : i + 6] for i in range(0, len(expected_text), 6)]

    with patch.object(agents, "_get_client", return_value=fake_client):
        raw_chunks, raw_cb = _collecting_callback()
        _, narration_cb = _collecting_callback()
        agents.attacker_agent(
            "http://x", "sqli", "src", narration_cb, on_raw_chunk=raw_cb, mock=False
        )

    assert raw_chunks == expected_deltas


def test_attacker_agent_streaming_returns_usage_dict():
    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = _fake_stream(
        _ATTACKER_PAYLOAD, usage=_fake_usage(prompt=250, completion=60, total=310)
    )
    with patch.object(agents, "_get_client", return_value=fake_client):
        _, cb = _collecting_callback()
        _, usage = agents.attacker_agent("http://x", "sqli", "src", cb, mock=False)

    assert usage == {"prompt_tokens": 250, "completion_tokens": 60, "total_tokens": 310}


def test_defender_agent_streaming_forwards_raw_chunks():
    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = _fake_stream(_DEFENDER_PAYLOAD, chunk_size=5)
    expected_text = json.dumps(_DEFENDER_PAYLOAD)
    expected_deltas = [expected_text[i : i + 5] for i in range(0, len(expected_text), 5)]

    with patch.object(agents, "_get_client", return_value=fake_client):
        raw_chunks, raw_cb = _collecting_callback()
        _, narration_cb = _collecting_callback()
        request = {"method": "GET", "url": "http://x/notes/1", "headers": {}, "body": None}
        response = {"status": 200, "body": {}}
        agents.defender_agent(
            request, response, "src", narration_cb, on_raw_chunk=raw_cb, mock=False
        )

    assert raw_chunks == expected_deltas


def test_attacker_agent_real_call_without_on_raw_chunk_does_not_raise():
    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = _fake_stream(_ATTACKER_PAYLOAD)
    with patch.object(agents, "_get_client", return_value=fake_client):
        _, cb = _collecting_callback()
        agents.attacker_agent("http://x", "sqli", "src", cb, mock=False)  # no raise


# ---------------------------------------------------------------------------
# Retry wrapper
# ---------------------------------------------------------------------------

def test_call_model_with_retry_retries_once_on_connection_error_then_succeeds():
    fake_client = MagicMock()
    fake_client.chat.completions.create.side_effect = [
        APIConnectionError(request=httpx.Request("POST", "https://x")),
        _fake_stream(_ATTACKER_PAYLOAD),
    ]
    with patch.object(agents, "_get_client", return_value=fake_client):
        result, usage = agents._call_model_with_retry(
            [{"role": "user", "content": "hi"}], lambda _c: None
        )

    assert result == _ATTACKER_PAYLOAD
    assert usage is not None
    assert fake_client.chat.completions.create.call_count == 2


def test_call_model_with_retry_streaming_retries_once_on_5xx():
    fake_client = MagicMock()
    fake_client.chat.completions.create.side_effect = [
        _status_error(503),
        _status_error(503),
    ]
    with patch.object(agents, "_get_client", return_value=fake_client):
        with pytest.raises(APIStatusError):
            agents._call_model_with_retry([{"role": "user", "content": "hi"}], lambda _c: None)

    assert fake_client.chat.completions.create.call_count == 2


def test_call_model_with_retry_no_retry_on_4xx():
    fake_client = MagicMock()
    fake_client.chat.completions.create.side_effect = [_status_error(400)]
    with patch.object(agents, "_get_client", return_value=fake_client):
        with pytest.raises(APIStatusError):
            agents._call_model_with_retry([{"role": "user", "content": "hi"}], lambda _c: None)

    assert fake_client.chat.completions.create.call_count == 1


def test_call_model_with_retry_no_retry_on_generic_exception():
    fake_client = MagicMock()
    fake_client.chat.completions.create.side_effect = [ValueError("boom")]
    with patch.object(agents, "_get_client", return_value=fake_client):
        with pytest.raises(ValueError):
            agents._call_model_with_retry([{"role": "user", "content": "hi"}], lambda _c: None)

    assert fake_client.chat.completions.create.call_count == 1


# ---------------------------------------------------------------------------
# Contract check against Phase 2A events schema
# ---------------------------------------------------------------------------

def test_attacker_agent_real_call_agent_reasoning_shape_matches_events_schema():
    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = _fake_stream(_ATTACKER_PAYLOAD)
    with patch.object(agents, "_get_client", return_value=fake_client):
        _, cb = _collecting_callback()
        result, _ = agents.attacker_agent("http://x", "sqli", "src", cb, mock=False)

    request = {
        "method": result["method"],
        "url": result["url"],
        "headers": result["headers"],
        "body": result["body"],
    }
    event = make_attack_sent(
        request=request,
        response={"status": 200, "body": {}},
        agent_reasoning=result["agent_reasoning"],
        iteration=1,
        vulnerability_class="sqli",
    )
    assert set(event["payload"]["agent_reasoning"].keys()) == {"narration", "technical"}


def test_defender_agent_real_call_agent_reasoning_shape_matches_events_schema():
    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = _fake_stream(_DEFENDER_PAYLOAD)
    with patch.object(agents, "_get_client", return_value=fake_client):
        _, cb = _collecting_callback()
        request = {"method": "GET", "url": "http://x/notes/1", "headers": {}, "body": None}
        response = {"status": 200, "body": {}}
        result, _ = agents.defender_agent(request, response, "src", cb, mock=False)

    event = make_patch_applied(
        diff="dummy diff",
        patched_source=result["patched_source"],
        agent_reasoning=result["agent_reasoning"],
        iteration=1,
        vulnerability_class="sqli",
    )
    assert set(event["payload"]["agent_reasoning"].keys()) == {"narration", "technical"}
