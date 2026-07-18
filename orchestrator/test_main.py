"""
Tests for orchestrator/main.py.

Network calls (send_request) and the target-app subprocess/sandbox are
mocked/faked throughout — no real HTTP, no real process spawned, no real
Daytona sandbox created, no AIAND_API_KEY needed (run_iteration exercises
attacker_agent/defender_agent with mock=True unless a test explicitly sets
main.MOCK = False to exercise the real-call wiring path with agents mocked).
"""

import json
import sys
from unittest.mock import MagicMock, patch

import pytest

import orchestrator
from orchestrator import main


def _patch_daytona_client(monkeypatch) -> MagicMock:
    """Replace orchestrator.daytona_client with a MagicMock everywhere main.py's
    local `from orchestrator import daytona_client` statements can find it.

    Once the real submodule has been imported anywhere in the test session
    (e.g. by test_daytona_client.py), Python caches it both in sys.modules
    AND as an attribute on the orchestrator package object — a bare
    monkeypatch.setitem(sys.modules, ...) only covers the first, so a later
    `from orchestrator import daytona_client` inside main.py's functions
    still resolves to the real module. Patch both.
    """
    fake = MagicMock()
    monkeypatch.setitem(sys.modules, "orchestrator.daytona_client", fake)
    monkeypatch.setattr(orchestrator, "daytona_client", fake, raising=False)
    return fake


# ---------------------------------------------------------------------------
# apply_patch
# ---------------------------------------------------------------------------

def test_apply_patch_writes_file_and_returns_nonempty_diff(tmp_path, monkeypatch):
    app_file = tmp_path / "app.py"
    app_file.write_text("old contents\n", encoding="utf-8")
    monkeypatch.setattr(main, "APP_SOURCE_PATH", app_file)

    diff = main.apply_patch("new contents\n")

    assert app_file.read_text(encoding="utf-8") == "new contents\n"
    assert diff != ""
    assert "-old contents" in diff
    assert "+new contents" in diff


def test_apply_patch_diff_is_empty_when_source_unchanged(tmp_path, monkeypatch):
    app_file = tmp_path / "app.py"
    app_file.write_text("same contents\n", encoding="utf-8")
    monkeypatch.setattr(main, "APP_SOURCE_PATH", app_file)

    diff = main.apply_patch("same contents\n")

    assert diff == ""


# ---------------------------------------------------------------------------
# send_request — URL resolution
# ---------------------------------------------------------------------------

def _fake_response(status=200, json_body=None):
    resp = MagicMock()
    resp.status_code = status
    if json_body is None:
        resp.json.side_effect = ValueError("no json")
        resp.text = "plain text"
    else:
        resp.json.return_value = json_body
    return resp


def test_send_request_resolves_relative_url_against_base():
    exploit = {"method": "POST", "url": "/login", "headers": {}, "body": {"a": 1}}
    with patch.object(main.requests, "request", return_value=_fake_response(200, {"ok": True})) as mock_req:
        result = main.send_request(exploit)

    mock_req.assert_called_once()
    assert mock_req.call_args.kwargs["url"] == "http://localhost:5000/login"
    assert result == {"status": 200, "body": {"ok": True}}


def test_send_request_resolves_relative_url_against_custom_base():
    exploit = {"method": "POST", "url": "/login", "headers": {}, "body": None}
    with patch.object(main.requests, "request", return_value=_fake_response(200, {"ok": True})) as mock_req:
        main.send_request(exploit, base_url="https://abc123.daytonaproxy01.net")

    assert mock_req.call_args.kwargs["url"] == "https://abc123.daytonaproxy01.net/login"


def test_send_request_leaves_absolute_url_untouched():
    exploit = {"method": "GET", "url": "http://example.com/notes/1", "headers": {}, "body": None}
    with patch.object(main.requests, "request", return_value=_fake_response(200, {"ok": True})) as mock_req:
        main.send_request(exploit)

    assert mock_req.call_args.kwargs["url"] == "http://example.com/notes/1"


def test_send_request_falls_back_to_text_body_on_non_json_response():
    exploit = {"method": "GET", "url": "/whatever", "headers": {}, "body": None}
    with patch.object(main.requests, "request", return_value=_fake_response(500, None)):
        result = main.send_request(exploit)

    assert result == {"status": 500, "body": "plain text"}


# ---------------------------------------------------------------------------
# reset helpers
# ---------------------------------------------------------------------------

def test_reset_events_log_removes_existing_file(tmp_path, monkeypatch):
    events_file = tmp_path / "events.json"
    events_file.write_text("stale\n", encoding="utf-8")
    monkeypatch.setattr(main, "EVENTS_PATH", events_file)

    main.reset_events_log()

    assert not events_file.exists()


def test_reset_events_log_noop_when_missing(tmp_path, monkeypatch):
    events_file = tmp_path / "events.json"
    monkeypatch.setattr(main, "EVENTS_PATH", events_file)

    main.reset_events_log()  # no raise


def test_reset_target_db_removes_existing_file(tmp_path, monkeypatch):
    db_file = tmp_path / "notes.db"
    db_file.write_bytes(b"stale")
    monkeypatch.setattr(main, "DB_PATH", db_file)

    main.reset_target_db()

    assert not db_file.exists()


# ---------------------------------------------------------------------------
# run_iteration — event sequence (mock mode, local target)
# ---------------------------------------------------------------------------

def test_run_iteration_emits_expected_event_sequence_in_order(tmp_path, monkeypatch):
    real_source = (main.ROOT / "target-app" / "app.py").read_text(encoding="utf-8")
    app_file = tmp_path / "app.py"
    app_file.write_text(real_source, encoding="utf-8")
    events_file = tmp_path / "events.json"
    monkeypatch.setattr(main, "APP_SOURCE_PATH", app_file)
    monkeypatch.setattr(main, "EVENTS_PATH", events_file)
    monkeypatch.setattr(main, "MOCK", True)

    fake_proc = MagicMock()
    monkeypatch.setattr(main, "restart_target_app", lambda proc: fake_proc)
    monkeypatch.setattr(
        main, "send_request",
        lambda exploit, base_url=main.LOCAL_APP_URL: {"status": 401, "body": {"error": "invalid credentials"}},
    )

    target = {"mode": "local", "proc": fake_proc, "url": main.LOCAL_APP_URL}
    main.run_iteration(1, "sqli", target)

    assert target["proc"] is fake_proc
    lines = events_file.read_text(encoding="utf-8").strip().splitlines()
    events = [json.loads(line) for line in lines]
    types = [e["type"] for e in events]

    assert types[0] == "iteration_start"
    assert types[1] == "agent_thinking"
    assert events[1]["payload"]["agent"] == "attacker"
    # a run of narration_chunk events for the attacker follows
    narration_start = 2
    narration_end = narration_start
    while types[narration_end] == "narration_chunk":
        narration_end += 1
    assert narration_end > narration_start

    assert types[narration_end] == "attack_sent"
    idx = narration_end + 1
    assert types[idx] == "agent_thinking"
    assert events[idx]["payload"]["agent"] == "defender"
    idx += 1
    while types[idx] == "narration_chunk":
        idx += 1
    assert types[idx] == "patch_applied"
    idx += 1
    assert types[idx] == "verified"
    idx += 1
    assert types[idx] == "iteration_complete"
    assert idx == len(types) - 1

    # mock mode never emits llm_usage (no real call was made)
    assert "llm_usage" not in types

    # patch was actually written to disk
    assert app_file.read_text(encoding="utf-8") != real_source


def test_run_iteration_sets_exploit_blocked_true_when_verify_status_4xx(tmp_path, monkeypatch):
    app_file = tmp_path / "app.py"
    app_file.write_text("source\n", encoding="utf-8")
    events_file = tmp_path / "events.json"
    monkeypatch.setattr(main, "APP_SOURCE_PATH", app_file)
    monkeypatch.setattr(main, "EVENTS_PATH", events_file)
    monkeypatch.setattr(main, "MOCK", True)
    monkeypatch.setattr(main, "restart_target_app", lambda proc: proc)
    monkeypatch.setattr(
        main, "send_request",
        lambda exploit, base_url=main.LOCAL_APP_URL: {"status": 401, "body": {"error": "unauthorized"}},
    )

    target = {"mode": "local", "proc": MagicMock(), "url": main.LOCAL_APP_URL}
    main.run_iteration(1, "sqli", target)

    events = [json.loads(l) for l in events_file.read_text(encoding="utf-8").strip().splitlines()]
    verified = next(e for e in events if e["type"] == "verified")
    assert verified["payload"]["exploit_blocked"] is True


def test_run_iteration_sets_exploit_blocked_false_when_verify_status_2xx(tmp_path, monkeypatch):
    app_file = tmp_path / "app.py"
    app_file.write_text("source\n", encoding="utf-8")
    events_file = tmp_path / "events.json"
    monkeypatch.setattr(main, "APP_SOURCE_PATH", app_file)
    monkeypatch.setattr(main, "EVENTS_PATH", events_file)
    monkeypatch.setattr(main, "MOCK", True)
    monkeypatch.setattr(main, "restart_target_app", lambda proc: proc)
    monkeypatch.setattr(
        main, "send_request",
        lambda exploit, base_url=main.LOCAL_APP_URL: {"status": 200, "body": {"token": "still works"}},
    )

    target = {"mode": "local", "proc": MagicMock(), "url": main.LOCAL_APP_URL}
    main.run_iteration(1, "sqli", target)

    events = [json.loads(l) for l in events_file.read_text(encoding="utf-8").strip().splitlines()]
    verified = next(e for e in events if e["type"] == "verified")
    assert verified["payload"]["exploit_blocked"] is False


# ---------------------------------------------------------------------------
# run_iteration — real mode (agents mocked, no real network/API/sandbox)
# ---------------------------------------------------------------------------

_FAKE_ATTACKER_RESULT = {
    "method": "POST",
    "url": "/login",
    "headers": {},
    "body": {"username": "x"},
    "agent_reasoning": {"narration": "Hi", "technical": "Detail"},
}
_FAKE_DEFENDER_RESULT = {
    "patched_source": "patched\n",
    "agent_reasoning": {"narration": "Found", "technical": "Detail"},
}
_FAKE_USAGE = {"prompt_tokens": 50, "completion_tokens": 10, "total_tokens": 60}


def test_run_iteration_emits_llm_usage_after_each_real_call(tmp_path, monkeypatch):
    app_file = tmp_path / "app.py"
    app_file.write_text("source\n", encoding="utf-8")
    events_file = tmp_path / "events.json"
    monkeypatch.setattr(main, "APP_SOURCE_PATH", app_file)
    monkeypatch.setattr(main, "EVENTS_PATH", events_file)
    monkeypatch.setattr(main, "MOCK", False)
    monkeypatch.setattr(
        main, "send_request",
        lambda exploit, base_url=None: {"status": 401, "body": {}},
    )

    fake_daytona = _patch_daytona_client(monkeypatch)

    def fake_attacker(*args, **kwargs):
        return _FAKE_ATTACKER_RESULT, _FAKE_USAGE

    def fake_defender(*args, **kwargs):
        return _FAKE_DEFENDER_RESULT, _FAKE_USAGE

    monkeypatch.setattr(main, "attacker_agent", fake_attacker)
    monkeypatch.setattr(main, "defender_agent", fake_defender)

    target = {"mode": "daytona", "sandbox_id": "sbox-1", "url": "https://sbox-1.daytonaproxy01.net"}
    main.run_iteration(1, "sqli", target)

    events = [json.loads(l) for l in events_file.read_text(encoding="utf-8").strip().splitlines()]
    usage_events = [e for e in events if e["type"] == "llm_usage"]
    assert len(usage_events) == 2
    assert usage_events[0]["payload"]["agent"] == "attacker"
    assert usage_events[1]["payload"]["agent"] == "defender"
    assert usage_events[0]["payload"]["total_tokens"] == 60

    fake_daytona.upload_file.assert_called_once_with(
        "sbox-1", "/home/daytona/app/app.py", _FAKE_DEFENDER_RESULT["patched_source"]
    )
    fake_daytona.restart_app.assert_called_once_with("sbox-1")


# ---------------------------------------------------------------------------
# sandbox id persistence (setup.py <-> main.py handoff)
# ---------------------------------------------------------------------------

def test_start_sandbox_reuses_persisted_sandbox_id(tmp_path, monkeypatch):
    sandbox_id_file = tmp_path / ".sandbox_id"
    sandbox_id_file.write_text("sbox-existing\n", encoding="utf-8")
    monkeypatch.setattr(main, "SANDBOX_ID_PATH", sandbox_id_file)
    events_file = tmp_path / "events.json"
    monkeypatch.setattr(main, "EVENTS_PATH", events_file)

    fake_daytona = _patch_daytona_client(monkeypatch)
    fake_daytona.get_sandbox_info.return_value = {
        "region": "us-east-1", "created_at": "t", "cpu": 1, "memory": 1,
    }
    fake_daytona.get_url.return_value = "https://sbox-existing.daytonaproxy01.net"

    sandbox_id, url = main.start_sandbox()

    assert sandbox_id == "sbox-existing"
    assert url == "https://sbox-existing.daytonaproxy01.net"
    fake_daytona.create_sandbox.assert_not_called()
    fake_daytona.deploy_app.assert_not_called()
    fake_daytona.start_app.assert_not_called()


def test_start_sandbox_creates_new_when_no_persisted_id(tmp_path, monkeypatch):
    sandbox_id_file = tmp_path / ".sandbox_id"
    monkeypatch.setattr(main, "SANDBOX_ID_PATH", sandbox_id_file)
    events_file = tmp_path / "events.json"
    monkeypatch.setattr(main, "EVENTS_PATH", events_file)

    fake_daytona = _patch_daytona_client(monkeypatch)
    fake_daytona.create_sandbox.return_value = "sbox-new"
    fake_daytona.get_sandbox_info.return_value = {
        "region": "us-east-1", "created_at": "t", "cpu": 1, "memory": 1,
    }
    fake_daytona.get_url.return_value = "https://sbox-new.daytonaproxy01.net"

    sandbox_id, url = main.start_sandbox()

    assert sandbox_id == "sbox-new"
    assert url == "https://sbox-new.daytonaproxy01.net"
    fake_daytona.create_sandbox.assert_called_once()
    fake_daytona.deploy_app.assert_called_once()
    fake_daytona.start_app.assert_called_once()


def test_stop_sandbox_clears_persisted_id_file(tmp_path, monkeypatch):
    sandbox_id_file = tmp_path / ".sandbox_id"
    sandbox_id_file.write_text("sbox-1\n", encoding="utf-8")
    monkeypatch.setattr(main, "SANDBOX_ID_PATH", sandbox_id_file)

    fake_daytona = _patch_daytona_client(monkeypatch)

    main.stop_sandbox("sbox-1")

    fake_daytona.delete_sandbox.assert_called_once_with("sbox-1")
    assert not sandbox_id_file.exists()


# ---------------------------------------------------------------------------
# main() — mock-mode subprocess lifecycle
# ---------------------------------------------------------------------------

def test_main_stops_subprocess_even_when_iteration_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "MOCK", True)
    monkeypatch.setattr(main, "reset_events_log", lambda: None)
    monkeypatch.setattr(main, "reset_target_db", lambda: None)

    fake_proc = MagicMock()
    monkeypatch.setattr(main, "start_target_app", lambda: fake_proc)

    stopped = []
    monkeypatch.setattr(main, "stop_target_app", lambda proc: stopped.append(proc))

    def _boom(iteration, vuln, target):
        raise RuntimeError("iteration blew up")

    monkeypatch.setattr(main, "run_iteration", _boom)

    with pytest.raises(RuntimeError):
        main.main()

    assert stopped == [fake_proc]


def test_main_stops_subprocess_on_clean_run(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "MOCK", True)
    monkeypatch.setattr(main, "reset_events_log", lambda: None)
    monkeypatch.setattr(main, "reset_target_db", lambda: None)

    fake_proc = MagicMock()
    monkeypatch.setattr(main, "start_target_app", lambda: fake_proc)

    stopped = []
    monkeypatch.setattr(main, "stop_target_app", lambda proc: stopped.append(proc))
    monkeypatch.setattr(main, "run_iteration", lambda iteration, vuln, target: None)

    main.main()

    assert stopped == [fake_proc]


# ---------------------------------------------------------------------------
# main() — real-mode sandbox lifecycle
# ---------------------------------------------------------------------------

def test_main_deletes_sandbox_even_when_iteration_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "MOCK", False)
    monkeypatch.setattr(main, "reset_events_log", lambda: None)

    fake_env_module = MagicMock(inject_env=lambda: None)
    monkeypatch.setitem(sys.modules, "orchestrator.load_daytona_env", fake_env_module)
    monkeypatch.setattr(orchestrator, "load_daytona_env", fake_env_module, raising=False)

    monkeypatch.setattr(
        main, "start_sandbox", lambda: ("sbox-1", "https://sbox-1.daytonaproxy01.net")
    )

    deleted = []
    monkeypatch.setattr(main, "stop_sandbox", lambda sandbox_id: deleted.append(sandbox_id))

    def _boom(iteration, vuln, target):
        raise RuntimeError("iteration blew up")

    monkeypatch.setattr(main, "run_iteration", _boom)

    with pytest.raises(RuntimeError):
        main.main()

    assert deleted == ["sbox-1"]
