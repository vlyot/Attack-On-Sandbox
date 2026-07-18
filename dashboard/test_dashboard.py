"""
Tests for dashboard/app.py.

After the iframe refactor the feed is rendered entirely in JS — Python-side
HTML block builders no longer exist. Tests now cover:
  - TAUNTS lookup (_taunt_for)
  - apply_event: session-state mutations from the event stream
  - _process_events_this_cycle: batch-cap behaviour
  - sandbox_history roster (sidebar data)
  - do_reset / render_reset_button widget behaviour
  - render_sidebar / render_feed_iframe: smoke tests via AppTest
"""

from pathlib import Path

from streamlit.testing.v1 import AppTest

from dashboard import app


# ---------------------------------------------------------------------------
# _taunt_for
# ---------------------------------------------------------------------------

def test_taunt_for_returns_correct_line_per_vuln_class():
    assert app._taunt_for("sqli") == "Thanks for the login — didn't even need a password."
    assert app._taunt_for("idor") == "Appreciate Annie's notes — didn't need to be her to read them."
    assert app._taunt_for("missing_auth") == "Reset's done — nobody even asked who I was."


def test_taunt_for_unknown_vuln_class_returns_empty():
    assert app._taunt_for("xss") == ""
    assert app._taunt_for("") == ""


# ---------------------------------------------------------------------------
# apply_event — session-state mutations
# ---------------------------------------------------------------------------

_REQ  = {"method": "POST", "url": "/login", "headers": {}, "body": {"a": 1}}
_RESP = {"status": 401, "body": {"error": "no"}}


def _apply_script(events_repr: str) -> str:
    return f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})
import streamlit as st
from dashboard import app
app.init_state()
{events_repr}
"""


def test_apply_event_iteration_start_sets_stage_and_clears_narration():
    script = _apply_script("""
st.session_state.attacker_narration = "old"
st.session_state.defender_narration = "old"
app.apply_event({"type": "iteration_start", "iteration": 2, "vulnerability_class": "idor"})
st.session_state['_stage']    = st.session_state.stage
st.session_state['_iter']     = st.session_state.iteration
st.session_state['_atk_narr'] = st.session_state.attacker_narration
st.session_state['_def_narr'] = st.session_state.defender_narration
""")
    at = AppTest.from_string(script); at.run()
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_stage"]    == "scanning"
    assert at.session_state["_iter"]     == 2
    assert at.session_state["_atk_narr"] == ""
    assert at.session_state["_def_narr"] == ""


def test_apply_event_narration_chunk_accumulates():
    script = _apply_script("""
app.apply_event({"type": "iteration_start", "iteration": 1, "vulnerability_class": "sqli"})
for ch in "Hello":
    app.apply_event({"type": "narration_chunk", "iteration": 1, "vulnerability_class": "sqli",
                     "payload": {"agent": "attacker", "char": ch}})
st.session_state['_narr'] = st.session_state.attacker_narration
""")
    at = AppTest.from_string(script); at.run()
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_narr"] == "Hello"


def test_apply_event_stream_chunk_returns_true_hot_path():
    script = _apply_script("""
result = app.apply_event({"type": "stream_chunk", "iteration": 1, "vulnerability_class": "sqli",
                           "payload": {"agent": "attacker", "chunk": "abc"}})
st.session_state['_result'] = result
st.session_state['_has_raw_field'] = hasattr(st.session_state, 'attacker_raw_stream')
""")
    at = AppTest.from_string(script); at.run()
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_result"] is True
    assert at.session_state["_has_raw_field"] is False


def test_apply_event_llm_usage_increments_counters():
    script = _apply_script("""
app.apply_event({"type": "llm_usage", "iteration": 1, "vulnerability_class": "sqli",
                 "payload": {"total_tokens": 120}})
app.apply_event({"type": "llm_usage", "iteration": 1, "vulnerability_class": "sqli",
                 "payload": {"total_tokens": 95}})
st.session_state['_calls']  = st.session_state.llm_calls
st.session_state['_tokens'] = st.session_state.llm_tokens
""")
    at = AppTest.from_string(script); at.run()
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_calls"]  == 2
    assert at.session_state["_tokens"] == 215


def test_apply_event_attack_sent_sets_stage_breached():
    script = _apply_script(f"""
app.apply_event({{"type": "iteration_start", "iteration": 1, "vulnerability_class": "sqli"}})
app.apply_event({{"type": "attack_sent", "iteration": 1, "vulnerability_class": "sqli",
                  "payload": {{"request": {_REQ!r}, "response": {_RESP!r},
                               "agent_reasoning": {{"narration": "n", "technical": "t"}}}}}})
st.session_state['_stage']        = st.session_state.stage
st.session_state['_wire_request'] = st.session_state.wire_request
""")
    at = AppTest.from_string(script); at.run()
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_stage"]        == "breached"
    assert at.session_state["_wire_request"] == _REQ


def test_apply_event_full_iteration_reaches_verified_stage():
    events = [
        {"type": "iteration_start", "iteration": 1, "vulnerability_class": "sqli"},
        {"type": "agent_thinking",  "iteration": 1, "vulnerability_class": "sqli",
         "payload": {"agent": "attacker", "label": "Scanning..."}},
        {"type": "attack_sent",     "iteration": 1, "vulnerability_class": "sqli",
         "payload": {"request": _REQ, "response": {"status": 200, "body": {}},
                     "agent_reasoning": {"narration": "n", "technical": "t"}}},
        {"type": "patch_applied",   "iteration": 1, "vulnerability_class": "sqli",
         "payload": {"diff": "+fix", "patched_source": "src",
                     "agent_reasoning": {"narration": "n2", "technical": "t2"}}},
        {"type": "verified",        "iteration": 1, "vulnerability_class": "sqli",
         "payload": {"request": _REQ, "response": _RESP, "exploit_blocked": True}},
        {"type": "iteration_complete", "iteration": 1, "vulnerability_class": "sqli"},
    ]
    script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})
import streamlit as st
from dashboard import app
app.init_state()
for event in {events!r}:
    app.apply_event(event)
st.session_state['_stage']   = st.session_state.stage
st.session_state['_blocked'] = st.session_state.wire_blocked
"""
    at = AppTest.from_string(script); at.run()
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_stage"]   == "verified"
    assert at.session_state["_blocked"] is True


# ---------------------------------------------------------------------------
# _process_events_this_cycle — batch-cap behaviour (Python still runs this
# to drain narration/stream chunks before the JS iframe takes over)
# ---------------------------------------------------------------------------

def _stream_chunk_events(chunks, agent="attacker", iteration=1, vuln="sqli"):
    return [
        {"type": "stream_chunk", "iteration": iteration, "vulnerability_class": vuln,
         "payload": {"agent": agent, "chunk": c}}
        for c in chunks
    ]


def test_process_events_caps_stream_chunk_chars_per_cycle():
    script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})
import streamlit as st
from dashboard import app
app.init_state()
raw    = {_stream_chunk_events(["ab","cd","ef","gh","ij","kl","mn","op","qr","st"])!r}
tagged = [(e, i+1) for i, e in enumerate(raw)]
last_offset, had_structural, _ = app._process_events_this_cycle(tagged)
st.session_state['_last_offset']    = last_offset
st.session_state['_had_structural'] = had_structural
"""
    at = AppTest.from_string(script); at.run()
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_last_offset"]    == 8   # consumed through "op" (16 chars, cap=15)
    assert at.session_state["_had_structural"] is False


def test_process_events_stream_chunk_does_not_starve_structural_events():
    script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})
import streamlit as st
from dashboard import app
app.init_state()
raw_stream = {_stream_chunk_events(["x" * 20])!r}
usage = {{"type": "llm_usage", "iteration": 1, "vulnerability_class": "sqli",
          "payload": {{"total_tokens": 2}}}}
raw    = raw_stream + [usage]
tagged = [(e, i+1) for i, e in enumerate(raw)]
last_offset, had_structural, _ = app._process_events_this_cycle(tagged)
st.session_state['_last_offset']    = last_offset
st.session_state['_calls']          = st.session_state.llm_calls
st.session_state['_had_structural'] = had_structural
"""
    at = AppTest.from_string(script); at.run()
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_last_offset"]    == 2
    assert at.session_state["_calls"]          == 1
    assert at.session_state["_had_structural"] is True


def test_process_events_narration_only_cycle_not_structural():
    script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})
import streamlit as st
from dashboard import app
app.init_state()
raw = [
    {{"type": "narration_chunk", "iteration": 1, "vulnerability_class": "sqli",
      "payload": {{"agent": "attacker", "char": "x"}}}}
    for _ in range(5)
]
tagged = [(e, i+1) for i, e in enumerate(raw)]
last_offset, had_structural, _ = app._process_events_this_cycle(tagged)
st.session_state['_had_structural'] = had_structural
st.session_state['_last_offset']    = last_offset
"""
    at = AppTest.from_string(script); at.run()
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_had_structural"] is False
    assert at.session_state["_last_offset"]    == 5


def test_process_events_structural_event_sets_flag():
    script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})
import streamlit as st
from dashboard import app
app.init_state()
raw    = [{{"type": "iteration_start", "iteration": 1, "vulnerability_class": "sqli"}}]
tagged = [(e, i+1) for i, e in enumerate(raw)]
last_offset, had_structural, _ = app._process_events_this_cycle(tagged)
st.session_state['_had_structural'] = had_structural
"""
    at = AppTest.from_string(script); at.run()
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_had_structural"] is True


# ---------------------------------------------------------------------------
# sandbox_history — sidebar roster data
# ---------------------------------------------------------------------------

def test_sandbox_ready_appends_to_sandbox_history():
    script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})
import streamlit as st
from dashboard import app
app.init_state()
app.apply_event({{"type": "sandbox_ready", "iteration": 1, "vulnerability_class": "sqli",
                   "payload": {{"sandbox_id": "sbox-1", "url": "https://a.daytona.io",
                                "region": "us-east-1", "created_at": "t1", "spec": {{}}}}}})
app.apply_event({{"type": "sandbox_ready", "iteration": 2, "vulnerability_class": "idor",
                   "payload": {{"sandbox_id": "sbox-2", "url": "https://b.daytona.io",
                                "region": "us-west-1", "created_at": "t2", "spec": {{}}}}}})
st.session_state['_history'] = list(st.session_state.sandbox_history)
"""
    at = AppTest.from_string(script); at.run()
    assert len(at.exception) == 0, at.exception
    history = at.session_state["_history"]
    assert len(history) == 2
    assert history[0]["id"]     == "sbox-1"
    assert history[1]["id"]     == "sbox-2"
    assert history[0]["status"] == "running"


def test_verified_marks_latest_sandbox_history_entry_verified():
    script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})
import streamlit as st
from dashboard import app
app.init_state()
app.apply_event({{"type": "sandbox_ready", "iteration": 1, "vulnerability_class": "sqli",
                   "payload": {{"sandbox_id": "sbox-1", "url": "https://a.daytona.io",
                                "region": "us-east-1", "created_at": "t1", "spec": {{}}}}}})
app.apply_event({{"type": "verified", "iteration": 1, "vulnerability_class": "sqli",
                   "payload": {{"request": {_REQ!r}, "response": {_RESP!r}, "exploit_blocked": True}}}})
st.session_state['_status'] = st.session_state.sandbox_history[-1]["status"]
"""
    at = AppTest.from_string(script); at.run()
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_status"] == "verified"


def test_sandbox_destroyed_marks_matching_history_entry():
    script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})
import streamlit as st
from dashboard import app
app.init_state()
app.apply_event({{"type": "sandbox_ready", "iteration": 1, "vulnerability_class": "sqli",
                   "payload": {{"sandbox_id": "sbox-1", "url": "https://a.daytona.io",
                                "region": "us-east-1", "created_at": "t1", "spec": {{}}}}}})
app.apply_event({{"type": "sandbox_ready", "iteration": 2, "vulnerability_class": "idor",
                   "payload": {{"sandbox_id": "sbox-2", "url": "https://b.daytona.io",
                                "region": "us-west-1", "created_at": "t2", "spec": {{}}}}}})
app.apply_event({{"type": "sandbox_destroyed", "iteration": 1, "vulnerability_class": "sqli",
                   "payload": {{"sandbox_id": "sbox-1"}}}})
st.session_state['_history'] = list(st.session_state.sandbox_history)
"""
    at = AppTest.from_string(script); at.run()
    assert len(at.exception) == 0, at.exception
    history = at.session_state["_history"]
    assert history[0]["status"] == "destroyed"
    assert history[1]["status"] == "running"


# ---------------------------------------------------------------------------
# _sbox_card_html
# ---------------------------------------------------------------------------

def test_sbox_card_html_includes_id_url_and_status():
    html = app._sbox_card_html({
        "id": "sbox-1", "url": "https://a.daytona.io", "region": "us-east-1",
        "status": "running", "iteration": 1, "vuln_class": "sqli",
    })
    assert "sbox-1" in html
    assert "https://a.daytona.io" in html
    assert "running" in html
    assert "us-east-1" in html


def test_sbox_card_html_escapes_fields():
    html = app._sbox_card_html({
        "id": "<script>", "url": "https://a.daytona.io", "region": "",
        "status": "running", "iteration": 1, "vuln_class": "",
    })
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# do_reset / render_reset_button
# ---------------------------------------------------------------------------

def _run_reset_script(tmp_path, script_body: str) -> AppTest:
    script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})
import streamlit as st
from pathlib import Path
from unittest.mock import patch
from dashboard import app

app.EVENTS_PATH        = Path({str(tmp_path / "events.json")!r})
app.STATIC_EVENTS_PATH = Path({str(tmp_path / "static" / "events.json")!r})
app.TARGET_APP_SOURCE  = Path({str(tmp_path / "app.py")!r})
app.TARGET_APP_DB      = Path({str(tmp_path / "notes.db")!r})

{script_body}
"""
    at = AppTest.from_string(script)
    at.run()
    return at


def test_do_reset_removes_events_json(tmp_path):
    (tmp_path / "events.json").write_text("stale\n", encoding="utf-8")
    at = _run_reset_script(tmp_path, """
with patch.object(app.subprocess, 'run'):
    app.do_reset()
st.session_state['_ok'] = not app.EVENTS_PATH.exists()
""")
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_ok"] is True


def test_do_reset_removes_notes_db(tmp_path):
    (tmp_path / "notes.db").write_bytes(b"stale")
    at = _run_reset_script(tmp_path, """
with patch.object(app.subprocess, 'run'):
    app.do_reset()
st.session_state['_ok'] = not app.TARGET_APP_DB.exists()
""")
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_ok"] is True


def test_do_reset_restores_app_py_via_git_checkout(tmp_path):
    at = _run_reset_script(tmp_path, """
with patch.object(app.subprocess, 'run') as mock_run:
    app.do_reset()
st.session_state['_call_args'] = mock_run.call_args.args[0]
""")
    assert len(at.exception) == 0, at.exception
    call_args = at.session_state["_call_args"]
    assert call_args[0] == "git"
    assert call_args[1] == "checkout"
    assert "app.py" in call_args[-1]


def test_do_reset_clears_session_state_back_to_defaults(tmp_path):
    at = _run_reset_script(tmp_path, """
app.init_state()
st.session_state.iteration       = 3
st.session_state.stage           = 'verified'
st.session_state.sandbox_history = [{'iteration': 1}]
with patch.object(app.subprocess, 'run'):
    app.do_reset()
st.session_state['_iteration'] = st.session_state.iteration
st.session_state['_stage']     = st.session_state.stage
st.session_state['_history']   = st.session_state.sandbox_history
""")
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_iteration"] == 0
    assert at.session_state["_stage"]     == "idle"
    assert at.session_state["_history"]   == []


def test_do_reset_clears_sandbox_history(tmp_path):
    at = _run_reset_script(tmp_path, """
app.init_state()
st.session_state.sandbox_history = [{'id': 'sbox-1'}]
with patch.object(app.subprocess, 'run'):
    app.do_reset()
st.session_state['_history'] = st.session_state.sandbox_history
""")
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_history"] == []


def test_render_reset_button_disabled_while_iteration_in_flight(tmp_path):
    at = _run_reset_script(tmp_path, """
app.init_state()
st.session_state.stage = 'breached'
app.render_reset_button()
""")
    assert len(at.exception) == 0, at.exception
    assert at.button[0].disabled is True


def test_render_reset_button_enabled_when_idle(tmp_path):
    at = _run_reset_script(tmp_path, """
app.init_state()
st.session_state.stage = 'idle'
app.render_reset_button()
""")
    assert len(at.exception) == 0, at.exception
    assert at.button[0].disabled is False


def test_render_reset_button_enabled_when_verified(tmp_path):
    at = _run_reset_script(tmp_path, """
app.init_state()
st.session_state.stage = 'verified'
app.render_reset_button()
""")
    assert len(at.exception) == 0, at.exception
    assert at.button[0].disabled is False


# ---------------------------------------------------------------------------
# Orchestrator subprocess lifecycle
# ---------------------------------------------------------------------------

def test_orchestrator_is_running_false_when_no_process_started(tmp_path):
    at = _run_reset_script(tmp_path, """
st.session_state['_running'] = app._orchestrator_is_running()
""")
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_running"] is False


def test_orchestrator_is_running_true_while_process_alive(tmp_path):
    at = _run_reset_script(tmp_path, """
from unittest.mock import MagicMock
fake_proc = MagicMock()
fake_proc.poll.return_value = None
app._orchestrator_proc = fake_proc
st.session_state['_running'] = app._orchestrator_is_running()
""")
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_running"] is True


def test_orchestrator_is_running_false_once_process_exits(tmp_path):
    at = _run_reset_script(tmp_path, """
from unittest.mock import MagicMock
fake_proc = MagicMock()
fake_proc.poll.return_value = 0
app._orchestrator_proc = fake_proc
st.session_state['_running'] = app._orchestrator_is_running()
""")
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_running"] is False


def test_do_reset_and_run_launches_orchestrator_script(tmp_path):
    at = _run_reset_script(tmp_path, """
with patch.object(app.subprocess, 'run'):
    with patch.object(app.subprocess, 'Popen') as mock_popen:
        app.do_reset_and_run()
        st.session_state['_popen_args'] = mock_popen.call_args.args[0]
""")
    assert len(at.exception) == 0, at.exception
    popen_args = at.session_state["_popen_args"]
    assert popen_args[0] == app.sys.executable
    assert "main.py" in popen_args[-1]


def test_render_reset_button_labeled_running_while_dashboard_owned_run_active(tmp_path):
    at = _run_reset_script(tmp_path, """
from unittest.mock import MagicMock
app.init_state()
st.session_state.stage = 'idle'
fake_proc = MagicMock()
fake_proc.poll.return_value = None
app._orchestrator_proc = fake_proc
app.render_reset_button()
""")
    assert len(at.exception) == 0, at.exception
    assert at.button[0].disabled is True
    assert at.button[0].label == "Running…"


# ---------------------------------------------------------------------------
# render_sidebar — smoke test via AppTest
# ---------------------------------------------------------------------------

def test_render_sidebar_shows_empty_state_with_no_sandboxes(tmp_path):
    at = _run_reset_script(tmp_path, """
app.init_state()
app.render_sidebar()
""")
    assert len(at.exception) == 0, at.exception
    html_bodies = [n.proto.body for n in at.get("html")]
    assert any("Waiting for the first sandbox" in body for body in html_bodies)


def test_render_sidebar_lists_all_sandboxes_most_recent_first(tmp_path):
    at = _run_reset_script(tmp_path, """
app.init_state()
st.session_state.sandbox_history = [
    {'id': 'sbox-1', 'url': 'https://a.daytona.io', 'region': 'us-east-1',
     'status': 'destroyed', 'iteration': 1, 'vuln_class': 'sqli'},
    {'id': 'sbox-2', 'url': 'https://b.daytona.io', 'region': 'us-west-1',
     'status': 'running', 'iteration': 2, 'vuln_class': 'idor'},
]
app.render_sidebar()
""")
    assert len(at.exception) == 0, at.exception
    html_bodies = [n.proto.body for n in at.get("html")]
    joined = "".join(html_bodies)
    assert "sbox-1" in joined and "sbox-2" in joined
    assert joined.index("sbox-2") < joined.index("sbox-1")
