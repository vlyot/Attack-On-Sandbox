"""
Tests for dashboard/app.py.

Pure helper functions (taunts, feed-block HTML builders) are called directly
with no Streamlit context. Anything touching st.session_state runs through
Streamlit's AppTest.from_string harness with a small inline script — this
gives a real session_state without invoking main()'s infinite polling loop.
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
# _feed_narration_block
# ---------------------------------------------------------------------------

def test_feed_narration_block_includes_caret_when_incomplete():
    html = app._feed_narration_block("attacker", "spotted it", "detail", complete=False)
    assert "aos-caret" in html
    assert "aos-technical" not in html  # technical hidden until complete


def test_feed_narration_block_omits_caret_when_complete():
    html = app._feed_narration_block("attacker", "spotted it", "detail", complete=True)
    assert "aos-caret" not in html
    assert "aos-technical" in html
    assert "detail" in html


def test_feed_narration_block_escapes_html_in_narration_text():
    html = app._feed_narration_block("defender", "<script>alert(1)</script>", "", complete=True)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_feed_narration_block_role_labels():
    assert "Attacker" in app._feed_narration_block("attacker", "x", "", complete=True)
    assert "Defender" in app._feed_narration_block("defender", "x", "", complete=True)


# ---------------------------------------------------------------------------
# _feed_wire_block
# ---------------------------------------------------------------------------

_REQ = {"method": "POST", "url": "/login", "headers": {}, "body": {"a": 1}}
_RESP = {"status": 401, "body": {"error": "no"}}


def test_feed_wire_block_colors_red_when_not_blocked():
    html = app._feed_wire_block(_REQ, _RESP, False)
    assert "breach" in html
    assert "Breach confirmed" in html


def test_feed_wire_block_colors_red_when_blocked_is_none():
    html = app._feed_wire_block(_REQ, _RESP, None)
    assert "breach" in html


def test_feed_wire_block_colors_green_when_blocked():
    html = app._feed_wire_block(_REQ, _RESP, True)
    assert "blocked" in html
    assert "Exploit blocked" in html


def test_feed_wire_block_escapes_request_and_response():
    req = {"method": "GET", "url": "/<x>", "headers": {}, "body": None}
    html = app._feed_wire_block(req, _RESP, False)
    assert "/&lt;x&gt;" in html


# ---------------------------------------------------------------------------
# _format_curl
# ---------------------------------------------------------------------------

def test_format_curl_includes_method_and_url():
    req = {"method": "POST", "url": "https://x.daytonaproxy01.net/login", "headers": {}, "body": None}
    curl = app._format_curl(req)
    assert curl.startswith("curl -X POST 'https://x.daytonaproxy01.net/login'")


def test_format_curl_includes_headers():
    req = {"method": "GET", "url": "/notes/1", "headers": {"Authorization": "Bearer Mg=="}, "body": None}
    curl = app._format_curl(req)
    assert "-H 'Authorization: Bearer Mg=='" in curl


def test_format_curl_includes_json_body():
    req = {"method": "POST", "url": "/login", "headers": {}, "body": {"username": "bob"}}
    curl = app._format_curl(req)
    assert "-d '{\"username\": \"bob\"}'" in curl


def test_format_curl_escapes_single_quotes_in_body():
    req = {"method": "POST", "url": "/login", "headers": {}, "body": {"username": "' OR '1'='1' --"}}
    curl = app._format_curl(req)
    # Escaped for shell safety: each embedded ' becomes '\''
    assert "'\\''" in curl


def test_format_curl_empty_request_returns_empty_string():
    assert app._format_curl(None) == ""
    assert app._format_curl({}) == ""


def test_feed_wire_block_includes_curl_command():
    html = app._feed_wire_block(_REQ, _RESP, False)
    assert "aos-wire-curl" in html
    assert "curl -X POST" in html


# ---------------------------------------------------------------------------
# _feed_live_timer_block
# ---------------------------------------------------------------------------

def test_feed_live_timer_block_includes_role_label_and_id():
    html = app._feed_live_timer_block("attacker", "requesting…", "aos-timer-attacker-1")
    assert "Attacker" in html
    assert 'id="aos-timer-attacker-1"' in html
    assert "aos-live-timer" in html


def test_feed_live_timer_block_includes_setinterval_script():
    html = app._feed_live_timer_block("defender", "requesting…", "aos-timer-defender-2")
    assert "<script>" in html
    assert "performance.now()" in html
    assert "aos-timer-defender-2" in html


def test_feed_live_timer_block_escapes_label():
    html = app._feed_live_timer_block("attacker", "<script>alert(1)</script>", "t1")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


# ---------------------------------------------------------------------------
# _feed_taunt_block / _feed_divider
# ---------------------------------------------------------------------------

def test_feed_taunt_block_contains_text_and_arrow_tag():
    html = app._feed_taunt_block("gotcha")
    assert "gotcha" in html
    assert "Attacker → Defender" in html


def test_feed_divider_escapes_and_colors():
    html = app._feed_divider("Iteration 1", "#ff0000")
    assert "Iteration 1" in html
    assert "#ff0000" in html


# ---------------------------------------------------------------------------
# _diff_line_class / _feed_diff_block
# ---------------------------------------------------------------------------

def test_diff_line_class_add():
    assert app._diff_line_class("+    new_line()") == "add"


def test_diff_line_class_del():
    assert app._diff_line_class("-    old_line()") == "del"


def test_diff_line_class_context():
    assert app._diff_line_class("    unchanged_line()") == "ctx"


def test_diff_line_class_skips_file_headers_and_hunk_markers():
    assert app._diff_line_class("--- app.py (before)") == ""
    assert app._diff_line_class("+++ app.py (after)") == ""
    assert app._diff_line_class("@@ -1,3 +1,3 @@") == ""


_SAMPLE_DIFF = (
    "--- app.py (before)\n"
    "+++ app.py (after)\n"
    "@@ -1,3 +1,3 @@\n"
    " def login():\n"
    "-    query = f\"SELECT ... {username}\"\n"
    "+    query = \"SELECT ... ?\"\n"
)


def test_feed_diff_block_includes_endpoint_kicker():
    html = app._feed_diff_block("/login", _SAMPLE_DIFF)
    assert "/login" in html
    assert "patch applied" in html


def test_feed_diff_block_drops_file_headers_and_hunk_markers():
    html = app._feed_diff_block("/login", _SAMPLE_DIFF)
    assert "app.py (before)" not in html
    assert "app.py (after)" not in html
    assert "@@" not in html


def test_feed_diff_block_colors_added_and_removed_lines():
    html = app._feed_diff_block("/login", _SAMPLE_DIFF)
    assert 'class="aos-diff-line add"' in html
    assert 'class="aos-diff-line del"' in html
    assert 'class="aos-diff-line ctx"' in html


def test_feed_diff_block_escapes_html_in_diff_lines():
    diff = "+    x = '<script>'\n"
    html = app._feed_diff_block("/login", diff)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# do_reset / render_reset_button — need real st.session_state (AppTest)
# ---------------------------------------------------------------------------

def _run_reset_script(tmp_path, script_body: str) -> AppTest:
    """Build and run an inline AppTest script against dashboard.app, with
    EVENTS_PATH/TARGET_APP_SOURCE/TARGET_APP_DB monkeypatched to tmp_path."""
    script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})
import streamlit as st
from pathlib import Path
from unittest.mock import patch
from dashboard import app

app.EVENTS_PATH = Path({str(tmp_path / "events.json")!r})
app.TARGET_APP_SOURCE = Path({str(tmp_path / "app.py")!r})
app.TARGET_APP_DB = Path({str(tmp_path / "notes.db")!r})

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
st.session_state.iteration = 3
st.session_state.stage = 'verified'
st.session_state.history = [{'iteration': 1}]
with patch.object(app.subprocess, 'run'):
    app.do_reset()
st.session_state['_iteration'] = st.session_state.iteration
st.session_state['_stage'] = st.session_state.stage
st.session_state['_history'] = st.session_state.history
""")
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_iteration"] == 0
    assert at.session_state["_stage"] == "idle"
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
# do_reset_and_run / _orchestrator_is_running — dashboard-owned subprocess
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
fake_proc.poll.return_value = None  # still running
app._orchestrator_proc = fake_proc
st.session_state['_running'] = app._orchestrator_is_running()
""")
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_running"] is True


def test_orchestrator_is_running_false_once_process_exits(tmp_path):
    at = _run_reset_script(tmp_path, """
from unittest.mock import MagicMock
fake_proc = MagicMock()
fake_proc.poll.return_value = 0  # exited
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


def test_render_reset_button_disabled_and_labeled_running_while_dashboard_owned_run_active(tmp_path):
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


def test_render_live_evidence_tab_shows_existing_before_and_after_results(tmp_path):
    script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})
import streamlit as st
from dashboard import app

app.init_state()
st.session_state.wire_request = {{"method": "GET", "url": "/notes/1", "headers": {{}}, "body": None}}
st.session_state.sandbox_url = "https://example.daytona.io"
st.session_state.live_before = {{"status": 200, "body": {{"ok": True}}}}
st.session_state.live_after = {{"status": 403, "body": {{"error": "forbidden"}}}}
app.render_live_evidence_tab()
"""
    at = AppTest.from_string(script)
    at.run()
    assert len(at.exception) == 0, at.exception
    markdown_values = [node.value for node in at.markdown]
    assert any("Before patch" in value for value in markdown_values)
    assert any("After patch" in value for value in markdown_values)


# ---------------------------------------------------------------------------
# apply_event — regression guard, full fixture replay still works
# ---------------------------------------------------------------------------

def test_apply_event_full_iteration_reaches_verified_stage(tmp_path):
    events = [
        {"type": "iteration_start", "iteration": 1, "vulnerability_class": "sqli"},
        {"type": "agent_thinking", "iteration": 1, "vulnerability_class": "sqli",
         "payload": {"agent": "attacker", "label": "Scanning..."}},
        {"type": "attack_sent", "iteration": 1, "vulnerability_class": "sqli",
         "payload": {"request": _REQ, "response": {"status": 200, "body": {}},
                     "agent_reasoning": {"narration": "n", "technical": "t"}}},
        {"type": "patch_applied", "iteration": 1, "vulnerability_class": "sqli",
         "payload": {"diff": "+fix", "patched_source": "src",
                     "agent_reasoning": {"narration": "n2", "technical": "t2"}}},
        {"type": "verified", "iteration": 1, "vulnerability_class": "sqli",
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
st.session_state['_stage'] = st.session_state.stage
st.session_state['_history'] = st.session_state.history
"""
    at = AppTest.from_string(script)
    at.run()
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_stage"] == "verified"
    history_html = "".join(at.session_state["_history"])
    assert "Iteration 1 complete" in history_html
    assert "n2" in history_html  # defender narration frozen into history


# ---------------------------------------------------------------------------
# _feed_raw_stream_block
# ---------------------------------------------------------------------------

def test_feed_raw_stream_block_shows_role_and_caret():
    html = app._feed_raw_stream_block("attacker", '{"method": "POST"')
    assert "Attacker" in html
    assert "aos-caret" in html
    assert '{"method": "POST"' in html


def test_feed_raw_stream_block_escapes_html():
    html = app._feed_raw_stream_block("defender", '<script>alert(1)</script>')
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# apply_event — stream_chunk / llm_usage (Phase 5 streaming)
# ---------------------------------------------------------------------------

def test_apply_event_stream_chunk_appends_to_correct_agent_buffer():
    script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})
import streamlit as st
from dashboard import app
app.init_state()
app.apply_event({{"type": "stream_chunk", "iteration": 1, "vulnerability_class": "sqli",
                   "payload": {{"agent": "attacker", "chunk": "{{\\"method\\""}}}})
st.session_state['_attacker'] = st.session_state.attacker_raw_stream
st.session_state['_defender'] = st.session_state.defender_raw_stream
"""
    at = AppTest.from_string(script)
    at.run()
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_attacker"] == '{"method"'
    assert at.session_state["_defender"] == ""


def test_apply_event_stream_chunk_accumulates_multiple_deltas():
    script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})
import streamlit as st
from dashboard import app
app.init_state()
for chunk in ["ab", "cd", "ef"]:
    app.apply_event({{"type": "stream_chunk", "iteration": 1, "vulnerability_class": "sqli",
                       "payload": {{"agent": "defender", "chunk": chunk}}}})
st.session_state['_defender'] = st.session_state.defender_raw_stream
"""
    at = AppTest.from_string(script)
    at.run()
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_defender"] == "abcdef"


def test_apply_event_llm_usage_increments_counters():
    script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})
import streamlit as st
from dashboard import app
app.init_state()
app.apply_event({{"type": "llm_usage", "iteration": 1, "vulnerability_class": "sqli",
                   "payload": {{"agent": "attacker", "prompt_tokens": 100,
                                "completion_tokens": 20, "total_tokens": 120}}}})
app.apply_event({{"type": "llm_usage", "iteration": 1, "vulnerability_class": "sqli",
                   "payload": {{"agent": "defender", "prompt_tokens": 80,
                                "completion_tokens": 15, "total_tokens": 95}}}})
st.session_state['_calls'] = st.session_state.llm_calls
st.session_state['_tokens'] = st.session_state.llm_tokens
"""
    at = AppTest.from_string(script)
    at.run()
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_calls"] == 2
    assert at.session_state["_tokens"] == 215


def test_iteration_start_clears_raw_stream_buffers():
    script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})
import streamlit as st
from dashboard import app
app.init_state()
st.session_state.attacker_raw_stream = "stale"
st.session_state.defender_raw_stream = "stale"
app.apply_event({{"type": "iteration_start", "iteration": 2, "vulnerability_class": "idor"}})
st.session_state['_attacker'] = st.session_state.attacker_raw_stream
st.session_state['_defender'] = st.session_state.defender_raw_stream
"""
    at = AppTest.from_string(script)
    at.run()
    assert len(at.exception) == 0, at.exception
    assert at.session_state["_attacker"] == ""
    assert at.session_state["_defender"] == ""


def test_raw_stream_block_hidden_once_narration_present():
    script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})
import streamlit as st
from dashboard import app
app.init_state()
st.session_state.iteration = 1
st.session_state.vuln_class = "sqli"
st.session_state.stage = "scanning"
st.session_state.active_agent = "attacker"
st.session_state.attacker_raw_stream = '{{"method": "POST"'

# While streaming raw and no narration yet: raw block shown, no narration card.
blocks_streaming = app._current_iteration_blocks()

# Once narration has landed: raw block disappears, narration card takes over.
st.session_state.attacker_narration = "Spotted it."
blocks_narrated = app._current_iteration_blocks()

st.session_state['_streaming_html'] = "".join(blocks_streaming)
st.session_state['_narrated_html'] = "".join(blocks_narrated)
"""
    at = AppTest.from_string(script)
    at.run()
    assert len(at.exception) == 0, at.exception
    streaming_html = at.session_state["_streaming_html"]
    narrated_html = at.session_state["_narrated_html"]

    assert '{"method": "POST"' in streaming_html
    assert "Spotted it." not in streaming_html

    assert "Spotted it." in narrated_html
    assert '{"method": "POST"' not in narrated_html


def test_live_timer_shown_while_active_agent_has_no_output_yet():
    """Fills the dead-air gap right after agent_thinking fires, before the
    first stream_chunk lands — previously nothing rendered in this window."""
    script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})
import streamlit as st
from dashboard import app
app.init_state()
st.session_state.iteration = 1
st.session_state.vuln_class = "sqli"
st.session_state.stage = "scanning"
st.session_state.active_agent = "attacker"
# No raw_stream, no narration yet.
blocks_waiting = app._current_iteration_blocks()

st.session_state.attacker_raw_stream = '{{"method"'
blocks_streaming = app._current_iteration_blocks()

st.session_state['_waiting_html'] = "".join(blocks_waiting)
st.session_state['_streaming_html'] = "".join(blocks_streaming)
"""
    at = AppTest.from_string(script)
    at.run()
    assert len(at.exception) == 0, at.exception
    waiting_html = at.session_state["_waiting_html"]
    streaming_html = at.session_state["_streaming_html"]

    assert "aos-live-timer" in waiting_html
    assert "aos-live-timer" not in streaming_html
    assert '{"method"' in streaming_html
