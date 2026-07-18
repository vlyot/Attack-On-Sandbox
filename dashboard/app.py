"""
Attack on Sandbox — Streamlit dashboard.

Architecture:
  - Streamlit (Python) owns: sidebar sandbox roster, nav bar + round gallery,
    Reset button, and session state for those low-frequency elements.
  - The live feed is a self-contained HTML+JS iframe (st.iframe)
    that polls events.json directly via fetch/Range requests and patches its
    own DOM — zero Streamlit reruns touch the feed, so there is no flashing.
"""

import json
import subprocess
import sys
import time
from pathlib import Path

import streamlit as st

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

EVENTS_PATH = Path("events.json")
STATIC_EVENTS_PATH = Path(__file__).parent / "static" / "events.json"
POLL_INTERVAL_S = 2.0   # Python-side poll — only updates sidebar/nav/gallery (iframe polls independently at 120ms)

STAGE_COLORS = {
    "idle":      "#9b9797",
    "pending":   "#9b9797",
    "scanning":  "#b68235",
    "breached":  "#e53935",
    "analysing": "#b68235",
    "patched":   "#b68235",
    "verified":  "#43a047",
}

VULN_LABELS = {
    "sqli":         "SQL Injection",
    "idor":         "IDOR",
    "missing_auth": "Missing Auth",
}

TAUNTS = {
    "sqli":         "Thanks for the login — didn't even need a password.",
    "idor":         "Appreciate Annie's notes — didn't need to be her to read them.",
    "missing_auth": "Reset's done — nobody even asked who I was.",
}


def _taunt_for(vuln_class: str) -> str:
    return TAUNTS.get(vuln_class, "")

# ---------------------------------------------------------------------------
# State initialisation
# ---------------------------------------------------------------------------

_STATE_DEFAULTS: dict = {
    "sandbox_url":        "",
    "sandbox_id":         "",
    "sandbox_region":     "",
    "sandbox_created_at":  "",
    "sandbox_spec":       {},
    "sandbox_status":     "idle",
    "sandbox_history":    [],
    "iteration":          0,
    "stage":              "idle",
    "vuln_class":         "",
    "active_agent":       None,
    "attacker_narration": "",
    "attacker_technical": "",
    "defender_narration": "",
    "defender_technical": "",
    "wire_request":       None,
    "wire_response":      None,
    "wire_blocked":       None,
    "diff":               "",
    "llm_calls":           0,
    "llm_tokens":          0,
    # Python-side byte cursor into events.json
    "cursor":             0,
    # Cache keys for sidebar and nav+gallery
    "_sidebar_cache_key":   "",
    "_sidebar_html_cache":  "",
    "_nav_cache_key":       "",
    "_nav_html_cache":      "",
}


def init_state() -> None:
    for key, default in _STATE_DEFAULTS.items():
        if key not in st.session_state:
            st.session_state[key] = (
                default.copy() if isinstance(default, (list, dict)) else default
            )


# ---------------------------------------------------------------------------
# Sync events.json → dashboard/static/events.json
# Streamlit serves dashboard/static/ at /app/static/ so the iframe JS can
# fetch it without CORS issues.
# ---------------------------------------------------------------------------

def sync_events_file() -> None:
    """Copy events.json to the static folder the iframe can fetch."""
    STATIC_EVENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    if EVENTS_PATH.exists():
        STATIC_EVENTS_PATH.write_bytes(EVENTS_PATH.read_bytes())
    elif STATIC_EVENTS_PATH.exists():
        STATIC_EVENTS_PATH.unlink()


# ---------------------------------------------------------------------------
# Reset control
# ---------------------------------------------------------------------------

TARGET_APP_SOURCE = Path("target-app/app.py")
TARGET_APP_DB = Path("target-app/notes.db")
ORCHESTRATOR_SCRIPT = Path("orchestrator/main.py")
REPO_ROOT = Path(__file__).resolve().parent.parent

_orchestrator_proc: subprocess.Popen | None = None


def _orchestrator_is_running() -> bool:
    return _orchestrator_proc is not None and _orchestrator_proc.poll() is None


def _kill_any_orchestrator() -> None:
    """Kill any python process running orchestrator/main.py, whether or not
    this dashboard instance spawned it."""
    global _orchestrator_proc
    # Kill the dashboard-owned process first
    if _orchestrator_proc is not None and _orchestrator_proc.poll() is None:
        _orchestrator_proc.terminate()
        try:
            _orchestrator_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _orchestrator_proc.kill()
            _orchestrator_proc.wait(timeout=3)
    _orchestrator_proc = None
    # Also kill any external orchestrator processes (started from terminal)
    try:
        import psutil
        for proc in psutil.process_iter(["pid", "cmdline"]):
            cmdline = " ".join(proc.info.get("cmdline") or [])
            if "orchestrator" in cmdline and "main.py" in cmdline:
                proc.terminate()
    except Exception:
        pass


def do_reset() -> None:
    _kill_any_orchestrator()
    for p in (EVENTS_PATH, STATIC_EVENTS_PATH):
        try:
            p.unlink(missing_ok=True)
        except OSError:
            pass
    subprocess.run(["git", "checkout", "--", str(TARGET_APP_SOURCE)], check=False)
    if TARGET_APP_DB.exists():
        TARGET_APP_DB.unlink()
    for key in list(_STATE_DEFAULTS):
        st.session_state.pop(key, None)
    init_state()


def do_abort() -> None:
    """Kill the orchestrator process and clear all state — immediate stop."""
    do_reset()


def do_reset_and_run() -> None:
    global _orchestrator_proc
    do_reset()
    _orchestrator_proc = subprocess.Popen(
        [sys.executable, str(ORCHESTRATOR_SCRIPT)],
        cwd=str(REPO_ROOT),
    )


def render_reset_button() -> None:
    dashboard_owned_run = _orchestrator_is_running()
    external_run_in_flight = st.session_state.stage not in ("idle", "verified")
    stuck = external_run_in_flight and not dashboard_owned_run

    if dashboard_owned_run:
        col1, col2 = st.columns(2)
        with col1:
            st.button("Running…", disabled=True, help="A run is in progress.")
        with col2:
            if st.button("Abort", type="primary", help="Immediately kill the run and reset."):
                do_abort()
                st.rerun()
        return

    if stuck:
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Reset & Run", help="Clears stuck state and starts a fresh run."):
                do_reset_and_run()
                st.rerun()
        with col2:
            if st.button("Clear", help="Clears stuck state without starting a new run."):
                do_reset()
                st.rerun()
        return

    if st.button("Reset & Run", help="Clears state and starts a fresh 3-iteration run."):
        do_reset_and_run()
        st.rerun()


# ---------------------------------------------------------------------------
# Lightweight Python-side event scan
# Only reads structural events needed to update sidebar / nav state.
# narration_chunk and stream_chunk are ignored here — the JS iframe handles them.
# ---------------------------------------------------------------------------

def _scan_new_events() -> None:
    """Read events.json from Python cursor, update sidebar/llm state only."""
    if not EVENTS_PATH.exists():
        return
    s = st.session_state
    with EVENTS_PATH.open("rb") as fh:
        fh.seek(s.cursor)
        while True:
            line = fh.readline()
            if not line:
                break
            stripped = line.strip()
            if not stripped:
                continue
            try:
                event = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            t = event.get("type", "")
            p = event.get("payload", {})

            if t == "sandbox_ready":
                s.sandbox_url    = p.get("url", "")
                s.sandbox_id     = p.get("sandbox_id", "")
                s.sandbox_region = p.get("region", "")
                s.sandbox_created_at = p.get("created_at", "")
                s.sandbox_spec   = p.get("spec", {})
                s.sandbox_status = "running"
                s.iteration      = event.get("iteration", 0)
                s.vuln_class     = event.get("vulnerability_class", "")
                s.sandbox_history.append({
                    "id":         p.get("sandbox_id", ""),
                    "url":        p.get("url", ""),
                    "region":     p.get("region", ""),
                    "created_at": p.get("created_at", ""),
                    "status":     "running",
                    "iteration":  event.get("iteration", 0),
                    "vuln_class": event.get("vulnerability_class", ""),
                })
            elif t == "iteration_start":
                s.stage      = "scanning"
                s.iteration  = event.get("iteration", s.iteration)
                s.vuln_class = event.get("vulnerability_class", "")
            elif t == "agent_thinking":
                if p.get("agent") == "defender":
                    s.stage = "analysing"
            elif t == "attack_sent":
                s.stage = "breached"
            elif t == "patch_applied":
                s.stage = "patched"
            elif t == "verified":
                s.stage = "verified"
                s.sandbox_status = "verified"
                if s.sandbox_history:
                    s.sandbox_history[-1]["status"] = "verified"
            elif t == "sandbox_destroyed":
                sbox_id = p.get("sandbox_id", "")
                for entry in s.sandbox_history:
                    if entry["id"] == sbox_id:
                        entry["status"] = "destroyed"
                        break
            elif t == "llm_usage":
                s.llm_calls  += 1
                s.llm_tokens += p.get("total_tokens", 0)

            s.cursor = fh.tell()


# ---------------------------------------------------------------------------
# apply_event — full event dispatcher (used by tests and _process_events_this_cycle)
# The JS iframe owns all feed rendering; Python tracks state so tests can
# assert on session_state after replaying an event sequence.
# ---------------------------------------------------------------------------

def apply_event(event: dict) -> bool:
    """Apply one event to session state. Returns True for hot-path events
    (narration_chunk, stream_chunk) that don't need a Streamlit rerun."""
    t = event.get("type", "")
    p = event.get("payload", {})
    s = st.session_state

    if t == "sandbox_ready":
        s.sandbox_url        = p.get("url", "")
        s.sandbox_id         = p.get("sandbox_id", "")
        s.sandbox_region     = p.get("region", "")
        s.sandbox_created_at = p.get("created_at", "")
        s.sandbox_spec       = p.get("spec", {})
        s.sandbox_status     = "running"
        s.iteration          = event.get("iteration", 0)
        s.vuln_class         = event.get("vulnerability_class", "")
        s.sandbox_history.append({
            "id":         p.get("sandbox_id", ""),
            "url":        p.get("url", ""),
            "region":     p.get("region", ""),
            "created_at": p.get("created_at", ""),
            "status":     "running",
            "iteration":  event.get("iteration", 0),
            "vuln_class": event.get("vulnerability_class", ""),
        })
        s.wire_request = None; s.wire_response = None; s.wire_blocked = None
        s.diff = ""

    elif t == "iteration_start":
        s.stage              = "scanning"
        s.iteration          = event.get("iteration", s.iteration)
        s.vuln_class         = event.get("vulnerability_class", "")
        s.attacker_narration = ""
        s.attacker_technical = ""
        s.defender_narration = ""
        s.defender_technical = ""
        s.wire_request       = None
        s.wire_response      = None
        s.wire_blocked       = None
        s.diff               = ""
        s.active_agent       = None

    elif t == "agent_thinking":
        s.active_agent = p.get("agent")
        if p.get("agent") == "defender":
            s.stage = "analysing"

    elif t == "narration_chunk":
        agent = p.get("agent")
        char  = p.get("char", "")
        if agent == "attacker":
            s.attacker_narration += char
        elif agent == "defender":
            s.defender_narration += char
        return True

    elif t == "stream_chunk":
        return True

    elif t == "llm_usage":
        s.llm_calls  += 1
        s.llm_tokens += p.get("total_tokens", 0)

    elif t == "attack_sent":
        s.stage              = "breached"
        s.wire_request       = p.get("request")
        s.wire_response      = p.get("response")
        s.wire_blocked       = False
        s.active_agent       = None
        r = p.get("agent_reasoning", {})
        if not s.attacker_narration:
            s.attacker_narration = r.get("narration", "")
        s.attacker_technical = r.get("technical", "")

    elif t == "patch_applied":
        s.stage              = "patched"
        s.diff               = p.get("diff", "")
        s.active_agent       = None
        r = p.get("agent_reasoning", {})
        if not s.defender_narration:
            s.defender_narration = r.get("narration", "")
        s.defender_technical = r.get("technical", "")

    elif t == "verified":
        s.stage         = "verified"
        s.sandbox_status = "verified"
        s.wire_request  = p.get("request")
        s.wire_response = p.get("response")
        s.wire_blocked  = p.get("exploit_blocked", False)
        if s.sandbox_history:
            s.sandbox_history[-1]["status"] = "verified"

    elif t == "iteration_complete":
        s.active_agent = None

    elif t == "sandbox_destroyed":
        sbox_id = p.get("sandbox_id", "")
        for entry in s.sandbox_history:
            if entry["id"] == sbox_id:
                entry["status"] = "destroyed"
                break

    return False


# ---------------------------------------------------------------------------
# _process_events_this_cycle — used by the Python poll loop to drain events
# ---------------------------------------------------------------------------

MAX_EVENTS_PER_CYCLE        = 50
MAX_NARRATION_CHARS_PER_CYCLE = 6
NARRATION_CHAR_DELAY_S      = 0.033
MAX_STREAM_CHARS_PER_CYCLE  = 15
STREAM_CHAR_DELAY_S         = 0.01


def _process_events_this_cycle(
    tagged: list[tuple[dict, int]],
) -> tuple[int | None, bool, bool]:
    """Apply events from the queue up to per-cycle caps.

    Returns (last_consumed_offset, had_structural_event, has_more).
    The JS iframe handles rendering; Python processes events only to keep
    sidebar/nav state in sync and to give tests an apply_event path.
    """
    narration_chars = 0
    stream_chars    = 0
    processed       = 0
    had_structural  = False
    last_offset: int | None = None

    for event, end_offset in tagged:
        t = event.get("type")
        if t == "narration_chunk":
            if narration_chars >= MAX_NARRATION_CHARS_PER_CYCLE:
                return last_offset, had_structural, True
            apply_event(event)
            narration_chars += 1
            processed       += 1
            last_offset      = end_offset
            time.sleep(NARRATION_CHAR_DELAY_S)
        elif t == "stream_chunk":
            if stream_chars >= MAX_STREAM_CHARS_PER_CYCLE:
                return last_offset, had_structural, True
            apply_event(event)
            stream_chars += len(event.get("payload", {}).get("chunk", ""))
            processed    += 1
            last_offset   = end_offset
            time.sleep(STREAM_CHAR_DELAY_S)
        else:
            if processed >= MAX_EVENTS_PER_CYCLE:
                return last_offset, had_structural, True
            apply_event(event)
            processed   += 1
            last_offset  = end_offset
            had_structural = True

    return last_offset, had_structural, False


# ---------------------------------------------------------------------------
# CSS — injected once into the Streamlit shell (no feed classes needed here;
# those live inside the iframe)
# ---------------------------------------------------------------------------

_SHELL_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@600&family=Lora:wght@400;600&display=swap');

:root {
    --color-bg: #f3f2f2;
    --color-text: #201f1d;
    --color-accent: #b68235;
    --color-divider: rgba(32,31,29,0.16);
    --font-heading: 'Cormorant Garamond', Georgia, serif;
    --font-body: 'Lora', Georgia, serif;
    --danger: #e53935;
    --safe: #43a047;
    --feed-bg: #1e1e2e;
    --feed-muted: rgba(248,244,244,0.55);
}

html, body,
[data-testid="stApp"],
[data-testid="stAppViewContainer"],
[data-testid="stMain"],
[data-testid="stHeader"],
[data-testid="stMainBlockContainer"] {
    background-color: var(--color-bg) !important;
    color: var(--color-text) !important;
}
[data-testid="stApp"] * { color: inherit; }
body { font-family: var(--font-body); }
[data-testid="stHeader"] { background-color: transparent !important; }
[data-testid="baseButton-secondary"] {
    font-family: var(--font-heading) !important;
    color: var(--color-text) !important;
    border-color: var(--color-divider) !important;
    background: transparent !important;
}
[data-testid="baseButton-secondary"]:hover:not(:disabled) {
    border-color: var(--color-accent) !important;
    color: var(--color-accent) !important;
}

.aos-brand { font-family: var(--font-heading); font-weight: 600; font-size: 18px; color: var(--color-text); }
.aos-tagline { font-size: 11px; color: rgba(32,31,29,0.55); letter-spacing: 0.02em; }
.aos-tag {
    display: inline-flex; align-items: center; font-size: 11px;
    padding: 3px 10px; border-radius: 3px;
    border: 1px solid var(--color-accent); color: var(--color-accent);
}

[data-testid="stSidebar"] { background: var(--feed-bg) !important; }
[data-testid="stSidebar"] * { color: rgba(248,244,244,0.92) !important; }
.aos-sidebar-title {
    font-family: var(--font-heading); font-weight: 600; font-size: 15px;
    letter-spacing: 0.02em; margin-bottom: 2px;
}
.aos-sidebar-usage {
    font-family: ui-monospace, Menlo, monospace; font-size: 11px;
    color: var(--feed-muted); margin-bottom: 4px;
}
.aos-sbox-card {
    display: flex; flex-direction: column; gap: 6px;
    padding: 10px 12px; margin-bottom: 10px;
    border: 1px solid rgba(248,244,244,0.16); border-radius: 6px;
    background: rgba(255,255,255,0.03);
}
.aos-sbox-card.running  { border-color: var(--color-accent); }
.aos-sbox-card.verified { border-color: var(--safe); }
.aos-sbox-card.destroyed { opacity: 0.55; }
.aos-sbox-tags { display: flex; gap: 6px; flex-wrap: wrap; }
.aos-sbox-tag {
    font-size: 10px; letter-spacing: 0.03em; padding: 2px 8px; border-radius: 3px;
    border: 1px solid var(--color-accent); color: var(--color-accent);
}
.aos-sbox-url { font-family: ui-monospace, Menlo, monospace; font-size: 10.5px; color: var(--feed-muted); word-break: break-all; }
.aos-sbox-status { display: inline-flex; align-items: center; gap: 5px; font-size: 10px; letter-spacing: 0.06em; text-transform: uppercase; }
.aos-sbox-status-dot { width: 6px; height: 6px; border-radius: 50%; }
@keyframes livePulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.25; } }
.aos-sbox-status.running  .aos-sbox-status-dot { background: var(--color-accent); animation: livePulse 1.1s ease-in-out infinite; }
.aos-sbox-status.verified .aos-sbox-status-dot { background: var(--safe); }
.aos-sbox-status.destroyed .aos-sbox-status-dot { background: var(--feed-muted); }
.aos-sbox-status.running  { color: var(--color-accent); }
.aos-sbox-status.verified { color: var(--safe); }
.aos-sbox-status.destroyed { color: var(--feed-muted); }
.aos-sbox-meta { font-family: ui-monospace, Menlo, monospace; font-size: 10.5px; color: var(--feed-muted); }
.aos-sidebar-empty { font-family: var(--font-body); font-style: italic; font-size: 12px; color: var(--feed-muted); }

.aos-round-card {
    display: flex; align-items: center; gap: 12px;
    padding: 10px 16px; border-radius: 4px;
    border: 1px solid var(--color-divider);
}
.aos-round-card.active { border-color: var(--color-accent); box-shadow: 0 1px 2px rgba(45,43,43,0.14); }
.aos-round-numeral { font-family: var(--font-heading); font-weight: 600; font-size: 26px; width: 30px; flex: none; color: rgba(32,31,29,0.45); }
.aos-round-card.active .aos-round-numeral { color: var(--color-accent); }
.aos-round-title { font-family: var(--font-heading); font-weight: 600; font-size: 15px; color: var(--color-text); }
.aos-round-stage {
    font-size: 10.5px; letter-spacing: 0.06em; text-transform: uppercase;
    padding: 3px 9px; border-radius: 3px; border: 1px solid currentColor;
    flex: none; white-space: nowrap;
}
</style>
"""

MODEL_TAG = "ai& · deepseek-v4-flash"
ROUND_NUMERALS = {1: "I", 2: "II", 3: "III"}


def inject_shell_css() -> None:
    if not st.session_state.get("_css_injected"):
        st.html(_SHELL_CSS)
        st.session_state["_css_injected"] = True


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _sbox_card_html(entry: dict) -> str:
    status = entry.get("status", "running")
    sbox_id = entry.get("id", "")
    url = entry.get("url", "")
    region = entry.get("region", "")
    vc_label = VULN_LABELS.get(entry.get("vuln_class", ""), entry.get("vuln_class", ""))
    round_num = entry.get("iteration", 0)
    meta_bits = [b for b in (
        f"Iteration {ROUND_NUMERALS.get(round_num, round_num)} · {vc_label}" if vc_label else "",
        region,
    ) if b]
    meta_line = f'<div class="aos-sbox-meta">{_escape(" · ".join(meta_bits))}</div>' if meta_bits else ""
    return (
        f'<div class="aos-sbox-card {status}">'
        f'<div class="aos-sbox-tags"><span class="aos-sbox-tag">{_escape(sbox_id) or "sandbox"}</span></div>'
        f'<div class="aos-sbox-url">{_escape(url) or "—"}</div>'
        f'{meta_line}'
        f'<div class="aos-sbox-status {status}"><span class="aos-sbox-status-dot"></span>{status}</div>'
        f'</div>'
    )


_SIDEBAR_CSS = """
<style>
.aos-sidebar-title {
    font-family: 'Cormorant Garamond', Georgia, serif; font-weight: 600; font-size: 15px;
    letter-spacing: 0.02em; margin-bottom: 2px; color: rgba(248,244,244,0.92);
}
.aos-sidebar-usage {
    font-family: ui-monospace, Menlo, monospace; font-size: 11px;
    color: rgba(248,244,244,0.55); margin-bottom: 4px;
}
.aos-sbox-card {
    display: flex; flex-direction: column; gap: 6px;
    padding: 10px 12px; margin-bottom: 10px;
    border: 1px solid rgba(248,244,244,0.16); border-radius: 6px;
    background: rgba(255,255,255,0.03);
}
.aos-sbox-card.running  { border-color: #b68235; }
.aos-sbox-card.verified { border-color: #43a047; }
.aos-sbox-card.destroyed { opacity: 0.55; }
.aos-sbox-tags { display: flex; gap: 6px; flex-wrap: wrap; }
.aos-sbox-tag {
    font-size: 10px; letter-spacing: 0.03em; padding: 2px 8px; border-radius: 3px;
    border: 1px solid #b68235; color: #b68235;
}
.aos-sbox-url { font-family: ui-monospace, Menlo, monospace; font-size: 10.5px; color: rgba(248,244,244,0.55); word-break: break-all; }
.aos-sbox-status { display: inline-flex; align-items: center; gap: 5px; font-size: 10px; letter-spacing: 0.06em; text-transform: uppercase; }
.aos-sbox-status-dot { width: 6px; height: 6px; border-radius: 50%; display: inline-block; }
@keyframes livePulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.25; } }
.aos-sbox-status.running  .aos-sbox-status-dot { background: #b68235; animation: livePulse 1.1s ease-in-out infinite; }
.aos-sbox-status.verified .aos-sbox-status-dot { background: #43a047; }
.aos-sbox-status.destroyed .aos-sbox-status-dot { background: rgba(248,244,244,0.55); }
.aos-sbox-status.running  { color: #b68235; }
.aos-sbox-status.verified { color: #43a047; }
.aos-sbox-status.destroyed { color: rgba(248,244,244,0.55); }
.aos-sbox-meta { font-family: ui-monospace, Menlo, monospace; font-size: 10.5px; color: rgba(248,244,244,0.55); }
.aos-sidebar-empty { font-style: italic; font-size: 12px; color: rgba(248,244,244,0.55); }
</style>
"""


def render_sidebar() -> None:
    s = st.session_state
    history = s.sandbox_history
    key = f"{len(history)}:{[e.get('status') for e in history]}:{s.llm_calls}:{s.llm_tokens}"
    with st.sidebar:
        if s._sidebar_cache_key == key:
            st.html(s._sidebar_html_cache)
            return
        s._sidebar_cache_key = key
        parts = [_SIDEBAR_CSS, '<div class="aos-sidebar-title">Daytona sandboxes</div>']
        if s.llm_calls:
            parts.append(f'<div class="aos-sidebar-usage">{MODEL_TAG} · {s.llm_calls} calls · {s.llm_tokens:,} tokens</div>')
        if not history:
            parts.append('<div class="aos-sidebar-empty">Waiting for the first sandbox…</div>')
        else:
            for entry in reversed(history):
                parts.append(_sbox_card_html(entry))
        s._sidebar_html_cache = "".join(parts)
        st.html(s._sidebar_html_cache)


# ---------------------------------------------------------------------------
# Nav bar + round gallery (combined into one st.html block)
# ---------------------------------------------------------------------------

def _round_stage_label(round_num: int) -> str:
    s = st.session_state
    if s.iteration > round_num:
        return "verified"
    if s.iteration < round_num or not s.iteration:
        return "pending"
    return s.stage


_NAV_CSS = """<style>
@import url('https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@600&family=Lora:wght@400;600&display=swap');
.aos-brand { font-family: 'Cormorant Garamond', Georgia, serif; font-weight: 600; font-size: 18px; color: #201f1d; }
.aos-tagline { font-size: 11px; color: rgba(32,31,29,0.55); letter-spacing: 0.02em; }
.aos-tag {
    display: inline-flex; align-items: center; font-size: 11px;
    padding: 3px 10px; border-radius: 3px;
    border: 1px solid #b68235; color: #b68235;
}
.aos-round-card {
    display: flex; align-items: center; gap: 12px;
    padding: 10px 16px; border-radius: 4px;
    border: 1px solid rgba(32,31,29,0.16);
}
.aos-round-numeral { font-family: 'Cormorant Garamond', Georgia, serif; font-weight: 600; font-size: 26px; width: 30px; flex: none; color: rgba(32,31,29,0.45); }
.aos-round-numeral.active { color: #b68235; }
.aos-round-title { font-family: 'Cormorant Garamond', Georgia, serif; font-weight: 600; font-size: 15px; color: #201f1d; }
.aos-round-stage {
    font-size: 10.5px; letter-spacing: 0.06em; text-transform: uppercase;
    padding: 3px 9px; border-radius: 3px; border: 1px solid currentColor;
    flex: none; white-space: nowrap;
}
</style>"""


def _build_header_html(s) -> str:
    token_line = (
        f'<span style="font-size:11px;color:rgba(32,31,29,0.55);margin-left:8px">'
        f'{s.llm_calls} calls · {s.llm_tokens:,} tokens</span>'
    ) if s.llm_calls else ""

    cards = ""
    for n in (1, 2, 3):
        stage = _round_stage_label(n)
        active = s.iteration == n
        color = STAGE_COLORS.get(stage, "#9b9797")
        active_border = f"border-color:{color};" if active else ""
        numeral_color = color if active else "rgba(32,31,29,0.45)"
        cards += (
            f'<div class="aos-round-card" style="flex:1;{active_border}">'
            f'<div class="aos-round-numeral" style="color:{numeral_color}">{ROUND_NUMERALS[n]}</div>'
            f'<div style="flex:1;min-width:0"><div class="aos-round-title">Iteration {ROUND_NUMERALS[n]}</div></div>'
            f'<div class="aos-round-stage" style="color:{color}">{stage.upper()}</div>'
            f'</div>'
        )
    return (
        f'{_NAV_CSS}'
        f'<div style="display:flex;align-items:flex-start;justify-content:space-between;padding-bottom:4px">'
        f'<div><div class="aos-brand">Attack on Sandbox</div>'
        f'<div class="aos-tagline">Two agents. One sandbox. No trust.</div></div>'
        f'<div style="text-align:right;padding-top:6px">'
        f'<span class="aos-tag">Daytona sandbox</span>&nbsp;'
        f'<span class="aos-tag">{MODEL_TAG}</span>{token_line}</div>'
        f'</div>'
        f'<div style="display:flex;gap:12px;margin:8px 0 4px">{cards}</div>'
    )


def render_nav_and_gallery() -> None:
    s = st.session_state
    key = (
        f"{s.llm_calls}:{s.llm_tokens}:{s.iteration}:{s.stage}:"
        + ":".join(_round_stage_label(n) for n in (1, 2, 3))
    )
    if s._nav_cache_key != key:
        s._nav_cache_key = key
        s._nav_html_cache = _build_header_html(s)

    running = _orchestrator_is_running()
    col_header, col_action = st.columns([5.5, 1.6 if running else 0.8])
    with col_header:
        st.html(s._nav_html_cache)
    with col_action:
        st.html('<div style="height:18px"></div>')
        render_reset_button()


# ---------------------------------------------------------------------------
# Feed iframe — self-contained HTML+JS that owns all live rendering
# ---------------------------------------------------------------------------

# The iframe sources events.json from Streamlit's static file server
# (dashboard/static/events.json → /app/static/events.json).
# It keeps its own byte cursor and uses Range requests to fetch only new bytes,
# exactly mirroring the Python read_new_events() approach.

_FEED_IFRAME = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --color-accent: #b68235;
  --danger: #e53935;
  --safe: #43a047;
  --feed-bg: #1e1e2e;
  --feed-text: rgba(248,244,244,0.92);
  --feed-muted: rgba(248,244,244,0.55);
  --feed-divider: rgba(248,244,244,0.16);
  --font-heading: 'Cormorant Garamond', Georgia, serif;
  --font-body: 'Lora', Georgia, serif;
}

@import url('https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@600&family=Lora:wght@400;600&display=swap');

@keyframes livePulse { 0%,100%{opacity:1}50%{opacity:.25} }
@keyframes caretBlink { 0%,49%{opacity:1}50%,100%{opacity:0} }
@keyframes feedIn { from{opacity:0;transform:translateY(14px)} to{opacity:1;transform:translateY(0)} }

body {
  background: var(--feed-bg);
  font-family: var(--font-body);
  color: var(--feed-text);
  padding: 24px;
  min-height: 100vh;
  overflow-y: auto;
}

#feed { display: flex; flex-direction: column; gap: 18px; }

.aos-feed-empty { color: var(--feed-muted); font-style: italic; }

.aos-divider { display:flex;align-items:center;gap:14px;margin:6px 0;animation:feedIn .5s ease both; }
.aos-divider-line { flex:1;height:1px;background:var(--feed-divider); }
.aos-divider-label {
  font-size:11px;letter-spacing:.12em;text-transform:uppercase;
  white-space:nowrap;font-family:var(--font-heading);font-weight:600;
}

.aos-narration { display:flex;flex-direction:column;gap:8px;animation:feedIn .5s ease both; }
.aos-role-tag {
  font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;font-weight:600;
  border-radius:3px;padding:2px 8px;width:fit-content;border:1px solid currentColor;
}
.aos-role-tag.attacker { color:var(--danger); }
.aos-role-tag.defender { color:var(--safe); }
.aos-quote {
  font-family:var(--font-heading);font-style:italic;font-weight:600;
  font-size:24px;line-height:1.4;color:var(--feed-text);
}
.aos-caret { animation:caretBlink .9s step-end infinite;color:var(--color-accent); }
.aos-technical {
  font-family:ui-monospace,Menlo,monospace;font-size:11.5px;
  line-height:1.6;color:var(--feed-muted);white-space:pre-wrap;
}

.aos-taunt {
  display:flex;flex-direction:column;gap:6px;
  padding-left:18px;border-left:2px dashed var(--danger);animation:feedIn .5s ease both;
}
.aos-taunt-tag { font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--danger);width:fit-content; }
.aos-taunt-text { font-family:ui-monospace,Menlo,monospace;font-size:13px;font-style:italic;color:var(--feed-muted); }

.aos-wire { display:flex;flex-direction:column;gap:8px;padding-left:14px;animation:feedIn .5s ease both; }
.aos-wire.blocked { border-left:3px solid var(--safe); }
.aos-wire.breach  { border-left:3px solid var(--danger); }
.aos-wire-header  { display:flex;align-items:center;gap:8px; }
.aos-wire-dot     { width:7px;height:7px;border-radius:50%; }
.aos-wire.blocked .aos-wire-dot  { background:var(--safe); }
.aos-wire.breach  .aos-wire-dot  { background:var(--danger); }
.aos-wire-label   { font-size:11px;letter-spacing:.06em;text-transform:uppercase;font-weight:600; }
.aos-wire.blocked .aos-wire-label { color:var(--safe); }
.aos-wire.breach  .aos-wire-label { color:var(--danger); }
.aos-wire-block {
  font-family:ui-monospace,Menlo,monospace;font-size:11.5px;line-height:1.6;
  white-space:pre-wrap;word-break:break-all;color:var(--feed-text);
  background:rgba(255,255,255,.04);border:1px solid var(--feed-divider);
  border-radius:4px;padding:10px 12px;
}
.aos-wire-curl { color:var(--color-accent);border-color:var(--color-accent); }

.aos-live-timer {
  display:flex;align-items:center;gap:8px;
  font-family:ui-monospace,Menlo,monospace;font-size:12px;
  color:var(--color-accent);animation:feedIn .5s ease both;
}
.aos-live-timer-dot { width:6px;height:6px;border-radius:50%;background:var(--color-accent);animation:livePulse 1.1s ease-in-out infinite; }

.aos-diff {
  display:flex;flex-direction:column;gap:4px;
  font-family:ui-monospace,Menlo,monospace;font-size:12px;line-height:1.7;
  background:rgba(255,255,255,.04);border:1px solid var(--feed-divider);
  border-radius:4px;padding:12px 14px;animation:feedIn .5s ease both;
}
.aos-diff-kicker { font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--color-accent);margin-bottom:4px; }
.aos-diff-line { padding-left:8px;white-space:pre-wrap;word-break:break-all; }
.aos-diff-line.add { color:var(--safe);border-left:2px solid var(--safe); }
.aos-diff-line.del { color:var(--danger);border-left:2px solid var(--danger); }
.aos-diff-line.ctx { color:var(--feed-text);border-left:2px solid transparent; }
</style>
</head>
<body>
<div id="feed"><div class="aos-feed-empty">Waiting for the first iteration…</div></div>
<script>
(function() {
'use strict';

// ── constants ──────────────────────────────────────────────────────────────
var EVENTS_URL = '/app/static/events.json';
var POLL_MS    = 120;
var CHAR_MS    = 28;   // typewriter speed

var VULN_LABELS = {sqli:'SQL Injection', idor:'IDOR', missing_auth:'Missing Auth'};
var TAUNTS = {
  sqli:         "Thanks for the login — didn't even need a password.",
  idor:         "Appreciate Annie's notes — didn't need to be her to read them.",
  missing_auth: "Reset's done — nobody even asked who I was."
};
var STAGE_COLORS = {
  idle:'#9b9797', pending:'#9b9797', scanning:'#b68235',
  breached:'#e53935', analysing:'#b68235', patched:'#b68235', verified:'#43a047'
};
var ROUND_NUMS = {1:'I', 2:'II', 3:'III'};

// ── state ──────────────────────────────────────────────────────────────────
var cursor = 0;

// per-iteration live state
var state = {
  iteration: 0,
  stage: 'idle',
  vuln_class: '',
  active_agent: null,
  attacker_narration: '',
  attacker_technical: '',
  defender_narration: '',
  defender_technical: '',
  wire_request: null,
  wire_response: null,
  wire_blocked: null,
  diff: '',
  frozen: false
};

// queued narration characters waiting to be typed
var narratQueue = [];  // [{agent, char}]
var typingActive = false;

// ── DOM refs (created lazily, one per iteration) ───────────────────────────
var dom = {};  // keys: divider, atk_narration, atk_quote, atk_caret, atk_technical,
               //       atk_timer, wire_breach, taunt, def_narration, def_quote,
               //       def_caret, def_technical, def_timer, diff_block, wire_verify

var feed = document.getElementById('feed');

// ── helpers ────────────────────────────────────────────────────────────────
function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function el(tag, cls, style) {
  var e = document.createElement(tag);
  if (cls)   e.className = cls;
  if (style) e.style.cssText = style;
  return e;
}

function append(parent, child) { parent.appendChild(child); return child; }

function clearEmpty() {
  var emp = feed.querySelector('.aos-feed-empty');
  if (emp) emp.remove();
}

function scrollToBottom() {
  feed.lastElementChild && feed.lastElementChild.scrollIntoView({behavior:'smooth', block:'end'});
}

// ── timer ──────────────────────────────────────────────────────────────────
function startTimer(el) {
  var start = performance.now();
  function tick() {
    if (!el || !document.body.contains(el)) return;
    el.textContent = ((performance.now() - start) / 1000).toFixed(2) + 's';
    setTimeout(tick, 100);
  }
  tick();
}

// ── block builders ─────────────────────────────────────────────────────────
function makeDivider(text, color) {
  var d = el('div','aos-divider');
  var l1 = append(d, el('div','aos-divider-line'));
  var lb = append(d, el('div','aos-divider-label'));
  lb.style.color = color;
  lb.textContent = text;
  var l2 = append(d, el('div','aos-divider-line'));
  return d;
}

function makeNarrationBlock(agent) {
  var wrap = el('div','aos-narration');
  var tag  = append(wrap, el('span','aos-role-tag ' + agent));
  tag.textContent = agent === 'attacker' ? 'Attacker' : 'Defender';
  var quote = append(wrap, el('div','aos-quote'));
  quote.innerHTML = '"<span class="aos-narration-text"></span><span class="aos-caret">▌</span>"';
  var tech  = append(wrap, el('div','aos-technical'));
  tech.style.display = 'none';
  return {wrap, quote, text: quote.querySelector('.aos-narration-text'),
          caret: quote.querySelector('.aos-caret'), tech};
}

function makeTimerBlock(agent) {
  var wrap = el('div','aos-live-timer');
  append(wrap, el('div','aos-live-timer-dot'));
  var tag = append(wrap, el('span','aos-role-tag ' + agent));
  tag.textContent = agent === 'attacker' ? 'Attacker' : 'Defender';
  var lbl = append(wrap, el('span'));
  lbl.textContent = 'requesting deepseek-v4-flash…';
  var clk = append(wrap, el('span'));
  clk.textContent = '0.00s';
  startTimer(clk);
  return wrap;
}

function formatRequest(req) {
  if (!req) return '';
  var lines = [req.method + ' ' + req.url];
  var hdrs = req.headers || {};
  Object.keys(hdrs).forEach(function(k){ lines.push(k + ': ' + hdrs[k]); });
  if (req.body != null) {
    lines.push('');
    lines.push(typeof req.body === 'object' ? JSON.stringify(req.body, null, 2) : String(req.body));
  }
  return lines.join('\\n');
}

function formatCurl(req) {
  if (!req) return '';
  var parts = ["curl -X " + req.method + " '" + req.url + "'"];
  var hdrs = req.headers || {};
  Object.keys(hdrs).forEach(function(k){ parts.push("  -H '" + k + ": " + hdrs[k] + "'"); });
  if (req.body != null) {
    var b = typeof req.body === 'object' ? JSON.stringify(req.body) : String(req.body);
    parts.push("  -d '" + b.replace(/'/g, "'\\\\''") + "'");
  }
  return parts.join(' \\\\\\n');
}

function formatResponse(resp) {
  if (!resp) return '';
  var body = typeof resp.body === 'object' ? JSON.stringify(resp.body, null, 2) : String(resp.body || '');
  return 'HTTP ' + resp.status + '\\n\\n' + body;
}

function makeWireBlock(req, resp, blocked) {
  var cls   = blocked ? 'blocked' : 'breach';
  var label = blocked ? 'Exploit blocked — patch holds' : 'Breach confirmed';
  var wrap  = el('div','aos-wire ' + cls);
  var hdr   = append(wrap, el('div','aos-wire-header'));
  append(hdr, el('div','aos-wire-dot'));
  var lbl = append(hdr, el('span','aos-wire-label'));
  lbl.textContent = label;
  var curl = append(wrap, el('div','aos-wire-block aos-wire-curl'));
  curl.textContent = '$ ' + formatCurl(req);
  var reqB = append(wrap, el('div','aos-wire-block'));
  reqB.textContent = formatRequest(req);
  var resB = append(wrap, el('div','aos-wire-block'));
  resB.textContent = formatResponse(resp);
  return wrap;
}

function makeTauntBlock(text) {
  var wrap = el('div','aos-taunt');
  var tag  = append(wrap, el('span','aos-taunt-tag'));
  tag.textContent = 'Attacker → Defender';
  var txt  = append(wrap, el('div','aos-taunt-text'));
  txt.textContent = text;
  return wrap;
}

function makeDiffBlock(endpoint, diff) {
  var wrap   = el('div','aos-diff');
  var kicker = append(wrap, el('div','aos-diff-kicker'));
  kicker.textContent = endpoint + ' — patch applied';
  diff.split('\\n').forEach(function(line) {
    var cls = '';
    if (/^(\\+\\+\\+|---|@@)/.test(line)) return;
    if (line.startsWith('+')) cls = 'add';
    else if (line.startsWith('-')) cls = 'del';
    else cls = 'ctx';
    var row = append(wrap, el('div','aos-diff-line ' + cls));
    row.textContent = line;
  });
  return wrap;
}

// ── iteration DOM setup ────────────────────────────────────────────────────
function setupIterationDOM() {
  // called once per iteration_start — creates the divider and clears dom refs
  dom = {};

  // if this is the very first iteration of a new run, wipe the feed
  if (state.iteration === 1) {
    feed.innerHTML = '';
  }
  clearEmpty();

  var vc = VULN_LABELS[state.vuln_class] || state.vuln_class;
  var color = STAGE_COLORS['scanning'];
  dom.divider = append(feed, makeDivider(
    'Iteration ' + state.iteration + ' — ' + vc, color
  ));
}

function updateDivider() {
  if (!dom.divider) return;
  var vc = VULN_LABELS[state.vuln_class] || state.vuln_class;
  var color, text;
  if (state.stage === 'verified') {
    color = state.wire_blocked ? 'var(--safe)' : 'var(--danger)';
    text  = 'Iteration ' + state.iteration + ' complete — ' + vc;
  } else {
    color = STAGE_COLORS[state.stage] || '#9b9797';
    text  = 'Iteration ' + state.iteration + ' — ' + vc;
  }
  dom.divider.querySelector('.aos-divider-label').textContent = text;
  dom.divider.querySelector('.aos-divider-label').style.color = color;
}

// ── narration typewriter ───────────────────────────────────────────────────
function pumpNarration() {
  if (!narratQueue.length) { typingActive = false; return; }
  typingActive = true;
  var item = narratQueue.shift();
  var agent = item.agent;

  if (agent === 'attacker') {
    state.attacker_narration += item.char;
    if (!dom.atk_narration) {
      // first char — swap timer for narration block
      if (dom.atk_timer) { dom.atk_timer.remove(); dom.atk_timer = null; }
      var nb = makeNarrationBlock('attacker');
      dom.atk_narration = nb.wrap;
      dom.atk_quote     = nb.quote;
      dom.atk_text      = nb.text;
      dom.atk_caret     = nb.caret;
      dom.atk_technical = nb.tech;
      // insert after divider
      if (dom.divider && dom.divider.nextSibling) {
        feed.insertBefore(dom.atk_narration, dom.divider.nextSibling);
      } else {
        feed.appendChild(dom.atk_narration);
      }
    }
    dom.atk_text.textContent = state.attacker_narration;
  } else {
    state.defender_narration += item.char;
    if (!dom.def_narration) {
      if (dom.def_timer) { dom.def_timer.remove(); dom.def_timer = null; }
      var nb2 = makeNarrationBlock('defender');
      dom.def_narration = nb2.wrap;
      dom.def_quote     = nb2.quote;
      dom.def_text      = nb2.text;
      dom.def_caret     = nb2.caret;
      dom.def_technical = nb2.tech;
      feed.appendChild(dom.def_narration);
    }
    dom.def_text.textContent = state.defender_narration;
  }

  setTimeout(pumpNarration, CHAR_MS);
}

// ── event handlers ─────────────────────────────────────────────────────────
function handleEvent(ev) {
  var t = ev.type || '';
  var p = ev.payload || {};

  if (t === 'iteration_start') {
    state.iteration          = ev.iteration || state.iteration;
    state.vuln_class         = ev.vulnerability_class || '';
    state.stage              = 'scanning';
    state.active_agent       = null;
    state.attacker_narration = '';
    state.attacker_technical = '';
    state.defender_narration = '';
    state.defender_technical = '';
    state.wire_request       = null;
    state.wire_response      = null;
    state.wire_blocked       = null;
    state.diff               = '';
    state.frozen             = false;
    narratQueue              = [];
    dom                      = {};
    setupIterationDOM();

  } else if (t === 'agent_thinking') {
    state.active_agent = p.agent;
    if (p.agent === 'defender') state.stage = 'analysing';

    if (p.agent === 'attacker' && !dom.atk_timer && !dom.atk_narration) {
      dom.atk_timer = append(feed, makeTimerBlock('attacker'));
    } else if (p.agent === 'defender' && !dom.def_timer && !dom.def_narration) {
      dom.def_timer = append(feed, makeTimerBlock('defender'));
    }
    updateDivider();

  } else if (t === 'narration_chunk') {
    narratQueue.push({agent: p.agent, char: p.char || ''});
    if (!typingActive) pumpNarration();

  } else if (t === 'stream_chunk') {
    // not displayed — just consume

  } else if (t === 'attack_sent') {
    state.stage              = 'breached';
    state.wire_request       = p.request;
    state.wire_response      = p.response;
    state.wire_blocked       = false;
    state.active_agent       = null;
    // finalize attacker narration from agent_reasoning (in case no narration_chunks came through)
    var r = p.agent_reasoning || {};
    if (!state.attacker_narration && r.narration) {
      state.attacker_narration = r.narration;
    }
    state.attacker_technical = r.technical || '';
    narratQueue = [];
    typingActive = false;

    // complete the attacker narration block if it exists
    if (dom.atk_timer) { dom.atk_timer.remove(); dom.atk_timer = null; }
    if (!dom.atk_narration && state.attacker_narration) {
      var nb3 = makeNarrationBlock('attacker');
      dom.atk_narration = nb3.wrap; dom.atk_quote = nb3.quote;
      dom.atk_text = nb3.text; dom.atk_caret = nb3.caret; dom.atk_technical = nb3.tech;
      if (dom.divider && dom.divider.nextSibling) feed.insertBefore(dom.atk_narration, dom.divider.nextSibling);
      else feed.appendChild(dom.atk_narration);
    }
    if (dom.atk_text) dom.atk_text.textContent = state.attacker_narration;
    if (dom.atk_caret) dom.atk_caret.style.display = 'none';
    if (dom.atk_technical && state.attacker_technical) {
      dom.atk_technical.textContent = state.attacker_technical;
      dom.atk_technical.style.display = '';
    }

    // append wire block (breach)
    if (!dom.wire_breach) {
      dom.wire_breach = append(feed, makeWireBlock(p.request, p.response, false));
      scrollToBottom();
    }
    updateDivider();

  } else if (t === 'patch_applied') {
    state.stage              = 'patched';
    state.diff               = p.diff || '';
    state.active_agent       = null;
    var r2 = p.agent_reasoning || {};
    if (!state.defender_narration && r2.narration) {
      state.defender_narration = r2.narration;
    }
    state.defender_technical = r2.technical || '';
    narratQueue = [];
    typingActive = false;

    // append taunt if not already there
    var taunt = TAUNTS[state.vuln_class];
    if (taunt && !dom.taunt) {
      dom.taunt = append(feed, makeTauntBlock(taunt));
      scrollToBottom();
    }

    // complete defender narration block
    if (dom.def_timer) { dom.def_timer.remove(); dom.def_timer = null; }
    if (!dom.def_narration && state.defender_narration) {
      var nb4 = makeNarrationBlock('defender');
      dom.def_narration = nb4.wrap; dom.def_quote = nb4.quote;
      dom.def_text = nb4.text; dom.def_caret = nb4.caret; dom.def_technical = nb4.tech;
      feed.appendChild(dom.def_narration);
    }
    if (dom.def_text) dom.def_text.textContent = state.defender_narration;
    if (dom.def_caret) dom.def_caret.style.display = 'none';
    if (dom.def_technical && state.defender_technical) {
      dom.def_technical.textContent = state.defender_technical;
      dom.def_technical.style.display = '';
    }

    // diff block
    if (state.diff && !dom.diff_block) {
      var endpoint = state.wire_request ? state.wire_request.url : '';
      dom.diff_block = append(feed, makeDiffBlock(endpoint, state.diff));
      scrollToBottom();
    }
    updateDivider();

  } else if (t === 'verified') {
    state.stage        = 'verified';
    state.wire_request = p.request;
    state.wire_response= p.response;
    state.wire_blocked = p.exploit_blocked || false;

    // verified wire block
    if (!dom.wire_verify) {
      dom.wire_verify = append(feed, makeWireBlock(p.request, p.response, p.exploit_blocked));
    }
    // update breach wire to show final blocked state if it was blocked
    updateDivider();

    // scroll into view
    scrollToBottom();

  } else if (t === 'iteration_complete') {
    state.frozen       = true;
    state.active_agent = null;
    // hide remaining carets
    if (dom.atk_caret) dom.atk_caret.style.display = 'none';
    if (dom.def_caret) dom.def_caret.style.display = 'none';
  }
}

// ── poller ─────────────────────────────────────────────────────────────────
function poll() {
  var headers = {};
  if (cursor > 0) headers['Range'] = 'bytes=' + cursor + '-';

  fetch(EVENTS_URL, {headers: headers, cache: 'no-store'})
    .then(function(r) {
      // 416 = range not satisfiable — file was reset/truncated, restart from 0
      if (r.status === 416) { cursor = 0; setTimeout(poll, POLL_MS); return null; }
      if (!r.ok && r.status !== 206) { setTimeout(poll, POLL_MS); return null; }
      // get Content-Range to update cursor correctly
      var contentRange = r.headers.get('Content-Range');
      return r.text().then(function(text) {
        if (!text) { setTimeout(poll, POLL_MS); return; }
        // update cursor: if we got a Content-Range header use it,
        // otherwise just advance by bytes received
        if (contentRange) {
          var m = contentRange.match(/bytes \\d+-\\d+\\/(\\d+)/);
          if (m) cursor = parseInt(m[1], 10);
        } else {
          // full file response (first fetch or no Range support)
          cursor += new TextEncoder().encode(text).length;
        }
        text.split('\\n').forEach(function(line) {
          line = line.trim();
          if (!line) return;
          try { handleEvent(JSON.parse(line)); } catch(e) {}
        });
        setTimeout(poll, POLL_MS);
      });
    })
    .catch(function() { setTimeout(poll, POLL_MS * 3); });
}

poll();
})();
</script>
</body>
</html>"""


# Process-level flag — True once per Streamlit process lifetime, not per session.
# Ensures stale events files are wiped whenever Streamlit (re)starts.
_STARTUP_CLEARED = False


def _clear_on_startup() -> None:
    global _STARTUP_CLEARED
    for p in (EVENTS_PATH, STATIC_EVENTS_PATH):
        try:
            p.unlink(missing_ok=True)
        except OSError:
            pass
    _STARTUP_CLEARED = True


@st.fragment(run_every=POLL_INTERVAL_S)
def _updatable_shell() -> None:
    """Fragment that reruns every POLL_INTERVAL_S to update sidebar + nav/gallery.

    Using @st.fragment means only this function reruns on the poll timer —
    the iframe rendered outside it is never touched, so its JS state
    (typewriter position, DOM, cursor) persists across updates.
    """
    sync_events_file()
    _scan_new_events()
    render_sidebar()
    render_nav_and_gallery()


def main() -> None:
    st.set_page_config(
        page_title="Attack on Sandbox",
        page_icon="⚔️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    init_state()
    inject_shell_css()

    # On the very first run of this Streamlit process (tracked by a process-level
    # flag, not session state), wipe both events files so the iframe never
    # replays a stale previous run after Streamlit restarts.
    if not _STARTUP_CLEARED:
        _clear_on_startup()

    # Fragment handles sidebar + nav/gallery + events sync on a timer.
    # It reruns independently — the iframe below is never re-rendered.
    _updatable_shell()

    st.divider()

    # Iframe rendered once at page load. Its JS polls events.json directly
    # and never needs a Python rerun to update.
    st.iframe(_FEED_IFRAME, height=900)


if __name__ == "__main__":
    main()
