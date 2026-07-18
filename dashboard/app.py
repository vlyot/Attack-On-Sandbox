"""
Attack on Sandbox — Streamlit dashboard.

Reads newline-delimited JSON from events.json, updates session state on each
poll, and renders a single vertical feed (nav bar + round gallery above it):
  - Nav bar        (brand, Reset)
  - Sidebar        (sticky: every sandbox this run has created, live + past)
  - Round gallery  (3 iteration cards: numeral + stage, no endpoint)
  - Feed           (narration -> wire -> taunt -> narration -> diff -> wire,
                     in event order, styled after the project's HTML design
                     reference)
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
POLL_INTERVAL_S = 0.08   # 80 ms between polls when idle
MAX_EVENTS_PER_CYCLE = 50  # batch cap so UI stays responsive during fixture replay

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

# Pre-scripted attacker taunts — authored theatre, never model-generated.
# The defender never sees these; it receives only request + response + source.
TAUNTS = {
    "sqli":         "Thanks for the login — didn't even need a password.",
    "idor":         "Appreciate Annie's notes — didn't need to be her to read them.",
    "missing_auth": "Reset's done — nobody even asked who I was.",
}

# ---------------------------------------------------------------------------
# State initialisation
# ---------------------------------------------------------------------------

_STATE_DEFAULTS: dict = {
    "cursor":             0,
    "sandbox_url":        "",
    "sandbox_id":         "",
    "sandbox_region":     "",
    "sandbox_created_at":  "",
    "sandbox_spec":       {},
    "sandbox_status":     "idle",
    # Every sandbox this run has created, in order — each entry a dict with
    # id/url/region/created_at/status/iteration/vuln_class. The current
    # sandbox_* fields above always mirror the last entry here; this list is
    # what lets the sidebar show past sandboxes too, not just the live one.
    "sandbox_history":    [],
    "iteration":          0,
    "stage":              "idle",
    "vuln_class":         "",
    "source_code":        "",
    "diff":               "",
    "wire_request":       None,
    "wire_response":      None,
    "wire_blocked":       None,
    "attacker_narration": "",
    "attacker_technical": "",
    "defender_narration": "",
    "defender_technical": "",
    "attacker_raw_stream": "",
    "defender_raw_stream": "",
    "llm_calls":           0,
    "llm_tokens":          0,
    "active_agent":       None,
    "active_agent_label": "",
    "history":            [],
    # True once the current iteration's blocks have been frozen into
    # history at iteration_complete — stops render_feed() from also
    # rendering them "live" until the next iteration_start clears it.
    "_iteration_frozen":  False,
}


def init_state() -> None:
    for key, default in _STATE_DEFAULTS.items():
        if key not in st.session_state:
            # Copy mutable defaults so tests don't share the same object
            st.session_state[key] = default.copy() if isinstance(default, (list, dict)) else default


# ---------------------------------------------------------------------------
# Reset control
# ---------------------------------------------------------------------------

TARGET_APP_SOURCE = Path("target-app/app.py")
TARGET_APP_DB = Path("target-app/notes.db")
ORCHESTRATOR_SCRIPT = Path("orchestrator/main.py")
REPO_ROOT = Path(__file__).resolve().parent.parent

# _orchestrator_proc lives outside st.session_state: a subprocess.Popen isn't
# JSON-serialisable and Streamlit's session_state persistence would choke on
# it. A module-level global is safe here because a single Streamlit process
# serves one dashboard instance in this project's usage (one presenter, one
# demo run) — this is not a multi-user web app.
_orchestrator_proc: subprocess.Popen | None = None


def _orchestrator_is_running() -> bool:
    return _orchestrator_proc is not None and _orchestrator_proc.poll() is None


def do_reset() -> None:
    """Restore all on-disk state to pre-iteration-1: clear events.json,
    restore target-app/app.py from git, delete notes.db, reset session state.
    """
    if EVENTS_PATH.exists():
        EVENTS_PATH.unlink()
    subprocess.run(["git", "checkout", "--", str(TARGET_APP_SOURCE)], check=False)
    if TARGET_APP_DB.exists():
        TARGET_APP_DB.unlink()
    for key in list(_STATE_DEFAULTS):
        st.session_state.pop(key, None)
    init_state()


def do_reset_and_run() -> None:
    """Reset all state, then launch a fresh orchestrator/main.py run.

    The dashboard owns this subprocess (tracked in the module-level
    _orchestrator_proc) so it can refuse to start a second overlapping run —
    two orchestrators racing for port 5000 and the same target-app/notes.db
    would corrupt each other.
    """
    global _orchestrator_proc
    do_reset()
    _orchestrator_proc = subprocess.Popen(
        [sys.executable, str(ORCHESTRATOR_SCRIPT)],
        cwd=str(REPO_ROOT),
    )


def render_reset_button() -> None:
    # Two independent signals a run is in flight: a subprocess this dashboard
    # itself spawned (_orchestrator_is_running), or an externally-run
    # orchestrator whose events are still landing mid-iteration (stage not
    # yet idle/verified) — e.g. someone ran `python orchestrator/main.py` by
    # hand in a separate terminal instead of clicking this button.
    dashboard_owned_run = _orchestrator_is_running()
    external_run_in_flight = st.session_state.stage not in ("idle", "verified")
    disabled = dashboard_owned_run or external_run_in_flight

    if dashboard_owned_run:
        label, help_text = "Running…", "A run started from this button is still in progress."
    elif external_run_in_flight:
        label, help_text = "Reset & Run", "An iteration is in progress — wait for it to finish or stop it first."
    else:
        label, help_text = "Reset & Run", "Clears state and starts a fresh 3-iteration run."

    if st.button(label, disabled=disabled, help=help_text):
        do_reset_and_run()
        st.rerun()


# ---------------------------------------------------------------------------
# Event reader
# ---------------------------------------------------------------------------

def read_new_events() -> list[dict]:
    """Read lines appended since the last cursor position."""
    if not EVENTS_PATH.exists():
        return []
    events: list[dict] = []
    with EVENTS_PATH.open("rb") as fh:
        fh.seek(st.session_state.cursor)
        for raw in fh:
            raw = raw.strip()
            if raw:
                try:
                    events.append(json.loads(raw))
                except json.JSONDecodeError:
                    pass
        st.session_state.cursor = fh.tell()
    return events


# ---------------------------------------------------------------------------
# Event dispatcher
# ---------------------------------------------------------------------------

def apply_event(event: dict) -> bool:
    """
    Apply one event to session state.
    Returns True if it was a narration_chunk (hot path — skip UI redraw delay).
    """
    t = event.get("type", "")
    p = event.get("payload", {})

    if t == "sandbox_ready":
        st.session_state.sandbox_url    = p.get("url", "")
        st.session_state.sandbox_id     = p.get("sandbox_id", "")
        st.session_state.sandbox_region = p.get("region", "")
        st.session_state.sandbox_created_at = p.get("created_at", "")
        st.session_state.sandbox_spec   = p.get("spec", {})
        st.session_state.sandbox_status  = "running"
        st.session_state.iteration      = event.get("iteration", 0)
        st.session_state.vuln_class     = event.get("vulnerability_class", "")
        st.session_state.sandbox_history.append({
            "id":         p.get("sandbox_id", ""),
            "url":        p.get("url", ""),
            "region":     p.get("region", ""),
            "created_at": p.get("created_at", ""),
            "spec":       p.get("spec", {}),
            "status":     "running",
            "iteration":  event.get("iteration", 0),
            "vuln_class": event.get("vulnerability_class", ""),
        })
        # reset per-sandbox state
        st.session_state.diff           = ""
        st.session_state.wire_request   = None
        st.session_state.wire_response  = None
        st.session_state.wire_blocked   = None
        if not st.session_state.source_code and TARGET_APP_SOURCE.exists():
            try:
                st.session_state.source_code = TARGET_APP_SOURCE.read_text(encoding="utf-8")
            except OSError:
                st.session_state.source_code = ""

    elif t == "iteration_start":
        st.session_state.stage              = "scanning"
        st.session_state.sandbox_status     = "running"
        st.session_state.iteration          = event.get("iteration", st.session_state.iteration)
        st.session_state.vuln_class         = event.get("vulnerability_class", "")
        st.session_state.attacker_narration = ""
        st.session_state.attacker_technical = ""
        st.session_state.defender_narration = ""
        st.session_state.defender_technical = ""
        st.session_state.attacker_raw_stream = ""
        st.session_state.defender_raw_stream = ""
        st.session_state.diff               = ""
        st.session_state.wire_request       = None
        st.session_state.wire_response      = None
        st.session_state.wire_blocked       = None
        st.session_state.active_agent       = None
        st.session_state.active_agent_label = ""
        st.session_state._iteration_frozen  = False

    elif t == "agent_thinking":
        st.session_state.active_agent = p.get("agent")
        st.session_state.active_agent_label = p.get("label", "")
        if p.get("agent") == "defender":
            st.session_state.stage = "analysing"

    elif t == "narration_chunk":
        agent = p.get("agent")
        char  = p.get("char", "")
        if agent == "attacker":
            st.session_state.attacker_narration += char
        elif agent == "defender":
            st.session_state.defender_narration += char
        return True  # hot path

    elif t == "stream_chunk":
        # Raw SSE text delta from a real (non-mock) model call, shown live
        # before the assembled JSON response has finished parsing. Cleared
        # by iteration_start; stops being rendered once the matching
        # narration is non-empty (see _current_iteration_blocks).
        agent = p.get("agent")
        chunk = p.get("chunk", "")
        if agent == "attacker":
            st.session_state.attacker_raw_stream += chunk
        elif agent == "defender":
            st.session_state.defender_raw_stream += chunk
        return True  # hot path

    elif t == "llm_usage":
        st.session_state.llm_calls  += 1
        st.session_state.llm_tokens += p.get("total_tokens", 0)

    elif t == "attack_sent":
        st.session_state.stage              = "breached"
        st.session_state.wire_request       = p.get("request")
        st.session_state.wire_response      = p.get("response")
        st.session_state.wire_blocked       = False
        reasoning = p.get("agent_reasoning", {})
        st.session_state.attacker_narration = reasoning.get("narration", "")
        st.session_state.attacker_technical = reasoning.get("technical", "")
        st.session_state.active_agent       = None
        st.session_state.active_agent_label = ""

    elif t == "patch_applied":
        st.session_state.stage              = "patched"
        st.session_state.diff               = p.get("diff", "")
        st.session_state.source_code        = p.get("patched_source", "")
        reasoning = p.get("agent_reasoning", {})
        st.session_state.defender_narration = reasoning.get("narration", "")
        st.session_state.defender_technical = reasoning.get("technical", "")
        st.session_state.active_agent       = None
        st.session_state.active_agent_label = ""

    elif t == "verified":
        st.session_state.stage             = "verified"
        st.session_state.sandbox_status    = "verified"
        st.session_state.wire_request      = p.get("request")
        st.session_state.wire_response     = p.get("response")
        st.session_state.wire_blocked      = p.get("exploit_blocked", False)
        if st.session_state.sandbox_history:
            st.session_state.sandbox_history[-1]["status"] = "verified"

    elif t == "iteration_complete":
        st.session_state.active_agent = None
        st.session_state.history.extend(_current_iteration_blocks())
        st.session_state._iteration_frozen = True

    elif t == "sandbox_destroyed":
        sbox_id = p.get("sandbox_id", "")
        for entry in st.session_state.sandbox_history:
            if entry["id"] == sbox_id:
                entry["status"] = "destroyed"
                break

    return False


# ---------------------------------------------------------------------------
# CSS (injected once per session)
# ---------------------------------------------------------------------------

_CSS = """
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
    --feed-text: rgba(248,244,244,0.92);
    --feed-muted: rgba(248,244,244,0.55);
    --feed-divider: rgba(248,244,244,0.16);
}

@keyframes livePulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.25; } }
@keyframes caretBlink { 0%, 49% { opacity: 1; } 50%, 100% { opacity: 0; } }
@keyframes feedIn { from { opacity: 0; transform: translateY(14px); } to { opacity: 1; transform: translateY(0); } }

/* Force the light parchment shell regardless of the browser/OS dark-mode
   preference Streamlit otherwise follows — only the feed panel below is
   meant to read as dark. Belt-and-braces alongside .streamlit/config.toml,
   which is the primary fix (this CSS covers any client that ignores it). */
html, body,
[data-testid="stApp"],
[data-testid="stAppViewContainer"],
[data-testid="stMain"],
[data-testid="stHeader"],
[data-testid="stMainBlockContainer"] {
    background-color: var(--color-bg) !important;
    color: var(--color-text) !important;
}
[data-testid="stApp"] * {
    color: inherit;
}
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

/* — nav — */
.aos-brand { font-family: var(--font-heading); font-weight: 600; font-size: 18px; color: var(--color-text); }
.aos-tagline { font-size: 11px; color: rgba(32,31,29,0.55); letter-spacing: 0.02em; }
.aos-tag {
    display: inline-flex; align-items: center; font-size: 11px;
    padding: 3px 10px; border-radius: 3px;
    border: 1px solid var(--color-accent); color: var(--color-accent);
}
.aos-url {
    font-size: 11px; color: rgba(32,31,29,0.55); letter-spacing: 0.02em;
    text-align: right; margin-top: 4px;
}

/* — sidebar (sandbox roster) — */
[data-testid="stSidebar"] {
    background: var(--feed-bg) !important;
}
[data-testid="stSidebar"] * {
    color: var(--feed-text) !important;
}
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
    border: 1px solid var(--feed-divider); border-radius: 6px;
    background: rgba(255,255,255,0.03);
}
.aos-sbox-card.running { border-color: var(--color-accent); }
.aos-sbox-card.verified { border-color: var(--safe); }
.aos-sbox-card.destroyed { opacity: 0.55; }
.aos-sbox-tags { display: flex; gap: 6px; flex-wrap: wrap; }
.aos-sbox-tag {
    font-size: 10px; letter-spacing: 0.03em;
    padding: 2px 8px; border-radius: 3px;
    border: 1px solid var(--color-accent); color: var(--color-accent);
}
.aos-sbox-url {
    font-family: ui-monospace, Menlo, monospace; font-size: 10.5px;
    color: var(--feed-muted); word-break: break-all;
}
.aos-sbox-status {
    display: inline-flex; align-items: center; gap: 5px;
    font-size: 10px; letter-spacing: 0.06em; text-transform: uppercase;
}
.aos-sbox-status-dot { width: 6px; height: 6px; border-radius: 50%; }
.aos-sbox-status.running .aos-sbox-status-dot { background: var(--color-accent); animation: livePulse 1.1s ease-in-out infinite; }
.aos-sbox-status.verified .aos-sbox-status-dot { background: var(--safe); }
.aos-sbox-status.destroyed .aos-sbox-status-dot { background: var(--feed-muted); }
.aos-sbox-status.running { color: var(--color-accent); }
.aos-sbox-status.verified { color: var(--safe); }
.aos-sbox-status.destroyed { color: var(--feed-muted); }
.aos-sbox-meta {
    font-family: ui-monospace, Menlo, monospace; font-size: 10.5px;
    color: var(--feed-muted);
}
.aos-sidebar-empty {
    font-family: var(--font-body); font-style: italic; font-size: 12px;
    color: var(--feed-muted);
}

/* — round gallery — */
.aos-round-card {
    display: flex; align-items: center; gap: 12px;
    padding: 10px 16px; border-radius: 4px;
    border: 1px solid var(--color-divider);
}
.aos-round-card.active { border-color: var(--color-accent); box-shadow: 0 1px 2px rgba(45,43,43,0.14); }
.aos-round-numeral {
    font-family: var(--font-heading); font-weight: 600; font-size: 26px;
    width: 30px; flex: none; color: rgba(32,31,29,0.45);
}
.aos-round-card.active .aos-round-numeral { color: var(--color-accent); }
.aos-round-title { font-family: var(--font-heading); font-weight: 600; font-size: 15px; color: var(--color-text); }
.aos-round-stage {
    font-size: 10.5px; letter-spacing: 0.06em; text-transform: uppercase;
    padding: 3px 9px; border-radius: 3px; border: 1px solid currentColor;
    flex: none; white-space: nowrap;
}

/* — feed panel — */
.aos-feed {
    background: var(--feed-bg); border-radius: 7px;
    padding: 24px; display: flex; flex-direction: column; gap: 18px;
}
.aos-feed-empty { color: var(--feed-muted); font-family: var(--font-body); font-style: italic; }

.aos-divider { display: flex; align-items: center; gap: 14px; margin: 6px 0; animation: feedIn .5s ease both; }
.aos-divider-line { flex: 1; height: 1px; background: var(--feed-divider); }
.aos-divider-label {
    font-size: 11px; letter-spacing: 0.12em; text-transform: uppercase;
    white-space: nowrap; font-family: var(--font-heading); font-weight: 600;
}

.aos-narration { display: flex; flex-direction: column; gap: 8px; animation: feedIn .5s ease both; }
.aos-role-tag {
    font-size: 10.5px; letter-spacing: 0.1em; text-transform: uppercase; font-weight: 600;
    border-radius: 3px; padding: 2px 8px; width: fit-content; border: 1px solid currentColor;
}
.aos-role-tag.attacker { color: var(--danger); }
.aos-role-tag.defender { color: var(--safe); }
.aos-quote {
    font-family: var(--font-heading); font-style: italic; font-weight: 600;
    font-size: 24px; line-height: 1.4; color: var(--feed-text);
}
.aos-caret { animation: caretBlink 0.9s step-end infinite; color: var(--color-accent); }
.aos-technical {
    font-family: ui-monospace, Menlo, monospace; font-size: 11.5px;
    line-height: 1.6; color: var(--feed-muted); white-space: pre-wrap;
}

.aos-taunt {
    display: flex; flex-direction: column; gap: 6px;
    padding-left: 18px; border-left: 2px dashed var(--danger);
    animation: feedIn .5s ease both;
}
.aos-taunt-tag { font-size: 10px; letter-spacing: 0.08em; text-transform: uppercase; color: var(--danger); width: fit-content; }
.aos-taunt-text { font-family: ui-monospace, Menlo, monospace; font-size: 13px; font-style: italic; color: var(--feed-muted); }

.aos-wire {
    display: flex; flex-direction: column; gap: 8px;
    padding-left: 14px; animation: feedIn .5s ease both;
}
.aos-wire.blocked { border-left: 3px solid var(--safe); }
.aos-wire.breach { border-left: 3px solid var(--danger); }
.aos-wire-header { display: flex; align-items: center; gap: 8px; }
.aos-wire-dot { width: 7px; height: 7px; border-radius: 50%; }
.aos-wire.blocked .aos-wire-dot { background: var(--safe); }
.aos-wire.breach .aos-wire-dot { background: var(--danger); }
.aos-wire-label { font-size: 11px; letter-spacing: 0.06em; text-transform: uppercase; font-weight: 600; }
.aos-wire.blocked .aos-wire-label { color: var(--safe); }
.aos-wire.breach .aos-wire-label { color: var(--danger); }
.aos-wire-block {
    font-family: ui-monospace, Menlo, monospace; font-size: 11.5px; line-height: 1.6;
    white-space: pre-wrap; word-break: break-all; color: var(--feed-text);
    background: rgba(255,255,255,0.04); border: 1px solid var(--feed-divider);
    border-radius: 4px; padding: 10px 12px;
}
.aos-wire-curl { color: var(--color-accent); border-color: var(--color-accent); }

.aos-live-timer {
    display: flex; align-items: center; gap: 8px;
    font-family: ui-monospace, Menlo, monospace; font-size: 12px;
    color: var(--color-accent); animation: feedIn .5s ease both;
}
.aos-live-timer-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--color-accent); animation: livePulse 1.1s ease-in-out infinite; }

.aos-diff {
    display: flex; flex-direction: column; gap: 4px;
    font-family: ui-monospace, Menlo, monospace; font-size: 12px; line-height: 1.7;
    background: rgba(255,255,255,0.04); border: 1px solid var(--feed-divider);
    border-radius: 4px; padding: 12px 14px; animation: feedIn .5s ease both;
}
.aos-diff-kicker {
    font-size: 10px; letter-spacing: 0.1em; text-transform: uppercase;
    color: var(--color-accent); margin-bottom: 4px;
}
.aos-diff-line { padding-left: 8px; white-space: pre-wrap; word-break: break-all; }
.aos-diff-line.add { color: var(--safe); border-left: 2px solid var(--safe); }
.aos-diff-line.del { color: var(--danger); border-left: 2px solid var(--danger); }
.aos-diff-line.ctx { color: var(--feed-text); border-left: 2px solid transparent; }

.aos-live-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--color-accent); animation: livePulse 1.1s ease-in-out infinite; }
</style>
"""


def inject_css() -> None:
    st.html(_CSS)


# ---------------------------------------------------------------------------
# Render helpers
# ---------------------------------------------------------------------------

MODEL_TAG = "ai& · deepseek-v4-flash"

# Fixed round order for the gallery strip — mirrors orchestrator/main.py's
# ITERATIONS list (sqli, idor, missing_auth), independent of which iteration
# has actually run yet so all three rounds are always visible.
ROUND_NUMERALS = {1: "I", 2: "II", 3: "III"}


def render_nav_bar() -> None:
    col_brand, col_tags, col_action = st.columns([3, 2.4, 0.8])
    with col_brand:
        st.html(
            '<div class="aos-brand">Attack on Sandbox</div>'
            '<div class="aos-tagline">Two agents. One sandbox. No trust.</div>'
        )
    with col_tags:
        st.html(
            f'<div style="text-align:right; padding-top: 6px">'
            f'<span class="aos-tag">Daytona sandbox</span>&nbsp;'
            f'<span class="aos-tag">{MODEL_TAG}</span>'
            f'</div>'
        )
    with col_action:
        st.html('<div style="height: 18px"></div>')
        render_reset_button()


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
        f'<div class="aos-sbox-tags">'
        f'<span class="aos-sbox-tag">{_escape(sbox_id) or "sandbox"}</span>'
        f'</div>'
        f'<div class="aos-sbox-url">{_escape(url) or "—"}</div>'
        f'{meta_line}'
        f'<div class="aos-sbox-status {status}">'
        f'<span class="aos-sbox-status-dot"></span>{status}'
        f'</div>'
        f'</div>'
    )


def render_sidebar() -> None:
    """Sticky sidebar listing every Daytona sandbox this run has created —
    not just the currently-live one — plus overall ai& call/token usage.
    Uses Streamlit's native sidebar so it stays pinned while the feed scrolls.
    """
    with st.sidebar:
        st.html('<div class="aos-sidebar-title">Daytona sandboxes</div>')
        calls, tokens = st.session_state.llm_calls, st.session_state.llm_tokens
        if calls:
            st.html(f'<div class="aos-sidebar-usage">{MODEL_TAG} · {calls} calls · {tokens:,} tokens</div>')

        history = st.session_state.sandbox_history
        if not history:
            st.html('<div class="aos-sidebar-empty">Waiting for the first sandbox…</div>')
            return

        # Most recent first so the live sandbox is always at the top.
        for entry in reversed(history):
            st.html(_sbox_card_html(entry))


def _round_stage_label(round_num: int) -> str:
    """Vulnerable / Scanning / Breached / Analysing / Patched / Verified for a
    gallery card, derived from current session state — Pending if that
    round's iteration hasn't started yet, Verified if a later round has."""
    s = st.session_state
    if s.iteration > round_num:
        return "verified"
    if s.iteration < round_num or not s.iteration:
        return "pending"
    return s.stage


def render_round_gallery() -> None:
    cols = st.columns(3)
    for round_num, col in zip((1, 2, 3), cols):
        stage = _round_stage_label(round_num)
        active = st.session_state.iteration == round_num
        color = STAGE_COLORS.get(stage, "#9b9797")
        with col:
            st.html(
                f'<div class="aos-round-card{" active" if active else ""}">'
                f'<div class="aos-round-numeral">{ROUND_NUMERALS[round_num]}</div>'
                f'<div style="flex:1;min-width:0">'
                f'<div class="aos-round-title">Iteration {ROUND_NUMERALS[round_num]}</div>'
                f'</div>'
                f'<div class="aos-round-stage" style="color:{color}">{stage.upper()}</div>'
                f'</div>'
            )


def _format_request(req: dict) -> str:
    if not req:
        return ""
    method = req.get("method", "")
    url    = req.get("url", "")
    hdrs   = req.get("headers") or {}
    body   = req.get("body")
    lines  = [f"{method} {url}"]
    for k, v in hdrs.items():
        lines.append(f"{k}: {v}")
    if body is not None:
        lines.append("")
        lines.append(json.dumps(body, indent=2) if isinstance(body, dict) else str(body))
    return "\n".join(lines)


def _format_curl(req: dict) -> str:
    """Render {method, url, headers, body} as a copy-pasteable curl command —
    a live audience can read it as a real terminal command they could run
    themselves against the visible sandbox URL, not a canned animation."""
    if not req:
        return ""
    method = req.get("method", "GET").upper()
    url    = req.get("url", "")
    hdrs   = req.get("headers") or {}
    body   = req.get("body")

    parts = [f"curl -X {method} '{url}'"]
    for k, v in hdrs.items():
        parts.append(f"  -H '{k}: {v}'")
    if body is not None:
        body_s = json.dumps(body) if isinstance(body, dict) else str(body)
        escaped_body = body_s.replace("'", "'\\''")
        parts.append(f"  -d '{escaped_body}'")
    return " \\\n".join(parts)


def _format_response(resp: dict) -> str:
    if not resp:
        return ""
    status = resp.get("status", "")
    body   = resp.get("body", "")
    body_s = json.dumps(body, indent=2) if isinstance(body, dict) else str(body)
    return f"HTTP {status}\n\n{body_s}"


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _taunt_for(vuln_class: str) -> str:
    """Look up the pre-scripted attacker taunt for a vulnerability class.

    Returns "" for an unrecognised class rather than raising, so a caller can
    treat a missing taunt the same as "no taunt to show yet".
    """
    return TAUNTS.get(vuln_class, "")


def _feed_live_timer_block(agent: str, label: str, timer_id: str) -> str:
    """HTML+JS for a real wall-clock timer ticking while a request is in
    flight — proves this is genuinely live, since a canned animation has no
    reason to render a clock that actually counts real elapsed time.

    Client-side JS (setInterval from performance.now() at render time)
    rather than a server-computed elapsed value: it ticks smoothly in real
    browser time between Streamlit reruns, not just once per ~80ms poll.
    Re-initialises harmlessly on every rerun while this block keeps
    rendering — visually indistinguishable from one continuously running
    clock, and stops being rendered (frozen at its last value) the instant
    the caller swaps in the real response block.
    """
    role_label = "Attacker" if agent == "attacker" else "Defender"
    return (
        f'<div class="aos-live-timer">'
        f'<div class="aos-live-timer-dot"></div>'
        f'<span class="aos-role-tag {agent}">{role_label}</span>'
        f'<span>{_escape(label)}</span>'
        f'<span id="{timer_id}">0.00s</span>'
        f'<script>'
        f'(function(){{'
        f'  var start = performance.now();'
        f'  var el = document.getElementById("{timer_id}");'
        f'  var tick = function(){{'
        f'    if (!el || !document.body.contains(el)) return;'
        f'    el.textContent = ((performance.now() - start) / 1000).toFixed(2) + "s";'
        f'    setTimeout(tick, 100);'
        f'  }};'
        f'  tick();'
        f'}})();'
        f'</script>'
        f'</div>'
    )


def _feed_narration_block(agent: str, narration: str, technical: str, complete: bool) -> str:
    """HTML for one narration card: role pill, italic serif quote, optional
    trailing caret while incomplete, technical detail once complete."""
    role_label = "Attacker" if agent == "attacker" else "Defender"
    quote = _escape(narration)
    caret = '<span class="aos-caret">▌</span>' if not complete else ""
    technical_html = f'<div class="aos-technical">{_escape(technical)}</div>' if complete and technical else ""
    return (
        f'<div class="aos-narration">'
        f'<span class="aos-role-tag {agent}">{role_label}</span>'
        f'<div class="aos-quote">“{quote}”{caret}</div>'
        f'{technical_html}'
        f'</div>'
    )


def _feed_raw_stream_block(agent: str, raw_text: str) -> str:
    """HTML for the raw JSON-in-progress text streaming in live from a real
    (non-mock) model call, shown before the clean narration card is ready —
    proves this is a genuine live token stream, not a canned animation."""
    role_label = "Attacker" if agent == "attacker" else "Defender"
    return (
        f'<div class="aos-narration">'
        f'<span class="aos-role-tag {agent}">{role_label}</span>'
        f'<div class="aos-technical">{_escape(raw_text)}'
        f'<span class="aos-caret">▌</span></div>'
        f'</div>'
    )


def _feed_taunt_block(taunt_text: str) -> str:
    """HTML for the dashed-border attacker taunt line between breach and patch."""
    return (
        f'<div class="aos-taunt">'
        f'<span class="aos-taunt-tag">Attacker → Defender</span>'
        f'<div class="aos-taunt-text">{_escape(taunt_text)}</div>'
        f'</div>'
    )


def _feed_wire_block(request: dict, response: dict, blocked: bool | None) -> str:
    """HTML for one wire request/response pair, colored by outcome.

    Leads with the curl-equivalent command — a live audience can read it as
    a real terminal command they could copy and run themselves against the
    visible sandbox URL, which a canned animation would have no reason to
    render in copyable form.
    """
    css_class = "blocked" if blocked else "breach"
    label = "Exploit blocked — patch holds" if blocked else "Breach confirmed"
    curl_text = _escape(_format_curl(request))
    req_text = _escape(_format_request(request))
    resp_text = _escape(_format_response(response))
    return (
        f'<div class="aos-wire {css_class}">'
        f'<div class="aos-wire-header"><div class="aos-wire-dot"></div>'
        f'<span class="aos-wire-label">{label}</span></div>'
        f'<div class="aos-wire-block aos-wire-curl">$ {curl_text}</div>'
        f'<div class="aos-wire-block">{req_text}</div>'
        f'<div class="aos-wire-block">{resp_text}</div>'
        f'</div>'
    )


def _feed_divider(text: str, color: str) -> str:
    return (
        f'<div class="aos-divider">'
        f'<div class="aos-divider-line"></div>'
        f'<div class="aos-divider-label" style="color:{color}">{_escape(text)}</div>'
        f'<div class="aos-divider-line"></div>'
        f'</div>'
    )


def _diff_line_class(line: str) -> str:
    """Classify one unified-diff line for coloring: add/del/ctx.

    Skips the +++/--- file headers and @@ hunk markers entirely (they're
    metadata, not code) by returning "" — callers drop those lines.
    """
    if line.startswith(("+++", "---", "@@")):
        return ""
    if line.startswith("+"):
        return "add"
    if line.startswith("-"):
        return "del"
    return "ctx"


def _feed_diff_block(endpoint: str, diff: str) -> str:
    """HTML for a unified diff, one colored/bordered line per row, matching
    the prototype's line-by-line diff rendering (feedIn stagger, no per-char
    typewriter — that's cosmetic-only in the prototype and not reproduced)."""
    rows = []
    for raw_line in diff.splitlines():
        css_class = _diff_line_class(raw_line)
        if not css_class:
            continue
        rows.append(f'<div class="aos-diff-line {css_class}">{_escape(raw_line)}</div>')
    return (
        f'<div class="aos-diff">'
        f'<div class="aos-diff-kicker">{_escape(endpoint)} — patch applied</div>'
        f'{"".join(rows)}'
        f'</div>'
    )


def _current_iteration_blocks() -> list[str]:
    """Blocks for the iteration currently in progress, built from the live
    session-state fields that iteration_start clears at the top of each new
    iteration: divider -> attacker narration -> wire (breach) -> taunt ->
    defender narration -> diff -> wire (verified).

    Renders whatever is known so far; sections that haven't happened yet
    simply aren't emitted. Returns nothing once iteration_complete has
    already frozen these same blocks into history (_iteration_frozen) —
    otherwise the last iteration of a run, which never gets superseded by
    a following iteration_start, would render twice.
    """
    s = st.session_state
    blocks: list[str] = []

    if not s.iteration or s._iteration_frozen:
        return blocks

    vc_label = VULN_LABELS.get(s.vuln_class, s.vuln_class)
    if s.stage == "verified":
        color = "var(--safe)" if s.wire_blocked else "var(--danger)"
        divider_text = f"Iteration {s.iteration} complete — {vc_label}"
    else:
        color = "var(--color-accent)"
        divider_text = f"Iteration {s.iteration} — {vc_label}"
    blocks.append(_feed_divider(divider_text, color))

    attacker_active = s.active_agent == "attacker"
    attacker_streaming_raw = attacker_active and s.attacker_raw_stream and not s.attacker_narration
    attacker_waiting = attacker_active and not s.attacker_raw_stream and not s.attacker_narration
    if attacker_waiting:
        blocks.append(_feed_live_timer_block(
            "attacker", "requesting deepseek-v4-flash…", f"aos-timer-attacker-{s.iteration}"
        ))
    elif attacker_streaming_raw:
        blocks.append(_feed_raw_stream_block("attacker", s.attacker_raw_stream))
    elif s.attacker_narration or attacker_active:
        blocks.append(_feed_narration_block(
            "attacker", s.attacker_narration, s.attacker_technical,
            complete=not attacker_active or bool(s.wire_request),
        ))

    if s.wire_request is not None and s.stage in ("breached", "analysing", "patched", "verified"):
        blocked = False if s.stage != "verified" else s.wire_blocked
        blocks.append(_feed_wire_block(s.wire_request, s.wire_response, blocked))

        taunt = _taunt_for(s.vuln_class)
        if taunt and s.stage in ("analysing", "patched", "verified"):
            blocks.append(_feed_taunt_block(taunt))

    defender_active = s.active_agent == "defender"
    defender_streaming_raw = defender_active and s.defender_raw_stream and not s.defender_narration
    defender_waiting = defender_active and not s.defender_raw_stream and not s.defender_narration
    if defender_waiting:
        blocks.append(_feed_live_timer_block(
            "defender", "requesting deepseek-v4-flash…", f"aos-timer-defender-{s.iteration}"
        ))
    elif defender_streaming_raw:
        blocks.append(_feed_raw_stream_block("defender", s.defender_raw_stream))
    elif s.defender_narration or defender_active:
        blocks.append(_feed_narration_block(
            "defender", s.defender_narration, s.defender_technical,
            complete=not defender_active or bool(s.diff),
        ))

    if s.diff and s.stage in ("patched", "verified"):
        endpoint = s.wire_request.get("url", "") if s.wire_request else ""
        blocks.append(_feed_diff_block(endpoint, s.diff))

    if s.stage == "verified" and s.wire_request is not None:
        blocks.append(_feed_wire_block(s.wire_request, s.wire_response, s.wire_blocked))

    return blocks


def render_feed() -> None:
    """Running feed of every iteration this demo run has produced so far:
    each completed iteration's full narration/wire/taunt/diff blocks (frozen
    in st.session_state.history at iteration_complete, before the next
    iteration_start wipes the live fields), followed by whatever is known
    so far for the iteration currently in progress. Nothing is removed
    until a reset.
    """
    blocks = list(st.session_state.history) + _current_iteration_blocks()

    if not blocks:
        st.html('<div class="aos-feed"><div class="aos-feed-empty">Waiting for the first iteration…</div></div>')
        return

    # unsafe_allow_javascript: st.html strips <script> tags by default
    # (DOMPurify), which silently no-ops _feed_live_timer_block's clock and
    # the auto-scroll script below. Safe here — every value interpolated
    # into these blocks passes through _escape() first, so no untrusted
    # input ever reaches this HTML.
    #
    # Auto-scroll: a marker div after the last block, scrolled into view on
    # every render. scrollIntoView on an element already in view is a
    # harmless no-op, so this is safe to re-run every ~80ms poll cycle
    # without fighting a user who has manually scrolled up to read history —
    # it only moves the viewport when new content actually pushed the
    # marker out of view.
    st.html(
        f'<div class="aos-feed">{"".join(blocks)}'
        f'<div id="aos-feed-end"></div>'
        f'<script>'
        f'document.getElementById("aos-feed-end")'
        f'?.scrollIntoView({{behavior: "auto", block: "end"}});'
        f'</script>'
        f'</div>',
        unsafe_allow_javascript=True,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Narration_chunk and stream_chunk are capped lower than MAX_EVENTS_PER_CYCLE
# and paced with a small per-char sleep so both the narration typewriter and
# the raw-JSON stream reveal smoothly on screen instead of jumping in large
# blocks. stream_chunk deltas arrive unpaced from a real ai& call and can
# burst dozens of times per second — without this cap each burst triggers a
# full feed re-render (st.html() redraws the whole .aos-feed div every
# rerun), which is what caused visible flashing during real (non-mock) runs.
# Non-narration/stream events still process at full speed within the cycle.
MAX_NARRATION_CHARS_PER_CYCLE = 15
NARRATION_CHAR_DELAY_S = 0.01
MAX_STREAM_CHARS_PER_CYCLE = 15
STREAM_CHAR_DELAY_S = 0.01


def _process_events_this_cycle(events: list[dict]) -> list[dict]:
    """Apply events up to the per-cycle caps, returning any left for next cycle."""
    narration_chars_used = 0
    stream_chars_used = 0
    processed = 0
    for event in events:
        event_type = event.get("type")
        if event_type == "narration_chunk":
            if narration_chars_used >= MAX_NARRATION_CHARS_PER_CYCLE:
                break
            apply_event(event)
            narration_chars_used += 1
            processed += 1
            time.sleep(NARRATION_CHAR_DELAY_S)
        elif event_type == "stream_chunk":
            if stream_chars_used >= MAX_STREAM_CHARS_PER_CYCLE:
                break
            apply_event(event)
            stream_chars_used += len(event.get("payload", {}).get("chunk", ""))
            processed += 1
            time.sleep(STREAM_CHAR_DELAY_S)
        else:
            if processed >= MAX_EVENTS_PER_CYCLE:
                break
            apply_event(event)
            processed += 1
    return events[processed:]


def main() -> None:
    st.set_page_config(
        page_title="Attack on Sandbox",
        page_icon="⚔️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    init_state()
    inject_css()

    # ---- poll events -------------------------------------------------------
    new_events = read_new_events()
    got_events = bool(new_events)

    remaining = _process_events_this_cycle(new_events)

    # If we capped, put remaining back by rewinding the cursor
    if remaining:
        rewind = sum(len(json.dumps(e).encode()) + 1 for e in remaining)
        st.session_state.cursor = max(0, st.session_state.cursor - rewind)

    # ---- layout ------------------------------------------------------------
    render_sidebar()
    render_nav_bar()
    render_round_gallery()
    st.divider()
    render_feed()

    # ---- rerun loop --------------------------------------------------------
    if got_events:
        st.rerun()
    else:
        time.sleep(POLL_INTERVAL_S)
        st.rerun()


if __name__ == "__main__":
    main()
