# Attack on Sandbox — Implementation Roadmap

## Final Outcome

Two processes running simultaneously on one machine at demo time:

**Process 1 — Orchestrator** (`python orchestrator/main.py`)
Runs the full adversarial loop autonomously with zero human input after launch:
- Iteration 1: Attacker agent receives the target app URL and a scoped prompt ("look for SQL injection only"). It reasons about the app, constructs a payload, and returns a JSON object describing an HTTP request. The orchestrator fires that request for real, captures the real response, writes an `attack_sent` event, and passes the request/response pair + current source to the defender. Defender returns a JSON object with the full patched file contents. Orchestrator writes the patch, redeploys into the Daytona sandbox, restarts the service, then replays the exact original exploit request. The re-verification result is written as a `verified` event.
- Iteration 2: Same loop, scoped to IDOR/broken auth.
- All HTTP traffic is real. All ai& API calls are real. The sandbox is torn down and respun between iterations.

**Process 2 — Dashboard** (`streamlit run dashboard/app.py`)
Polls `events.json` on an interval and renders four zones live:
- Iteration tracker showing current iteration + stage (Vulnerable → Breached → Patched → Verified)
- Code panel showing current source with relevant lines highlighted, flipping to a diff view the moment a patch lands
- Wire feed showing the actual HTTP request and raw response, styled red for breaches, green for blocked attempts
- Agent reasoning panel showing short-form summaries of what each agent decided and why

**Backup:** a recorded video of a complete clean run exists before the live demo. If Daytona or ai& goes down on stage, the video plays instead.

The full demo loop takes approximately 2 minutes end-to-end.

---

## Parallelism Map

```
Phase 1 ──────────────────────────► Phase 3A ──┐
                                                 ├──► Phase 4 ──► Phase 5 ──► Phase 6
Phase 2A ──► Phase 3B ─────────────────────────┘
         └──► Phase 2B ──────────────────────────────────────────────────────────────►┘
```

Maximum concurrency windows:
- **Phase 1 + Phase 2A** can start simultaneously (no shared files, no dependencies)
- **Phase 2B + Phase 3A + Phase 3B** can all run simultaneously once their respective predecessors are done
- Phase 4 is the first sequential gate — needs both 3A and 3B complete

---

## Phase 1 — Target App 🔄 REFACTORED (note-taking API)

**Touches:** `target-app/app.py`, `target-app/requirements.txt`
**Depends on:** nothing
**Unlocks:** Phase 3A

### Concept
A simple note-taking API. Annie has private notes seeded in the database. Bob is the attacker's foothold — a legitimate but low-privilege user. All three vulnerabilities are bugs of omission.

### Database schema
Two tables:
- `users`: `id, username, password, role`
  - `id=1, username='annie', password='sunflower_2006!', role='admin'`
  - `id=2, username='bob', password='letmein', role='user'`
- `notes`: `id, owner_id, title, content`
  - `id=1` — *"Dear Diary"* — personal diary entry, the one bob overwrites with lorem ipsum
  - `id=2` — *"Passwords (DO NOT OPEN)"* — `gmail: anniesg2006@gmail.com / sunflower_2006!, netflix: annieee / popcorn4ever, bank pin: 4821` — the one bob reads and copies; this is what flashes on the wire feed in red
  - `id=3` — *"Jamie's birthday"* — dinner plans, untouched by the exploit

### Endpoints
- `GET /` — health check
- `POST /login` — **VULN-1 (SQLi):** raw f-string query, no parameterisation. Payload `' OR '1'='1' --` bypasses auth entirely.
- `GET /notes/<id>` — **VULN-2a (IDOR read):** no ownership check. Bob's token reads annie's notes.
- `PUT /notes/<id>` — **VULN-2b (IDOR write):** no ownership check. Bob's token overwrites annie's notes. Same omission, same fix.
- `POST /reset` — **VULN-3 (stretch, missing auth):** no `Authorization` check. Any unauthenticated caller wipes and reseeds the DB.

### Token scheme
`base64(str(user_id))` — trivially decodable, functional enough to drive the IDOR demo.

### Verification gate
Before moving to Phase 3A, manually confirm:
1. `POST /login` with `' OR '1'='1' --` returns 200 + a token
2. `GET /notes/1` with bob's token returns annie's note content
3. `PUT /notes/1` with bob's token successfully overwrites annie's note
4. `POST /reset` with no `Authorization` header returns 200 (stretch)

---

## Phase 2A — Event System ✅ COMPLETE

**Touches:** `orchestrator/__init__.py`, `orchestrator/events.py`, `orchestrator/make_fixture.py`, `events.json`
**Depends on:** nothing
**Unlocks:** Phase 2B, Phase 3B

### Goal
Define the single shared data contract that connects the orchestrator to the dashboard. Every observable state change in the system is represented as a structured event appended to `events.json`. Getting this schema right early prevents rework in both the orchestrator and dashboard later.

### Implementation

**`orchestrator/events.py`** — the sole event-writing interface. All orchestrator code imports from here; nothing else writes to `events.json` directly.

Public API:
- `write_event(event: dict, path: str = "events.json") -> None` — appends one JSON line; opens in `"a"` mode
- `make_sandbox_ready(sandbox_id, url, region, created_at, cpu, memory, iteration, vulnerability_class) -> dict`
- `make_sandbox_destroyed(sandbox_id, iteration, vulnerability_class) -> dict`
- `make_iteration_start(iteration, vulnerability_class) -> dict`
- `make_agent_thinking(agent, label, iteration, vulnerability_class) -> dict` — `agent`: `"attacker"|"defender"`; `label`: static string
- `make_narration_chunk(agent, char, iteration, vulnerability_class) -> dict` — validates `len(char) == 1`
- `make_attack_sent(request, response, agent_reasoning, iteration, vulnerability_class) -> dict`
- `make_patch_applied(diff, patched_source, agent_reasoning, iteration, vulnerability_class) -> dict`
- `make_verified(request, response, exploit_blocked, iteration, vulnerability_class) -> dict` — validates `isinstance(exploit_blocked, bool)`
- `make_iteration_complete(iteration, vulnerability_class) -> dict`

Internal helper `_base(type_, iteration, vulnerability_class)` stamps every event with `{type, timestamp, iteration, vulnerability_class}` using UTC ISO 8601 + `Z` suffix.

### Event schema
Each event is one JSON object per line (newline-delimited JSON), with at minimum:
- `type` — one of: `sandbox_ready`, `sandbox_destroyed`, `iteration_start`, `agent_thinking`, `narration_chunk`, `attack_sent`, `patch_applied`, `verified`, `iteration_complete`
- `timestamp` — ISO 8601 UTC, e.g. `"2026-07-18T14:32:01.123Z"`
- `iteration` — integer (1, 2, or 3)
- `vulnerability_class` — `"sqli"`, `"idor"`, or `"missing_auth"`
- `payload` — object whose shape varies by event type (see below)

Event-specific payload shapes:
- `sandbox_ready`: `{ sandbox_id, url, region, created_at, spec: {cpu, memory} }` — written by `setup.py` once Flask health check responds
- `sandbox_destroyed`: `{ sandbox_id }` — written at end of iteration; dashboard moves to history log
- `narration_chunk`: `{ agent, char }` — one event per character; dashboard appends for typewriter effect
- `agent_thinking`: `{ agent, label }` — written before each AI call; zero API cost
- `attack_sent`: `{ request: {method, url, headers, body}, response: {status, body}, agent_reasoning: {narration, technical} }`
- `patch_applied`: `{ diff, patched_source, agent_reasoning: {narration, technical} }` — diff computed by orchestrator via `difflib`
- `verified`: `{ request, response, exploit_blocked: boolean }`

**`agent_reasoning` is always `{narration, technical}`, never a plain string.**

### Fixture file
**`orchestrator/make_fixture.py`** — generates `events.json` by calling the actual event constructors (not hand-typed JSON), guaranteeing schema consistency. Run with `python orchestrator/make_fixture.py`.

Fixture covers all three iterations in sequence:
1. SQLi — `sbox-c7d2e1` / `https://c7d2e1.daytona.io`
2. IDOR — `sbox-a3f9c2` / `https://a3f9c2.daytona.io`
3. Missing auth (stretch) — `sbox-b1d8f4` / `https://b1d8f4.daytona.io`

613 events total: 586 `narration_chunk`, 6 `agent_thinking`, 3 each of the remaining types. All sandbox URLs use fake `https://<id>.daytona.io` format (not localhost). Fixture is gitignored — regenerate anytime with `make_fixture.py`.

---

## Phase 2B — Dashboard ✅ COMPLETE

**Touches:** `dashboard/app.py`, `dashboard/requirements.txt`
**Depends on:** Phase 2A fixture
**Unlocks:** Phase 6 (contributes to final rehearsal)

### Goal
A Streamlit app that reads `events.json` on a polling interval and renders the current state of the adversarial loop in a visually clear, demo-ready layout. Can be developed to full completion before the real orchestrator exists — it only needs the fixture file.

### Design reference
A standalone HTML prototype exists (`Attack on Sandbox Dashboard - Standalone Claude Design.html`). It is a rough sketch built against an older version of the spec — use it for visual/animation inspiration only, not as a functional spec. Key deltas documented below.

### Layout and zones
- **Top bar:** iteration badge + current stage label (`Vulnerable` / `Scanning...` / `Breached` / `Analysing...` / `Patched` / `Verified`), derived from the last event type seen. `agent_thinking` events drive the intermediate animated states.
  - **Do NOT show the endpoint name (`POST /login`, `GET /notes/<id>`) in the iteration tracker cards.** The endpoint is revealed naturally inside the wire feed when the attacker fires its request — showing it upfront undermines the discovery framing. Iteration cards show only: numeral, `Iteration I/II/III`, and stage badge.
  - **Show the live Daytona sandbox URL** prominently in the top bar (next to the "Daytona sandbox" badge). Display the real `https://<id>.daytona.io` URL so the audience can see it is not localhost. Make it visually distinct — this is the proof the sandbox is real. The URL should update when a new sandbox is spun up between iterations.

- **Status panel (always-visible sidebar or bottom bar):** two columns, pinned — never scrolls with the feed. Updated live from `sandbox_ready`, `sandbox_destroyed`, and streaming token events.

  ```
  DAYTONA SANDBOX                    AI& (deepseek-v4-flash)
  ID:      sbox-c7d2e1               Model:   deepseek-v4-flash
  URL:     https://c7d2e1.daytona.io Calls:   3
  Region:  us-east-1                 Tokens:  ~1,240
  Status:  ● RUNNING                 Latency: 8.3s avg
  Created: 18 Jul 2026, 14:32:01

  PREVIOUS SANDBOXES
  sbox-a3f9c2  Iteration I   SQLi         ✓ destroyed 14:33:01
  ```

  Daytona column fields (from `sandbox_ready` event payload):
  - `ID` — sandbox ID
  - `URL` — live `https://` endpoint
  - `Region` — where it's running
  - `Status` — `● RUNNING` (green) / `● RESTARTING` (amber, during patch redeploy) — derived from orchestrator events
  - `Created` — timestamp from `sandbox_ready`

  ai& column fields (tracked by orchestrator, written to events):
  - `Model` — `deepseek-v4-flash` (static; pulled from config)
  - `Calls` — running count of ai& API calls made this session
  - `Tokens` — cumulative token count from `usage` field in streaming response (available via `stream_options={"include_usage": True}`)
  - `Latency` — rolling average time from `agent_thinking` to corresponding `attack_sent`/`patch_applied`

  Previous sandboxes log: populated from `sandbox_destroyed` events. Shows ID, which iteration it served, vulnerability class, and destruction timestamp. Proves sandboxes are being created and torn down, not one persistent server.
- **Left panel — Code view:** display the current `target-app/app.py` source. When a `patch_applied` event arrives, switch to a diff view (additions in green, removals in red) computed from the event's `diff` field. Use `st.code()` with syntax highlighting.
- **Centre panel — Wire feed:** for each `attack_sent` and `verified` event, show the full HTTP request including the **real Daytona sandbox URL** in the request line (e.g. `POST https://abc123.daytona.io/login`) — not a localhost URL. This is the second proof point that traffic is hitting a real remote sandbox. Style the block red if `exploit_blocked == false` (breach succeeded), green if `exploit_blocked == true` (patch held).
- **Right panel — Agent reasoning:** for each agent action, show a compact card with:
  - Agent role label (Attacker / Defender) and event type as a header
  - When an `agent_thinking` event arrives: render an animated pending card with the `label` field and a pulsing indicator. This card is replaced — not appended — when the corresponding `attack_sent` or `patch_applied` event arrives.
  - `narration` text large and readable — this is what the audience watches. The two voices are deliberately asymmetric: the attacker's narration is certain and clinical (it knew what it was doing); the defender's narration is investigative, building from the evidence (it had to figure it out). This asymmetry is the dramatic core of the demo.
  - `technical` text below in a small `st.code()` monospace block — for judges who want the full reasoning trail
  - **Attacker taunt:** a short pre-scripted one-liner rendered as a distinct visual beat between the breach wire feed and the defender card (dashed left border, italic). This is authored by you, not generated by the model — it is pure theatre. The defender never sees it; it receives only request + response + source. Examples: *"Thanks for the login — didn't even need a password."*, *"Appreciate Annie's notes — didn't need to be her to read them."*, *"Reset's done — nobody even asked who I was."*
- **Polling:** use `st.rerun()` on a short interval (e.g. 2 seconds). Avoid re-reading the whole file unnecessarily — track the last event count and only process new lines.

### Proving the sandbox is real (critical for demo credibility)
Judges may assume the dashboard is a pre-baked animation. Two built-in proof points counter this without needing a second screen:
1. **Sandbox URL in top bar** — real `https://<id>.daytona.io` URL, visibly not localhost, updates between iterations
2. **Full URL in wire feed request line** — every HTTP request shows the real Daytona domain, not localhost

Optional (if time allows and screen real estate permits): open the Daytona web console in a split window during the demo — judges can watch the sandbox spin up and tear down live.

### Live evidence tab (fourth tab, alongside main feed)
A dedicated **"Live Proof"** tab that auto-fires a fixed HTTP request to the live sandbox URL at two moments:
- **Before the patch** (`iteration_start` or `attack_sent` event) — runs the same GET against Annie's note, shows the raw unchecked response
- **After the patch** (`verified` event) — runs the same request again, shows the 403 / error response

Displayed as a before/after side-by-side panel with timestamps. No human input required — entirely driven by the event stream. The audience watches the same curl-equivalent request return different responses as the patch lands.

**Implementation:** Python `requests` call from within the dashboard process, fired when the relevant event is received. The sandbox URL is pulled from the most recent `sandbox_ready` event. Not a real shell — just an HTTP client calling a hardcoded path (e.g. `GET /notes/1` with a pre-computed bob token) against the live URL.

**What this proves to the audience:**
- The sandbox URL is reachable by anyone, not just the orchestrator
- The patch actually changed the app's behaviour, not just the source code display
- Annie's data is real, the app is live, and the change happened exactly when the defender said it did

### Dashboard is a window, not a control plane
The dashboard is purely a visual layer for the demo — the agents run headlessly and autonomously with no human in the loop. The data pipeline is simple: the orchestrator writes newline-delimited JSON events to `events.json`, the dashboard polls and renders.

Any other consumer of that file would work equally well: a terminal tail, a Slack bot, a Grafana panel, a custom web UI. The dashboard is not the product — it is a presentation tool for the judges. Anyone watching the demo could swap it for their own consumer by simply reading `events.json` and reacting to events however they prefer. The Daytona sandbox just returns HTTP responses; the ai& API calls just return JSON. The orchestrator is the only thing that matters architecturally.

### Implementation (actual — July 2026)

**`dashboard/app.py`** — single-file Streamlit app (~290 lines).

Architecture: `read_new_events()` seeks to a byte cursor in `events.json`, reads new NDJSON lines, updates the cursor. `apply_event()` dispatches each event to `st.session_state` via a `match` block. `main()` polls at 80ms idle interval via `st.rerun()`, processes up to 50 events per cycle to stay responsive.

Key implementation decisions vs. spec:
- **Typewriter via cursor:** `narration_chunk` events are accumulated into `attacker_narration`/`defender_narration` strings in session state. Each `st.rerun()` replays the growing string — no `time.sleep` inside the render path.
- **Mutable default fix:** `init_state()` calls `.copy()` on list/dict defaults so each session gets a fresh object, preventing cross-run state leakage.
- **Strict-mode Playwright fix:** `st.tabs()` renders duplicate DOM elements; e2e tests use `.first` locators.
- **Live Evidence probes:** fired synchronously inside `render_live_evidence_tab()` when `_probe_before`/`_probe_after` flags are set by `apply_event()`. 5s timeout, never raises.
- **CSS:** injected via `st.html(_CSS)`, called unconditionally on every rerun (see "CSS injection fix" below for why the earlier once-per-session guard was removed).

**`dashboard/requirements.txt`**: `streamlit>=1.35.0`, `requests>=2.31.0`, `pygments>=2.17.0`

Verified:
- 18/18 unit tests pass (state dispatch, cursor advancement, probe error handling, full fixture replay → 3 history entries, final stage "verified")
- 12/12 Playwright e2e tests pass against live Streamlit server (page load, tab switching, event replay rendering)

### Visual remediation (actual — July 2026)

The HTML prototype (`Attack on Sandbox Dashboard - Standalone Claude Design.html`) is a self-executing Claude Artifact bundle — its real markup/CSS/JS is encoded inside `<script type="__bundler/template">`, not visible as plain HTML at a glance. Decoding it (extract the JSON string from that script tag) revealed a deliberate design system — warm parchment palette (`#f3f2f2` bg / `#201f1d` text / `#b68235` amber accent), Cormorant Garamond + Lora serif typography, a dark charcoal feed panel with typewriter-caret narration and staggered diff reveals — that had not made it into the initial Streamlit build, which shipped with generic default styling instead. This subsection documents the restyle that closed that gap, keeping the working polling/event architecture in place and only replacing the CSS/layout.

**Kept unchanged:** `read_new_events()`, `apply_event()`'s dispatch logic and `st.session_state` schema, `fire_live_probe()`, the underlying event contract from `orchestrator/events.py`.

**Changed:**
- **`_CSS`** — rewritten with the prototype's design tokens (`--color-bg`, `--color-accent`, etc.), a Google Fonts `@import` for Cormorant Garamond/Lora (simpler than self-hosting `woff2` files, since the prototype's self-hosting exists for artifact portability which doesn't apply here), and three of the prototype's four `@keyframes` (`livePulse`, `caretBlink`, `feedIn` — `typeClip` was skipped since the diff view stays Streamlit's native `st.code(diff, language="diff")`, which already has adequate red/green line coloring and can't easily host a per-character clip-path reveal). Semantic red/green (`#e53935`/`#43a047`) were kept as-is rather than swapped for the prototype's OKLCH figures — no functional gap existed there.
- **Layout** — replaced the `st.columns([2,2,2])` three-way split (code / wire / agent) with a single vertical feed (`render_feed()`), matching the prototype's one continuous scrollable panel: narration → wire (breach) → taunt → narration → diff → wire (verified), in event order. `render_status_bar()` was split into `render_nav_bar()` (brand, tagline, sandbox/model tag pills, Reset button) and `render_round_gallery()` (3 iteration cards — numeral + stage badge only, deliberately **not** the endpoint name, per the existing discovery-framing rule above; the prototype shows the endpoint upfront but that's a deviation kept intentional here).
- **Taunt lines** — previously absent from the dashboard entirely (the pre-scripted one-liners from the spec above existed only as prose in this document). Now rendered as `TAUNTS` dict + `_taunt_for(vuln_class)` + `_feed_taunt_block()`, appearing as a dashed-red-border italic line between the breach wire block and the defender's narration, exactly as originally specified.
- **New: Reset button** (`do_reset()` / `render_reset_button()`) — clears `events.json`, restores `target-app/app.py` via `git checkout`, deletes `target-app/notes.db`, and resets `st.session_state` back to defaults, so a demo run can be repeated without a manual terminal cleanup. File-level only — cannot stop a separately-running `orchestrator/main.py` process or its target-app subprocess, so the button is disabled unless `stage` is `idle` or `verified` (guards against resetting files out from under an in-flight run) and its help text tells the presenter to stop the orchestrator first.
- **Typewriter pacing** — `narration_chunk` events were previously processed up to `MAX_EVENTS_PER_CYCLE` (50) per rerun with no delay, so text visually jumped in large blocks rather than animating. `_process_events_this_cycle()` now caps narration_chunk processing at `MAX_NARRATION_CHARS_PER_CYCLE = 15` per cycle with a small `NARRATION_CHAR_DELAY_S` (10ms) sleep between chars, so the reveal is visible on screen across the run without duplicating the orchestrator's own 22ms/char pacing on the render side. A blinking `▌` caret (`aos-caret`, using the prototype's `caretBlink` keyframe) is appended to a narration card's quote while that agent's narration is still incomplete.
- **Branding fix** — the nav bar previously would have inherited the prototype's stale "Kimi K2 agents" tag (the project moved to ai&/deepseek-v4-flash before the dashboard was built, so this was never actually shipped, but is called out here since it's a trap for anyone copying the prototype's markup directly). `MODEL_TAG = "ai& · deepseek-v4-flash"` is now the canonical tag text.

**New file:** `dashboard/__init__.py` (empty) — added so `dashboard` is an importable package, matching `orchestrator/__init__.py`'s existing pattern; required for `dashboard/test_dashboard.py` to `from dashboard import app`.

Verified:
- 20/20 unit tests pass (`dashboard/test_dashboard.py`) — pure HTML-builder functions (`_taunt_for`, `_feed_narration_block`, `_feed_wire_block`, `_feed_taunt_block`, `_feed_divider`) tested directly with no Streamlit context; `do_reset()`/`render_reset_button()`/`apply_event()` regression tests run through Streamlit's `AppTest.from_string()` harness (a real `st.session_state` without invoking `main()`'s infinite polling loop, which `AppTest` can't drive directly since it never returns)
- Full repo suite (`orchestrator/` + `dashboard/`): 54/54 pass
- Live end-to-end: ran `python orchestrator/main.py` against the local target app (real 3-iteration run, `MOCK = True`), then drove `dashboard/app.py`'s render functions against the resulting real `events.json` via `AppTest` — zero exceptions, taunt lines confirmed present at the correct point in the timeline (e.g. "Thanks for the login…" visible immediately after iteration 1's `verified` event), "Breach confirmed" correctly shown mid-flight (right after `attack_sent`, before the patch lands) and replaced by "Exploit blocked — patch holds" once verified
- Also ran a real `streamlit run` server against the live `events.json` for several minutes with no exceptions in the server log
- **Gap (resolved — see "CSS injection fix" below):** Playwright MCP was not attached in this session (checked via ToolSearch — same limitation noted in the Phase 4 session); a real rendered-DOM/visual screenshot check was not possible at the time. `AppTest`-based verification (above) was a reasonable substitute for confirming render correctness and absence of exceptions, but did not confirm actual visual appearance (font loading, color rendering, animation smoothness) in a real browser — and in fact missed a real bug that only a live browser check could catch (below).

### CSS injection fix (July 2026)

A later live-browser check (once Playwright MCP was attached) found that the dashboard was actually rendering as **plain unstyled text** — no dark panel, no fonts, no badges — contradicting the clean `AppTest` result above. Root cause: `inject_css()` called `st.markdown(_CSS, unsafe_allow_html=True)` only once per session, gated behind `if "_css_injected" not in st.session_state`. `AppTest` never caught this because it only exercises a single script pass per test; it never exercises the dashboard's actual behavior of rerunning itself repeatedly via `st.rerun()` in its polling loop (`main()`, `POLL_INTERVAL_S = 0.08`). Under real repeated reruns, Streamlit's frontend element-tree reconciliation was dropping the once-emitted `<style>` markdown node — confirmed live via Playwright (`document.querySelectorAll('style')` showed the tag missing entirely from the DOM, not merely present-but-uncascaded).

**Fix:** `inject_css()` now calls `st.html(_CSS)` unconditionally on every rerun (no session-state guard). `st.html()` inserts as a true top-level DOM node rather than a scoped markdown fragment, and calling it every rerun means it can never be reconciled away. The same `st.markdown(..., unsafe_allow_html=True)` → `st.html(...)` swap was applied to every other purely-styling/structural HTML call in the file (`render_nav_bar`, `render_round_gallery`, `render_feed`, `render_history`, the inline HTTP-status spans in `render_live_evidence_tab`) for consistency, though only the CSS injection itself was actually broken by the once-per-session guard — the others were already re-emitted every rerun and rendered correctly before this fix too.

**Also investigated (no code change needed):** the same session separately reported old iteration state appearing to linger after clicking "Reset & Run" mid-run. Live Playwright testing across several repeated Reset & Run cycles found `do_reset()` (clears `events.json`, restores `target-app/app.py`, deletes `notes.db`, resets every `st.session_state` key including `history`) works correctly — `history` was observed growing correctly from empty on every fresh run, with no persisted stale entries. One single `browser_evaluate` read caught a transient 3-stale-entries reading that did not reproduce in any subsequent snapshot or screenshot; this is consistent with Streamlit patching `render_feed()`'s and `render_history()`'s DOM updates in separate frontend messages a few milliseconds apart during a rerun, not a `session_state` correctness bug. No fix was made here since nothing reproducible was found — if a future session reproduces a persistent (non-transient) version of this, capture a screenshot (not just one `evaluate()` read) to confirm before investigating further.

Verified (this fix):
- 68/68 tests pass (`orchestrator/` + `dashboard/` combined; `pytest -q` from repo root)
- Live Playwright verification against a real `streamlit run dashboard/app.py` server: confirmed `<style>` tag containing `_CSS` (searched for the `"Cormorant"` substring) present in the live DOM both on first load and after 300+ polling reruns mid-run; `getComputedStyle()` on `.aos-brand`/`.aos-feed` resolved to the custom fonts and dark panel background (`rgb(30, 30, 46)`), not Streamlit defaults; zero browser console errors/warnings
- Ran a full live 3-iteration demo end-to-end via the dashboard's own "Reset & Run" button (mock orchestrator, `MOCK = True`) and visually confirmed the dark panel, colored role badges, "Breach confirmed"/"Exploit blocked — patch holds" wire coloring, and diff add/del coloring all render correctly throughout
- Test/dev artifacts (screenshots, `.playwright-mcp/` snapshots, `events.json`, `notes.db`) cleaned up after verification; `target-app/app.py` restored to its committed vulnerable baseline via `git checkout`

### Running feed across all 3 iterations (July 2026)

Requested change: the feed previously showed only the *current* iteration's narration/wire/diff blocks, replacing them wholesale on the next `iteration_start`; a separate `render_history()` call below it only kept a one-line divider summary per completed iteration ("Iteration N complete — X"), discarding the full rendered content once an iteration ended. The ask was to keep every iteration's full content visible and stacked, clearing only on an explicit reset.

**Fix:** extracted the existing per-iteration block-building logic out of `render_feed()` into `_current_iteration_blocks()` (unchanged rendering logic — divider → attacker narration → wire → taunt → defender narration → diff → wire verified). At `iteration_complete`, `apply_event()` now calls `st.session_state.history.extend(_current_iteration_blocks())`, freezing that iteration's fully-rendered HTML blocks into `history` before the next `iteration_start` clears the live fields. `history` changed from a list of small summary dicts to a flat list of already-rendered HTML block strings. `render_feed()` now renders `list(st.session_state.history) + _current_iteration_blocks()` as one continuous `.aos-feed` — every completed iteration's full content, followed by the in-progress iteration's live content — so `render_history()` (the old one-line-per-iteration summary) became redundant and was removed along with its call site in `main()`.

**Bug caught during live verification, fixed same session:** the very last iteration of a run has no subsequent `iteration_start` to clear its live fields, so `_current_iteration_blocks()` kept re-rendering that iteration's content as "live" even after `iteration_complete` had already frozen the same blocks into `history` — producing a visible duplicate of the final iteration's divider and content. Fixed by adding a `_iteration_frozen` session-state flag: set `True` in `iteration_complete` right after the `history.extend(...)` snapshot, checked (and short-circuited on) at the top of `_current_iteration_blocks()`, and reset to `False` at the top of the next `iteration_start`. `do_reset()` clears it along with every other `_STATE_DEFAULTS` key.

Verified:
- 68/68 tests pass. `test_apply_event_full_iteration_reaches_verified_stage` (`dashboard/test_dashboard.py`) updated — it previously asserted `len(history) == 1` (one summary dict per completed iteration); now asserts the joined HTML in `history` contains the iteration's "complete" divider text and its defender narration, matching the new list-of-rendered-blocks representation.
- Live Playwright verification against a real `streamlit run` server across two full Reset & Run cycles: confirmed exactly 3 `.aos-divider-label` elements and 3 `.aos-diff` blocks after a completed 3-iteration run (no duplicate final-iteration render), all three iterations' full narration/wire/taunt/diff content simultaneously present in the DOM in order, and the feed fully clearing to just the new run's fresh content immediately after clicking "Reset & Run" a second time mid-demo.
- Test/dev artifacts cleaned up and `target-app/app.py` restored to baseline after verification, as before.

### Animation reference (from HTML prototype)
The prototype uses these patterns — replicate in Streamlit where possible:
- Character-by-character typewriter reveal for narration text (22ms/char)
- `feedIn` fade-in on each new block entering the feed
- Staggered diff line reveals (additions animate in, deletions appear instantly)
- Pulsing live indicator dot while events are actively arriving
- Auto-scroll feed to latest event

**Deferred (not implemented):** the prototype's play/pause/step-back/step-forward transport controls and progress-dot scrubber. These exist in the prototype because it has no live backend — scrubbing through a fixed 18-event script is its only way to demo itself. The real dashboard tails a live, indefinite event stream instead, so this affordance isn't needed for the hackathon demo. If the dashboard is ever reused as a standalone teaching/portfolio piece (i.e. replayed against a saved `events.json` after the fact rather than live), a scrubber would be the natural next addition — `st.session_state` would need to retain the full ordered event log (not just derived current-state fields) to support seeking to an arbitrary point in the past.

### Polish (cuttable if time runs out)
- Typewriter animation on narration text
- Auto-scroll the wire feed and reasoning panel to the latest event
- Animated stage label transition

---

## Phase 3A — Daytona Client ✅ COMPLETE

**Touches:** `orchestrator/daytona_client.py`, `orchestrator/load_daytona_env.py`, `orchestrator/requirements.txt`
**Depends on:** Phase 1 (target app must exist to deploy and test)
**Unlocks:** Phase 4

### Implementation notes
- SDK: `daytona-sdk==0.199.0` (PyPI package `daytona-sdk`, import `daytona_sdk`)
- Auth: JWT token + org ID from `~/.../daytona/config.json` — loaded by `load_daytona_env.inject_env()` into `DAYTONA_JWT_TOKEN` / `DAYTONA_ORGANIZATION_ID` before client init
- Sandboxes are created with `public=True` so preview URLs are accessible without Auth0 redirect
- Flask is launched via the session API with `run_async=True` (`SessionExecuteRequest`) to avoid the server-side command timeout that would fire on a long-running foreground process
- pip install is run as a separate synchronous exec with `timeout=300` (cold sandbox takes ~2 min); Flask start uses the session API
- SSL verification disabled for health checks only — `daytonaproxy01.net` wildcard cert doesn't chain on Windows Python by default
- Preview URL format: `https://5000-{sandbox_id}.daytonaproxy01.net`

### Verified (2026-07-18)
5/5 integration tests passed against a real Daytona sandbox:
1. Sandbox created, URL is a reachable https domain ✓
2. Flask app responds on root health endpoint ✓
3. SQLi payload returns 200 + token against live sandbox ✓
4. Patched file replaces running app after restart ✓ (SQLi blocked → 401)
5. Sandbox destroyed, URL no longer reachable ✓

### Goal
A self-contained Python wrapper aiteration the Daytona SDK that the orchestrator can call to manage the target app's sandbox lifecycle. The orchestrator should never import the Daytona SDK directly — all sandbox operations go through this module.

### Functions implemented
- `create_sandbox() -> str` — creates a new sandbox, returns its ID
- `deploy_app(sandbox_id: str, source_dir: str)` — uploads the contents of `target-app/` into the sandbox
- `start_app(sandbox_id: str)` — runs `pip install -r requirements.txt && python app.py` inside the sandbox as a backgiteration process
- `get_url(sandbox_id: str) -> str` — returns the public HTTP URL for the running Flask service
- `upload_file(sandbox_id: str, remote_path: str, content: str)` — writes a single file into the sandbox (used by the orchestrator to push a patched `app.py` without redeploying everything)
- `restart_app(sandbox_id: str)` — kills and restarts the Flask process after a patch is applied
- `delete_sandbox(sandbox_id: str)` — tears the sandbox down; always called in a `finally` block

### Testing approach
Deploy Phase 1's target app into a real Daytona sandbox and confirm:
1. `get_url()` returns a reachable URL
2. The SQLi exploit curl command works against the live sandbox URL
3. `upload_file()` + `restart_app()` successfully replaces the running source (simulate a patch by uploading a trivially modified `app.py`)
4. `delete_sandbox()` cleans up

This is the one place in the build where a real Daytona API call is made before Phase 5 — it's necessary to verify the wrapper works before wiring it into the orchestrator.

---

## Phase 3B — Agent Layer ✅ COMPLETE

**Touches:** `orchestrator/agents.py`, `orchestrator/test_agents.py`, `orchestrator/check_reliability.py`, `orchestrator/requirements.txt`
**Depends on:** Phase 2A (event schema only, for agent_reasoning field shape)
**Unlocks:** Phase 4

### Goal
All LLM interaction lives here. The orchestrator calls these functions and gets back structured Python dicts — it never constructs prompts or parses JSON itself. Developed and fully tested against hardcoded mock responses before any real ai& API call is made.

### ai& reliability test (do this before writing real prompts)
Write the smallest possible standalone script: one prompt asking `deepseek-ai/deepseek-v4-flash` to return a fixed JSON shape, run it 5–10 times, assert the output is parseable every time. If it fails more than once in ten, step up to `deepseek-ai/deepseek-v4-pro` on the same endpoint — same base URL, one model string change. This test informs what the retry wrapper needs to handle.

### JSON mode (guaranteed valid JSON output)
All agent calls use `response_format={"type": "json_object"}`. The model is guaranteed to return syntactically valid JSON — no regex extraction, no preamble stripping, no code-fence handling. The orchestrator calls `json.loads()` directly on `response.choices[0].message.content`.

```python
response = client.chat.completions.create(
    model="deepseek-ai/deepseek-v4-flash",
    messages=[...],
    response_format={"type": "json_object"},
)
result = json.loads(response.choices[0].message.content)
```

Include `stream_options={"include_usage": True}` on calls where token counts are needed for the status panel.

### Typewriter effect — simulated from parsed response
All agent calls are **non-streaming** (JSON mode + streaming are separate features; use JSON mode for reliability). The typewriter effect on the dashboard is produced by the orchestrator replaying the `narration` field character-by-character after parsing, writing incremental `narration_chunk` events — no live stream required.

```python
narration = result["agent_reasoning"]["narration"]
for char in narration:
    write_event({"type": "narration_chunk", "agent": agent, "char": char})
    time.sleep(0.022)  # 22ms/char matches the HTML prototype
```

**Summary of what the model returns vs what the dashboard sees:**
- `narration` → returned whole in JSON, replayed char-by-char as `narration_chunk` events
- `technical` → returned whole, written once to the event, rendered at once
- `patched_source` → returned whole, written to sandbox, diff computed locally
- `diff` → computed via `difflib`, rendered with staggered animation

### Functions to implement
- `attacker_agent(app_url: str, vulnerability_class: str, source_code: str, on_narration_chunk: callable) -> dict`
  Calls `deepseek-ai/deepseek-v4-flash` via ai& with JSON mode. Prompt includes the target URL, source code, and scoped instruction ("look specifically for `{vulnerability_class}` vulnerabilities only"). Parses response directly with `json.loads()`. Calls `on_narration_chunk(char)` for each character of the narration field after parsing. Returns complete dict. Expected shape: `{ method, url, headers, body, agent_reasoning: { narration, technical } }`. Narration voice: terse, first-person, present-tense, clinical and predatory.

- `defender_agent(request: dict, response: dict, source_code: str, on_narration_chunk: callable) -> dict`
  Same pattern. Prompt includes raw HTTP request, raw response, and current source code. **Vulnerability class is never named.** Returns: `{ patched_source, agent_reasoning: { narration, technical } }`. Narration voice: investigative, first-person, shows the discovery arc.

- Retry wrapper (max 1 re-attempt): only for network/5xx errors — JSON parse failures are eliminated by JSON mode.

### Mock mode
Both agent functions accept `mock=True` — bypasses ai& entirely, returns a hardcoded realistic response. `on_narration_chunk` is still called character by character to simulate the typewriter in mock mode. This is how Phase 4 is developed.

### Implementation (actual — July 2026)

**`orchestrator/agents.py`** — single-file module (~330 lines), two public functions (`attacker_agent`, `defender_agent`) plus private helpers for the client singleton, retry wrapper, prompt builders, and mock response tables.

Key implementation decisions vs. spec:
- **The 22ms/char sleep is NOT in `agents.py`.** `_replay_narration()` calls `on_narration_chunk(char)` back-to-back with no delay. The ROADMAP's inline snippet shows the sleep colocated with the write — in the real implementation that pacing belongs to whoever supplies the callback (Phase 4's `main.py`), since a real sleep inside the library function would make every test in `test_agents.py` take real wall-clock seconds. `agents.py` stays a pure "return a dict" module; `main.py` must wrap `write_event(make_narration_chunk(...))` with `time.sleep(0.022)` itself.
- **Client singleton pattern matches `daytona_client.py`** (built in parallel during this same phase): a module-level `_client` global, lazily constructed by `_get_client()`, reading `AIAND_API_KEY` / `AIAND_BASE_URL` / `AIAND_MODEL` from `os.environ` directly — no `python-dotenv` call inside the module itself, even though `python-dotenv` is now in `orchestrator/requirements.txt` for whatever loads the process environment upstream (shell export, or a future `main.py`/`setup.py` call).
- **Retry wrapper is narrow**: exactly one retry, only for `APIConnectionError`, `APITimeoutError`, or `APIStatusError` with `status_code >= 500`. 4xx and generic exceptions propagate immediately with no retry.
- **Defender prompt-builder (`_build_defender_prompt`) takes no `vulnerability_class` parameter at all** — structurally impossible to leak it into the prompt. Verified live: the defender's real narration derives the vuln purely from the request/response pair with no hint.
- **Defender scope discipline required a prompt tightening after live testing.** The first version of the system prompt ("fix ONLY that issue with the smallest correct change") was not restrictive enough — a live call against the real ai& API patched all three seeded vulnerabilities (SQLi, IDOR, missing-auth) at once, even though the request/response evidence only demonstrated the SQLi. Tightened to explicitly state the request/response pair is the *only* evidence and to not touch any other code path "even if it looks suspicious." Re-verified live post-fix: the defender now patches only the evidenced vulnerability and leaves unrelated endpoints untouched, for both the SQLi and IDOR iterations.
- **Mock mode content is lifted from `orchestrator/make_fixture.py`'s tone** (clinical/certain attacker, investigative/discovering defender) so mock-mode runs stay visually consistent with the dashboard fixture already used in Phase 2B rehearsal. Defender mock responses are chosen by pattern-matching the request URL fragment (`/login` → sqli reply, `/notes/` → idor reply, else → missing-auth reply), since mock mode has no ground-truth label and is always called immediately after the matching mock attacker response in practice.

**`orchestrator/check_reliability.py`** — standalone manual script (not part of pytest, not auto-run, makes real paid API calls). Runs 10 raw JSON-mode calls against a trivial fixed shape unrelated to the real security prompts, prints per-attempt pass/fail, exits nonzero if more than 1 failure. Run live during this phase: **10/10 passed** against `deepseek-ai/deepseek-v4-flash` — no need to escalate to `deepseek-v4-pro`.

**`orchestrator/requirements.txt`**: `daytona-sdk`, `openai>=1.30.0`, `python-dotenv` (the latter two entries were added by Phase 3A work happening in parallel; `agents.py` itself only requires `openai`).

Verified:
- 19/19 unit tests pass (`orchestrator/test_agents.py`), zero network calls, zero `AIAND_API_KEY` requirement — every real-path test patches `_get_client`
- Live smoke test against the real ai& API for both iterations (SQLi and IDOR): attacker produces a correct, executable exploit request with accurate technical reasoning; defender produces a correctly-scoped patch with accurate root-cause narration, verified by inspecting `patched_source` for exactly the expected endpoint change and no others
- `agent_reasoning` shape from both real-path outputs round-trips cleanly through `events.make_attack_sent()` / `events.make_patch_applied()` with no exception

**Known nuance for Phase 4/5 tuning (not a defect in `agents.py`):** in the live IDOR smoke test, the attacker authenticated as annie (the note owner) and requested her own note by ID — technically not a breach, since she owns it. `agents.py` faithfully relays whatever the model returns; if this recurs during Phase 4/5 rehearsal, tighten the attacker's user-prompt to explicitly supply Bob's credentials/token as the starting foothold rather than leaving credential choice to the model.

---

## Phase 4 — Orchestrator ✅ COMPLETE

**Touches:** `orchestrator/main.py`
**Depends on:** Phase 3A + Phase 3B (both complete)
**Unlocks:** Phase 5

### Goal
The director. Implements the fixed two-iteration sequence as a straight Python script. At this stage it runs with `mock=True` on both agent functions and points at a locally-running target app (not Daytona) — the goal is to confirm the full control flow, event writing, and iteration transitions are correct before introducing any live external dependency.

### Iteration sequence (implemented for both iterations)
```
for each iteration in [sqli, idor]:
    1.  write iteration_start event
    2.  write agent_thinking event (agent="attacker", label="Scanning for vulnerabilities...")
    3.  call attacker_agent(url, vulnerability_class, source) → exploit_request
    4.  send exploit_request as a real HTTP request to the target
    5.  write attack_sent event (request + response + agent_reasoning)
    6.  write agent_thinking event (agent="defender", label="Analysing the breach...")
    7.  call defender_agent(request, response, source) → patch  [no vulnerability class named]
    8.  compute diff between old source and patched_source via difflib
    9.  write patched source to target-app/app.py (locally for now)
   10.  restart the local Flask process
   11.  write patch_applied event (diff + patched_source + agent_reasoning)
   12.  replay the exact original exploit_request against the restarted service
   13.  write verified event (request + response + exploit_blocked bool)
   14.  write iteration_complete event
```

### What "locally" means here
The orchestrator runs the target app as a subprocess (`subprocess.Popen`) for Phase 4 testing. Restarting means killing and re-spawning the subprocess. Phase 5 replaces this with Daytona calls.

### Iteration 3 (stretch)
The iteration sequence is defined as `[sqli, idor]` for the core build. Iteration 3 (`missing_auth`) is a list entry that's conditionally included — gated by a config flag so it's easy to enable once the two-iteration loop is solid. The iteration sequence and event schema already support it (see Phase 2A).

### Verification gate
With mocks active and the local target app running, execute the full two-iteration sequence and confirm: all events are written to `events.json` in the correct order, the diff in `patch_applied` is non-empty, `exploit_blocked` is set correctly in `verified`, `agent_reasoning` contains both `narration` and `technical` subfields in every agent event, and the dashboard (Phase 2B) renders the full run correctly when pointed at the resulting `events.json`.

### Implementation (actual — July 2026)

**`orchestrator/main.py`** — single-file director (~230 lines). Iteration list is `["sqli", "idor"]` plus `"missing_auth"` appended when `RUN_STRETCH = True` (module-level constant) — all three iterations, including the stretch goal, run by default. `MOCK = True` for this phase; Phase 5 flips it.

Key functions: `reset_events_log()` / `reset_target_db()` (delete `events.json` / `notes.db` before each run — a fresh replay and fresh seed every time); `start_target_app()` / `stop_target_app()` / `restart_target_app()` (subprocess lifecycle — re-running `app.py` also re-seeds the DB via its existing `init_db()` call, so a process restart resets source *and* data in one step, no separate DB-reset call needed); `send_request()` (resolves a relative exploit URL like `/login` against `http://localhost:5000`, since mock attacker responses return paths, not full URLs; real-mode full URLs pass through untouched); `apply_patch()` (writes `patched_source`, returns a `difflib.unified_diff` against the prior contents — diff is always orchestrator-computed, never trusted from the model, per spec); `run_iteration()` (the 14-step sequence verbatim); `main()` (wraps the loop in `try/finally` so `stop_target_app()` always fires, even mid-iteration exceptions).

**Bug found and fixed during Phase 4's first live run:** the Phase 3B mock defender data (`agents.py`'s `_MOCK_DEFENDER_BY_URL_FRAGMENT` / `_MOCK_DEFENDER_DEFAULT`) stored `patched_source` as a bare route-handler fragment (e.g. just the `@app.post("/login")` function), not a full-file replacement — a mismatch against the real API's documented contract ("the FULL replacement contents of the source file"). `test_agents.py`'s shape-only assertions (`isinstance(..., str) and result`) never caught this, since a fragment is still a non-empty string. Writing that fragment as the entire `app.py` broke the app on restart (`NameError: name 'app' is not defined`), which only surfaced once Phase 4 actually restarted the subprocess against the written file.

**Fix:** `agents.py` now stores each mock scenario as an `_original_handler` / `_patched_handler` pair (the exact route-handler text, before and after) and a new `_patch_handler(source_code, original, patched)` helper substitutes the patched handler into whatever full source is passed in, string-replace style — falling back to returning `source_code` unchanged if the original handler text isn't found (keeps mock mode robust to a caller passing arbitrary/placeholder source in tests). `_mock_defender_response()` now takes `source_code` as a third argument and returns a real full-file `patched_source`. Regression tests added: `test_defender_agent_mock_patched_source_is_full_file_not_a_fragment` and `test_defender_agent_mock_idor_patch_preserves_rest_of_file` in `test_agents.py`, both asserting the patched output `compile()`s as valid Python and contains all the *other* route handlers untouched — exactly the gap the original bug slipped through.

**`orchestrator/test_main.py`** — 13 unit tests, all mocking `send_request`/subprocess boundaries (no real network, no real process spawned, no `AIAND_API_KEY` needed): `apply_patch` diff correctness (non-empty on change, empty when unchanged), `send_request` URL resolution (relative → joined with base, absolute → untouched, non-JSON response → falls back to `.text`), `reset_events_log`/`reset_target_db` file-removal semantics, full 9-event-type ordering assertion for one `run_iteration` call (using the real `target-app/app.py` source, not a placeholder, so the mock patch substitution has something real to match against), `exploit_blocked` true/false branching on verify-response status, and `main()`'s `finally`-block subprocess cleanup on both a clean run and one where `run_iteration` raises.

Verified:
- 34/34 unit tests pass across `orchestrator/test_agents.py` + `orchestrator/test_main.py`
- 2 consecutive live end-to-end runs (`python orchestrator/main.py`) against the real local target app, mock agents: all 3 iterations (sqli, idor, missing_auth) completed with `exploit_blocked: true` and a non-empty diff every time; `target-app/app.py` on disk after a run contains all three patches cumulatively (parameterised login query, ownership check on `GET /notes/<id>`, admin-role check on `POST /reset`) and is valid, importable Python
- Port 5000 confirmed free and no orphaned `python.exe` process after both runs (subprocess cleanup via `finally` verified under normal exit)
- Dashboard (`streamlit run dashboard/app.py`) started clean against the real orchestrator-produced `events.json` (797 events for a 3-iteration run: 776 `narration_chunk`, 6 `agent_thinking`, 3 each of the remaining 7 types) — server log showed no exceptions while polling; full interactive Playwright verification was not possible this session (the Playwright MCP server is configured in `~/.claude/settings.json` but wasn't attached to the session — needs a VS Code restart to activate per existing project memory), so this is HTTP/log-level confirmation only, not a rendered-DOM check

**Known scope note:** the mock IDOR scenario only exercises `GET /notes/<id>` (VULN-2a); the mock defender patch therefore leaves `PUT /notes/<id>` (VULN-2b) unpatched. This matches the mock attacker table's existing scope (`_MOCK_ATTACKER["idor"]` only ever requests a GET) and isn't a Phase 4 regression — flagged here in case Phase 5's real (non-mock) agent calls behave differently, since the real defender prompt has previously over-patched during Phase 3B testing (see Phase 3B's "Known nuance" note) and could plausibly patch both routes from one piece of evidence.

---

## Phase 5 — Live Integration ✅ COMPLETE (wiring + tests; live sandbox run pending)

**Touches:** `.env`, `orchestrator/main.py` (swap mock flags), `orchestrator/agents.py` (ai& endpoint wired), `orchestrator/daytona_client.py` (confirmed working from Phase 3A)
**Depends on:** Phase 4 (full mock run confirmed working)
**Unlocks:** Phase 6

### Goal
Replace the two stubs with real external calls, in a controlled order. The rest of the codebase doesn't change — this phase is purely about swapping the mock seam for the real thing.

### Step 1 — ai& integration
- Wire `AIAND_API_KEY` from `.env` into `agents.py`; client init is:
  ```python
  from openai import OpenAI
  client = OpenAI(base_url="https://api.aiand.com/v1", api_key=os.environ["AIAND_API_KEY"])
  ```
  Model string: `"deepseek-ai/deepseek-v4-flash"`
- Run the attacker agent once against the locally-running target app (not Daytona yet) for the SQLi iteration
- Inspect the raw model output, confirm `parse_model_json` handles it, confirm the returned request dict is sensible
- If the first real call produces a nonsensical exploit request, tune the prompt and re-run (max 2 tune cycles before stepping up to `deepseek-ai/deepseek-v4-pro` on the same endpoint)
- Do the same for the defender agent
- Once both agents produce reliable output on the local target, proceed to Step 2

### Step 2 — Daytona integration
- Replace the `subprocess.Popen` local-app management in `main.py` with calls to `daytona_client.py`
- Run the full two-iteration sequence against a live Daytona sandbox with real ai& API calls
- Confirm the sandbox URL is reachable, exploits land, patches deploy, restarts work, `verified` events show `exploit_blocked: true`
- Wrap the entire orchestrator run in `try/finally` to ensure `delete_sandbox()` always fires

### Pre-warm setup script (`orchestrator/setup.py`)
Sandbox creation + app deployment takes 10–30 seconds. Running this inside `main.py` creates dead air at the very start of the demo. Instead, extract it into a standalone `setup.py`:

```
python orchestrator/setup.py   # run during your verbal intro — prints sandbox URL, writes sandbox_ready event
python orchestrator/main.py    # iteration loop starts immediately, sandbox already live
```

`setup.py` responsibilities:
- Creates the Daytona sandbox
- Deploys and starts the target app
- Polls until the Flask `/` health check responds
- Writes a `sandbox_ready` event to `events.json` with the live sandbox URL
- Prints the URL to the terminal

The dashboard shows the URL the moment `sandbox_ready` lands. By the time you finish your 30-second intro and say *"let's start"*, the sandbox is warm and `main.py` fires the first iteration immediately with no delay.

### Credit discipline
- Step 1: at most 4 real ai& API calls total (1 attacker + 1 defender per iteration × 2 iterations)
- Step 2: 1 full end-to-end run — inspect everything, fix any issues, then treat the next run as a rehearsal (Phase 6)
- Do not iterate on live infra; fix issues against mocks and re-run once

### Implementation (actual — July 2026)

**One deliberate deviation from the plan above:** ai& API calls are now real
**streaming** calls (`stream=True` + `stream_options={"include_usage": True}`),
not the originally-planned non-streaming JSON-mode call with a simulated
post-parse replay. Confirmed via `docs.aiand.com` that `response_format:
{"type": "json_object"}` and `stream: true` compose freely — JSON mode only
constrains the *final* assembled content to be valid JSON; streaming just
delivers that content incrementally as `delta.content` text fragments,
terminated by the OpenAI-shape `[DONE]` marker. There is no such thing as a
"streamed structured field," only a streamed raw JSON string, unparseable
until the buffer is complete. Design: raw text deltas are pushed live as a
new `stream_chunk` event so the dashboard shows real token-by-token movement
from the first byte; once the stream ends, `agents.py` parses the fully
assembled buffer exactly as before and the existing narration/wire-feed
rendering takes over unchanged — the raw-stream view is simply replaced.
This also unlocks real per-call token usage (`llm_usage` event), which
nothing tracked before (the ROADMAP's originally-speced Calls/Tokens/Latency
sidebar panel was never actually built in the real Phase 2B implementation —
this phase adds a lightweight nav-bar counter instead, not that panel).

**`orchestrator/events.py`** — two additive event constructors:
`make_stream_chunk(agent, chunk, iteration, vulnerability_class)` (one per
raw SSE text fragment; unlike `narration_chunk`, `chunk` length is
unconstrained since real deltas arrive in arbitrary-sized pieces) and
`make_llm_usage(agent, prompt_tokens, completion_tokens, total_tokens,
iteration, vulnerability_class)` (one per real model call, written once the
stream completes).

**`orchestrator/agents.py`** — `_call_model` (non-streaming) replaced by
`_call_model_streaming(messages, on_raw_chunk) -> (parsed_dict, usage_dict)`:
opens the stream, forwards each non-empty `delta.content` to `on_raw_chunk`
as it arrives, captures `usage` off the trailer chunk, and
`json.loads()`s the assembled buffer once the stream ends. The one-retry-on-
network/5xx policy from Phase 3B is unchanged, now wrapping the streaming
call. `attacker_agent`/`defender_agent` gained an optional `on_raw_chunk`
parameter and now return `(result, usage)` instead of a bare dict — mock
mode ignores `on_raw_chunk` entirely (there's no real stream to replay) and
always returns `usage=None`, so `main.py` skips emitting `llm_usage` in mock
runs. The existing `_replay_narration` char-by-char callback is unchanged
and still runs in both modes once the (real or mock) response is available
— narration pacing was never coupled to the network call.

**`orchestrator/daytona_client.py`** — one addition,
`get_sandbox_info(sandbox_id) -> {region, created_at, cpu, memory}`, reading
directly off the SDK's `Sandbox` object (`sandbox.target` is Daytona's
internal name for what the dashboard shows as "region"; confirmed by
inspecting the installed `daytona_sdk` package rather than guessing field
names). Feeds the `sandbox_ready` event's payload, which Phase 3A's
integration tests never needed since they didn't touch the dashboard-facing
event.

**`orchestrator/main.py`** — now loads `.env` via `python-dotenv` (dead
weight since Phase 3B's `requirements.txt` entry — nothing ever called
`load_dotenv()` before this) and injects Daytona credentials via
`load_daytona_env.inject_env()` before any `daytona_client` import. `MOCK`
flipped `True` → `False`. Rather than deleting the local-subprocess path,
`main()` now branches on `MOCK`: mock mode still runs the target app as a
local subprocess exactly as in Phase 4 (kept deliberately, so local
dev/testing stays free and fast — see credit discipline above), real mode
runs it in a live Daytona sandbox. `run_iteration()` takes a `target` dict
(`{"mode": "local"|"daytona", ...}`) instead of a bare subprocess handle, so
the two backends share one code path for the attack/patch/verify sequence.
New `start_sandbox()` / `stop_sandbox()` wrap sandbox lifecycle and honor
`orchestrator/.sandbox_id` (see setup.py below) so a pre-warmed sandbox is
reused instead of creating a second one — cleared on teardown. New
`make_raw_chunk_callback()` mirrors `make_narration_callback()`'s shape but
emits `stream_chunk` with no artificial delay (real network pacing already
paces it). `run_iteration()` emits `llm_usage` after each real call when
usage is non-`None`.

**`orchestrator/setup.py`** (new file) — thin pre-warm script per the plan
above: creates/deploys/starts the sandbox via `start_sandbox()`, writes its
ID to `orchestrator/.sandbox_id`, prints the URL. Lets sandbox spin-up
happen during the presenter's verbal intro instead of as dead air after
"let's start" — `main.py` picks up the same sandbox via the persisted ID
file instead of creating a second one.

**`dashboard/app.py`** — `apply_event()` gained two branches: `stream_chunk`
appends to `attacker_raw_stream`/`defender_raw_stream` session-state buffers
(hot path, same treatment as `narration_chunk`); `llm_usage` increments
`llm_calls`/sums `llm_tokens`. New `_feed_raw_stream_block(agent, raw_text)`
renders the in-progress raw JSON text with a blinking caret, reusing the
existing `.aos-technical` monospace CSS class (no new styles needed) —
shown only while that agent is active and its raw buffer is non-empty *and*
its clean narration hasn't landed yet, so the raw block and the narration
card never render simultaneously (verified live: the raw block is fully
replaced by the narration card the instant the parsed response arrives, not
merely covered by an empty duplicate card). `render_nav_bar()` shows a
`"{calls} calls · {tokens:,} tokens"` line next to the existing model tag,
suppressed entirely while `llm_calls == 0` so it doesn't clutter the
pre-run empty state.

Verified:
- 92/92 unit tests pass across the full repo (`orchestrator/` + `dashboard/`
  combined), zero real network/API/sandbox calls — every real-path test
  mocks the client boundary at the same seam Phase 3A/3B established. Order-
  independence re-confirmed after fixing a test-isolation bug where
  `monkeypatch.setitem(sys.modules, ...)` alone didn't cover
  `orchestrator.daytona_client` once some other test had already imported it
  as a real submodule (Python also caches it as an attribute on the
  `orchestrator` package object) — fixed by patching both.
- `pyflakes` clean across every new/modified source and test file
- 1 live mock-mode end-to-end run (`MOCK` overridden to `True` without
  touching the file) via `python -c "..."`, confirming Phase 5's rewrite of
  `main.py` didn't regress the Phase 4 control flow: all 3 iterations
  completed, 797 events (identical count to Phase 4's documented baseline),
  zero `stream_chunk`/`llm_usage` events (correctly absent in mock mode),
  all three `verified.exploit_blocked == true`. Port 5000 confirmed free and
  no orphaned process afterward; `target-app/app.py` restored via
  `git checkout` post-run.
- Live Playwright verification against a real `streamlit run` server:
  loaded the empty-state dashboard (no calls/tokens line, as designed at
  `llm_calls == 0`), then hand-injected a realistic `stream_chunk` +
  `llm_usage` sequence directly into `events.json` (the same shape a real
  ai& streaming call produces) — confirmed the raw JSON text streamed into
  the attacker's card live with a blinking caret, the nav bar's "1 calls ·
  908 tokens" line appeared, and the iteration card advanced to SCANNING.
  Followed with a real `attack_sent` event and confirmed the raw-stream
  block was fully replaced by the clean italic narration card, technical
  detail, and red "Breach confirmed" wire block — zero console
  errors/warnings throughout. Server process and all test artifacts
  (`events.json`, `.playwright-mcp/` screenshots) cleaned up after
  verification.
- **Not yet done this session (deliberately, per credit discipline):** a
  real end-to-end run against a live Daytona sandbox with real ai& streaming
  calls. Everything up to that boundary is now proven with mocks; the first
  real run should be treated as the single Step 2 run the credit-discipline
  section above budgets for, not a debugging loop.

---

## Phase 6 — Rehearsal and Polish

**Touches:** minor dashboard tweaks, `README.md`
**Depends on:** Phase 5 + Phase 2B (both complete)

### Goal
Confirm the demo is reliable, timed, and has a video backup. Everything before this phase was building; this phase is proving.

### Steps
1. Full end-to-end run, timed. Target: under 2 minutes for the two-iteration loop
2. Record video on the first clean pass — this is the insurance policy
3. Second full run immediately after, confirming repeatability
4. Fix any visual stutter in the dashboard (increase poll interval, use `st.empty()` placeholders)
5. Confirm the demo works from a cold start: `events.json` cleared, both processes launched fresh
6. Write `README.md` with exact launch commands for demo day

### Cuttable polish
- Dashboard animation on stage transitions
- Auto-scroll wire feed
- "LIVE" badge
- Nosana stretch integration (only if all the above is done with time remaining)

### Streaming UX fix (post-Phase-5, July 2026) ✅ COMPLETE

Four issues surfaced after the first live run with real ai& API calls and were fixed in `dashboard/app.py` only (no orchestrator changes):

**Fix 1 — Raw JSON hidden.** `stream_chunk` events were displayed live as a scrolling JSON token stream while the model was generating. In practice deepseek emits JSON field-by-field so the audience saw garbage (e.g. `{"method": "POST", "url": ...`) for 10–30 seconds before the clean narration replaced it. Fix: `apply_event()` still consumes `stream_chunk` at the hot-path rate (so cursor mechanics are unchanged) but no longer accumulates into `attacker_raw_stream`/`defender_raw_stream` buffers — those state fields were removed entirely. `_feed_raw_stream_block()` was deleted. The live-timer block (real JS wall-clock, ticks between reruns) already proves liveness without showing garbage.

**Fix 2 — Smooth auto-scroll.** The feed's `scrollIntoView` was using `behavior: "auto"`, causing the viewport to snap hard on every 250ms rerun. Changed to `behavior: "smooth"`.

**Fix 3 — Gallery badge flashing.** Round gallery cards called `st.html()` on every rerun even when the stage hadn't changed, causing visible DOM replacement flicker during typewriter cycles. Added `_gallery_stage_cache` dict to session state; each card only re-emits HTML when its `f"{stage}:{active}"` cache key changes. Unchanged cards use `st.empty()` to hold the column position.

**Fix 4 — Rerun pacing.** `_process_events_this_cycle()` now returns `(remaining, had_structural_event)`. `main()` only calls `st.rerun()` immediately when a structural event (anything other than `narration_chunk`/`stream_chunk`) landed; narration-only cycles sleep `POLL_INTERVAL_S` (raised from 80ms → 250ms) before rerunning. This means the typewriter accumulates 15 chars per 250ms frame instead of triggering a full feed DOM replacement for every single character.

**Also fixed:** `target-app/app.py` had been accidentally committed in a partially-patched state (`5efd4b6 add demo (bad)`). The vulnerable baseline from `c2370fb` was restored — the `_ORIGINAL_*` handler strings in `agents.py`'s mock data must match the file exactly for `_patch_handler()` to do the string substitution that makes mock-mode patching work. Running `git checkout -- target-app/app.py` after each demo run is the correct reset procedure (also what `do_reset()` does).

**Verified:** 111/111 tests pass. Live Playwright e2e confirmed: live-timer shows while agent is active → silently swallows all stream_chunk events (zero raw JSON ever visible) → narration typewriter replaces timer → full iteration renders (attacker narration, breach wire, taunt, defender narration, diff, exploit-blocked wire) with no flashing or DOM thrash.
