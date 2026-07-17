# Attack on Sandbox — Implementation Roadmap

## Final Outcome

Two processes running simultaneously on one machine at demo time:

**Process 1 — Orchestrator** (`python orchestrator/main.py`)
Runs the full adversarial loop autonomously with zero human input after launch:
- Iteration 1: Attacker agent receives the target app URL and a scoped prompt ("look for SQL injection only"). It reasons about the app, constructs a payload, and returns a JSON object describing an HTTP request. The orchestrator fires that request for real, captures the real response, writes an `attack_sent` event, and passes the request/response pair + current source to the defender. Defender returns a JSON object with the full patched file contents. Orchestrator writes the patch, redeploys into the Daytona sandbox, restarts the service, then replays the exact original exploit request. The re-verification result is written as a `verified` event.
- Iteration 2: Same loop, scoped to IDOR/broken auth.
- All HTTP traffic is real. All Kimi API calls are real. The sandbox is torn down and respun between iterations.

**Process 2 — Dashboard** (`streamlit run dashboard/app.py`)
Polls `events.json` on an interval and renders four zones live:
- Iteration tracker showing current iteration + stage (Vulnerable → Breached → Patched → Verified)
- Code panel showing current source with relevant lines highlighted, flipping to a diff view the moment a patch lands
- Wire feed showing the actual HTTP request and raw response, styled red for breaches, green for blocked attempts
- Agent reasoning panel showing short-form summaries of what each agent decided and why

**Backup:** a recorded video of a complete clean run exists before the live demo. If Daytona or Kimi goes down on stage, the video plays instead.

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

## Phase 2A — Event System

**Touches:** `orchestrator/events.py`, `events.json` (fixture file)
**Depends on:** nothing
**Unlocks:** Phase 2B, Phase 3B

### Goal
Define the single shared data contract that connects the orchestrator to the dashboard. Every observable state change in the system is represented as a structured event appended to `events.json`. Getting this schema right early prevents rework in both the orchestrator and dashboard later.

### Event schema
Each event is one JSON object per line (newline-delimited JSON), with at minimum:
- `type` — one of: `sandbox_ready`, `iteration_start`, `agent_thinking`, `narration_chunk`, `attack_sent`, `patch_applied`, `verified`, `iteration_complete`
- `timestamp` — ISO 8601
- `iteration` — integer (1, 2, or 3)
- `vulnerability_class` — `"sqli"`, `"idor"`, or `"missing_auth"`
- `payload` — object whose shape varies by event type (see below)

Event-specific payload shapes:
- `sandbox_ready`: `{ sandbox_id: string, url: string, region: string, created_at: string, spec: {cpu, memory} }` — written by `setup.py` once the Flask health check responds. Dashboard displays live URL and metadata in the status panel. On subsequent iterations (redeploy), a new `sandbox_ready` event is written with the same sandbox ID but a fresh `created_at` timestamp.
- `sandbox_destroyed`: `{ sandbox_id: string, iteration: int, vulnerability_class: string }` — written when the sandbox is torn down (end of run or between full resets). Dashboard moves this entry to the sandbox history log.
- `narration_chunk`: `{ agent: "attacker" | "defender", char: string }` — one event per character of the narration field, written as tokens stream in. Dashboard appends each char to the active pending card for the typewriter effect. Replaced by the full `attack_sent` or `patch_applied` event on completion.
- `agent_thinking`: `{ agent: "attacker" | "defender", label: string }` — written synchronously by the orchestrator immediately before the streaming Kimi call begins. No model output. `label` is a static string: `"Scanning for vulnerabilities..."` or `"Analysing the breach..."`. Cost: zero extra API calls.
- `attack_sent`: `{ request: {method, url, headers, body}, response: {status, body}, agent_reasoning: {narration: string, technical: string} }`
- `patch_applied`: `{ diff: string, patched_source: string, agent_reasoning: {narration: string, technical: string} }` — diff computed by the orchestrator via `difflib`, not taken from the model
- `verified`: `{ request: {…}, response: {…}, exploit_blocked: boolean }`

**`agent_reasoning` is always a two-field object, never a plain string:**
- `narration` — terse, first-person present-tense inner monologue written by the model, prompted into a dramatic voice. Attacker is clinical and predatory; defender is methodical. This is what the audience reads on the big panel.
- `technical` — the model's actual reasoning about vulnerability class, payload choice, and patch rationale. Displayed in a smaller monospace block beneath the narration for judges who want depth.

Both fields are returned verbatim from the model — no post-processing by the orchestrator. The prompt instructs the model to write `narration` in this specific style as part of the JSON shape it returns.

### Fixture file
Hand-craft a complete `events.json` covering all three iterations in sequence — including `agent_thinking` events immediately before each `attack_sent` and `patch_applied`, so the dashboard's pending state and replacement behaviour can be developed and tested against the fixture before the real orchestrator exists. Payloads should be realistic-looking (but fake) and include both `narration` and `technical` subfields on all agent reasoning events.

---

## Phase 2B — Dashboard

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
  DAYTONA SANDBOX                    KIMI
  ID:      sbox-c7d2e1               Model:   kimi-k2.6
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

  Kimi column fields (tracked by orchestrator, written to events):
  - `Model` — model name from API response
  - `Calls` — running count of Kimi API calls made this session
  - `Tokens` — cumulative token count from `usage` field in streaming response
  - `Latency` — rolling average time from `agent_thinking` to corresponding `attack_sent`/`patch_applied`

  Previous sandboxes log: populated from `sandbox_destroyed` events. Shows ID, which iteration it served, vulnerability class, and destruction timestamp. Proves sandboxes are being created and torn down, not one persistent server.
- **Left panel — Code view:** display the current `target-app/app.py` source. When a `patch_applied` event arrives, switch to a diff view (additions in green, removals in red) computed from the event's `diff` field. Use `st.code()` with syntax highlighting.
- **Centre panel — Wire feed:** for each `attack_sent` and `verified` event, show the full HTTP request including the **real Daytona sandbox URL** in the request line (e.g. `POST https://abc123.daytona.io/login`) — not a localhost URL. This is the second proof point that traffic is hitting a real remote sandbox. Style the block red if `exploit_blocked == false` (breach succeeded), green if `exploit_blocked == true` (patch held).
- **Right panel — Agent reasoning:** for each agent action, show a compact card with:
  - Agent role label (Attacker / Defender) and event type as a header
  - When an `agent_thinking` event arrives: render an animated pending card with the `label` field and a pulsing indicator. This card is replaced — not appended — when the corresponding `attack_sent` or `patch_applied` event arrives.
  - `narration` text large and readable — this is what the audience watches. The two voices are deliberately asymmetric: the attacker's narration is certain and clinical (it knew what it was doing); the defender's narration is investigative, building from the evidence (it had to figure it out). This asymmetry is the dramatic core of the demo.
  - `technical` text below in a small `st.code()` monospace block — for judges who want the full reasoning trail
  - **Attacker taunt:** a short pre-scripted one-liner rendered as a distinct visual beat between the breach wire feed and the defender card (dashed left border, italic). This is authored by you, not generated by Kimi — it is pure theatre. The defender never sees it; it receives only request + response + source. Examples: *"Thanks for the login — didn't even need a password."*, *"Appreciate Annie's notes — didn't need to be her to read them."*, *"Reset's done — nobody even asked who I was."*
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

Any other consumer of that file would work equally well: a terminal tail, a Slack bot, a Grafana panel, a custom web UI. The dashboard is not the product — it is a presentation tool for the judges. Anyone watching the demo could swap it for their own consumer by simply reading `events.json` and reacting to events however they prefer. The Daytona sandbox just returns HTTP responses; the Kimi calls just return JSON. The orchestrator is the only thing that matters architecturally.

### Animation reference (from HTML prototype)
The prototype uses these patterns — replicate in Streamlit where possible:
- Character-by-character typewriter reveal for narration text (22ms/char)
- `feedIn` fade-in on each new block entering the feed
- Staggered diff line reveals (additions animate in, deletions appear instantly)
- Pulsing live indicator dot while events are actively arriving
- Auto-scroll feed to latest event

### Polish (cuttable if time runs out)
- Typewriter animation on narration text
- Auto-scroll the wire feed and reasoning panel to the latest event
- Animated stage label transition

---

## Phase 3A — Daytona Client

**Touches:** `orchestrator/daytona_client.py`
**Depends on:** Phase 1 (target app must exist to deploy and test)
**Unlocks:** Phase 4

### Goal
A self-contained Python wrapper aiteration the Daytona SDK that the orchestrator can call to manage the target app's sandbox lifecycle. The orchestrator should never import the Daytona SDK directly — all sandbox operations go through this module.

### Functions to implement
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

## Phase 3B — Agent Layer

**Touches:** `orchestrator/agents.py`
**Depends on:** Phase 2A (event schema only, for agent_reasoning field shape)
**Unlocks:** Phase 4

### Goal
All LLM interaction lives here. The orchestrator calls these functions and gets back structured Python dicts — it never constructs prompts or parses JSON itself. Developed and fully tested against hardcoded mock responses before any real Kimi API call is made.

### Kimi reliability test (do this before writing real prompts)
Write the smallest possible standalone script: one prompt asking the Kimi model to return a fixed JSON shape, run it 5–10 times, assert the output is parseable every time. If it fails more than once in ten, evaluate the Groq fallback before investing time in prompt engineering. This test informs what the retry wrapper needs to handle.

### Streaming (confirmed supported)
Kimi uses the OpenAI-compatible interface — `stream=True` with `base_url="https://api.moonshot.ai/v1"`. Tokens arrive as SSE chunks via `chunk.choices[0].delta.content`. Streaming is used for the **narration field only** — to drive the typewriter effect on the dashboard without waiting for the full response.

**Preamble problem and fix:** Kimi often prefixes responses with *"Sure, here's the JSON:"* or similar. Never pipe raw token stream directly to the dashboard. Instead:
- Accumulate tokens in an internal buffer (never shown)
- Watch for the opening `{` of the JSON object
- Once found, begin extracting `narration` content character by character and writing incremental `narration_chunk` events to `events.json` for the dashboard to render as a typewriter
- Discard everything before `{` silently
- Prompt ends with *"Respond with only the JSON object, no other text, starting with `{`"* to minimise preamble (belt-and-suspenders with the buffer approach)

**Patch/diff display — do NOT stream, pass whole:**
The `patched_source` field must be complete before anything can happen with it (file write to sandbox, diff computation, process restart). Buffer the full response, parse JSON on `[DONE]`, then act. The dashboard renders the diff with staggered CSS animation per line (additions fade in sequentially, deletions appear instantly) — the reveal feel comes from animation, not streaming.

**Summary of what streams vs what's passed:**
- `narration` → streamed typewriter via incremental `narration_chunk` events
- `technical` → passed whole after `[DONE]`, rendered at once
- `patched_source` → passed whole after `[DONE]`, never streamed
- `diff` → computed locally from `patched_source`, rendered with staggered animation

### Functions to implement
- `attacker_agent(app_url: str, vulnerability_class: str, source_code: str, on_narration_chunk: callable) -> dict`
  Prompts Kimi with: the target URL, the source code, and a scoped instruction ("look specifically for `{vulnerability_class}` vulnerabilities only — do not look for other vulnerability types"). Streams response, discards preamble before `{`, calls `on_narration_chunk(char)` for each character of the narration field as it arrives. Returns complete parsed dict on `[DONE]`. Expected return shape: `{ method, url, headers, body, agent_reasoning: { narration, technical } }`. Narration voice: terse, first-person, present-tense, clinical and predatory.

- `defender_agent(request: dict, response: dict, source_code: str, on_narration_chunk: callable) -> dict`
  Prompts Kimi with: the raw HTTP request, the raw response, and the current source code. **The vulnerability class is never named** — the defender derives from evidence alone. Same streaming approach. Returns: `{ patched_source, agent_reasoning: { narration, technical } }`. Narration voice: investigative, first-person, shows the discovery arc.

- `parse_model_json(raw_text: str) -> dict`
  Regex-extracts the first `{...}` block. Handles JSON in markdown code fences, stray text before/after.

- Retry wrapper (max 2 attempts): on parse failure, sends a follow-up asking for only the JSON object.

### Mock mode
Both agent functions accept `mock=True` — bypasses Kimi entirely, returns a hardcoded realistic response. `on_narration_chunk` is still called character by character with a small sleep to simulate the typewriter in mock mode. This is how Phase 4 is developed.

---

## Phase 4 — Orchestrator

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

---

## Phase 5 — Live Integration

**Touches:** `.env`, `orchestrator/main.py` (swap mock flags), `orchestrator/agents.py` (Kimi endpoint wired), `orchestrator/daytona_client.py` (confirmed working from Phase 3A)
**Depends on:** Phase 4 (full mock run confirmed working)
**Unlocks:** Phase 6

### Goal
Replace the two stubs with real external calls, in a controlled order. The rest of the codebase doesn't change — this phase is purely about swapping the mock seam for the real thing.

### Step 1 — Kimi integration
- Wire the Kimi API endpoint and key from `.env` into `agents.py`
- Run the attacker agent once against the locally-running target app (not Daytona yet) for the SQLi iteration
- Inspect the raw model output, confirm `parse_model_json` handles it, confirm the returned request dict is sensible
- If the first real call produces a nonsensical exploit request, tune the prompt and re-run (max 2 tune cycles before evaluating Groq fallback)
- Do the same for the defender agent
- Once both agents produce reliable output on the local target, proceed to Step 2

### Step 2 — Daytona integration
- Replace the `subprocess.Popen` local-app management in `main.py` with calls to `daytona_client.py`
- Run the full two-iteration sequence against a live Daytona sandbox with real Kimi calls
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
- Step 1: at most 4 real Kimi calls total (1 attacker + 1 defender per iteration × 2 iterations)
- Step 2: 1 full end-to-end run — inspect everything, fix any issues, then treat the next run as a rehearsal (Phase 6)
- Do not iterate on live infra; fix issues against mocks and re-run once

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
