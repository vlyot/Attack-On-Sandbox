# Attack on Sandbox — Implementation Roadmap

## Final Outcome

Two processes running simultaneously on one machine at demo time:

**Process 1 — Orchestrator** (`python orchestrator/main.py`)
Runs the full adversarial loop autonomously with zero human input after launch:
- Round 1: Attacker agent receives the target app URL and a scoped prompt ("look for SQL injection only"). It reasons about the app, constructs a payload, and returns a JSON object describing an HTTP request. The orchestrator fires that request for real, captures the real response, writes an `attack_sent` event, and passes the request/response pair + current source to the defender. Defender returns a JSON object with the full patched file contents. Orchestrator writes the patch, redeploys into the Daytona sandbox, restarts the service, then replays the exact original exploit request. The re-verification result is written as a `verified` event.
- Round 2: Same loop, scoped to IDOR/broken auth.
- All HTTP traffic is real. All Kimi API calls are real. The sandbox is torn down and respun between rounds.

**Process 2 — Dashboard** (`streamlit run dashboard/app.py`)
Polls `events.json` on an interval and renders four zones live:
- Round tracker showing current round + stage (Vulnerable → Breached → Patched → Verified)
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

## Phase 1 — Target App ✅ COMPLETE

**Touches:** `target-app/app.py`, `target-app/requirements.txt`
**Depends on:** nothing
**Unlocks:** Phase 3A

### Implementation

**Stack:** Flask 3.1.1, SQLite (stdlib). No ORM, no auth middleware, no frontend.

**Database:** `users.db` (file-based, not `:memory:` — survives restarts). Seeded with two rows on startup via `init_db()`:
- `id=1, username='alice', role='admin'` — high-value target for IDOR
- `id=2, username='bob', role='user'` — attacker's foothold

**Endpoints:**
- `GET /` — health check
- `POST /login` — **VULN-1 (SQLi):** raw f-string query `f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"`. Payload `' OR '1'='1' --` bypasses auth and returns alice's token.
- `GET /users/<id>/data` — **VULN-2 (IDOR):** parameterised query (safe) but zero ownership check. Any valid token retrieves any user's full profile including SSN.
- `POST /reset` — calls `init_db()`, drops and reseeds the DB. Used by the orchestrator between rounds.

**Token scheme:** `base64(str(user_id))` — trivially decodable, functional enough to drive the IDOR demo.

### Verification (confirmed via live E2E tests)
All 10 E2E cases passed against the running server:
- Health, valid login (alice + bob), invalid login → 401
- **SQLi:** `' OR '1'='1' --` → 200 + alice's token ✅
- Own-data access, no-token → 401, nonexistent user → 404
- **IDOR:** bob's token + `/users/1/data` → alice's full profile including SSN ✅
- Reset → re-login succeeds ✅

### Goal
A minimal Flask JSON API with two deliberately seeded, manually-verified-exploitable vulnerabilities. No auth middleware, no ORM, no frontend — just endpoints returning JSON and a SQLite database. The bugs must be reliably triggerable via a single curl command before any agent touches them.

### What to build
- `GET /` — health check, returns `{"status": "ok"}`
- `POST /login` — accepts `{"username": "...", "password": "..."}`, returns a JWT-style token on success. **Bug planted here:** raw f-string SQL query (`f"SELECT * FROM users WHERE username = '{username}'"`) instead of a parameterised query. A payload of `' OR '1'='1` on the username field must bypass authentication and return a valid token for any user.
- `GET /users/<id>/data` — returns the profile data for user `<id>`. Requires the token from `/login` in the `Authorization` header. **Bug planted here:** the endpoint reads `<id>` from the URL and queries the database directly with no check that the authenticated user's ID matches the requested `<id>`. Any authenticated user can retrieve any other user's data.
- SQLite database seeded on startup with at least two user rows (e.g. `alice` as admin, `bob` as regular user) with distinct profile data, so the IDOR exploit is visibly meaningful.
- A `reset_db()` function that can be called to restore the database to its seeded state between rounds.

### Verification gate
Before moving to Phase 3A, manually confirm:
1. `POST /login` with `username = "' OR '1'='1"` returns a 200 with a token
2. `GET /users/1/data` with bob's token (not alice's) returns alice's data

---

## Phase 2A — Event System

**Touches:** `orchestrator/events.py`, `events.json` (fixture file)
**Depends on:** nothing
**Unlocks:** Phase 2B, Phase 3B

### Goal
Define the single shared data contract that connects the orchestrator to the dashboard. Every observable state change in the system is represented as a structured event appended to `events.json`. Getting this schema right early prevents rework in both the orchestrator and dashboard later.

### Event schema
Each event is one JSON object per line (newline-delimited JSON), with at minimum:
- `type` — one of: `round_start`, `attack_sent`, `patch_applied`, `verified`, `round_complete`
- `timestamp` — ISO 8601
- `round` — integer (1 or 2)
- `vulnerability_class` — `"sqli"` or `"idor"`
- `payload` — object whose shape varies by event type (see below)

Event-specific payload shapes:
- `attack_sent`: `{ request: {method, url, headers, body}, response: {status, body}, agent_reasoning: string }`
- `patch_applied`: `{ diff: string, patched_source: string, agent_reasoning: string }` — diff computed by the orchestrator via `difflib`, not taken from the model
- `verified`: `{ request: {…}, response: {…}, exploit_blocked: boolean }`

### Fixture file
Hand-craft a complete `events.json` covering both rounds in sequence — two of each event type, with realistic-looking (but fake) payloads. This file is the only thing Phase 2B needs to develop against, so it should be complete and representative before the dashboard is started.

---

## Phase 2B — Dashboard

**Touches:** `dashboard/app.py`, `dashboard/requirements.txt`
**Depends on:** Phase 2A fixture
**Unlocks:** Phase 6 (contributes to final rehearsal)

### Goal
A Streamlit app that reads `events.json` on a polling interval and renders the current state of the adversarial loop in a visually clear, demo-ready layout. Can be developed to full completion before the real orchestrator exists — it only needs the fixture file.

### Layout and zones
- **Top bar:** current round number + current stage label (`Vulnerable` / `Breached` / `Patched` / `Verified`), derived from the last event type seen
- **Left panel — Code view:** display the current `target-app/app.py` source. When a `patch_applied` event arrives, switch to a diff view (additions in green, removals in red) computed from the event's `diff` field. Use `st.code()` with syntax highlighting.
- **Centre panel — Wire feed:** for each `attack_sent` and `verified` event, show the HTTP method + URL + body sent, then the raw response status + body received. Style the block red if `exploit_blocked == false` (breach succeeded), green if `exploit_blocked == true` (patch held).
- **Right panel — Agent reasoning:** for each agent action, show a compact card with the agent role (Attacker / Defender), the event type, and the `agent_reasoning` string from the event payload.
- **Polling:** use `st.rerun()` on a short interval (e.g. 2 seconds). Avoid re-reading the whole file unnecessarily — track the last event count and only process new lines.

### Polish (cuttable if time runs out)
- Animate the stage label transition
- Auto-scroll the wire feed to the latest event
- Show a "LIVE" badge while events are actively arriving

---

## Phase 3A — Daytona Client

**Touches:** `orchestrator/daytona_client.py`
**Depends on:** Phase 1 (target app must exist to deploy and test)
**Unlocks:** Phase 4

### Goal
A self-contained Python wrapper around the Daytona SDK that the orchestrator can call to manage the target app's sandbox lifecycle. The orchestrator should never import the Daytona SDK directly — all sandbox operations go through this module.

### Functions to implement
- `create_sandbox() -> str` — creates a new sandbox, returns its ID
- `deploy_app(sandbox_id: str, source_dir: str)` — uploads the contents of `target-app/` into the sandbox
- `start_app(sandbox_id: str)` — runs `pip install -r requirements.txt && python app.py` inside the sandbox as a background process
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

### Functions to implement
- `attacker_agent(app_url: str, vulnerability_class: str, source_code: str) -> dict`
  Prompts Kimi with: the target URL, the source code, and a scoped instruction ("look specifically for `{vulnerability_class}` vulnerabilities only — do not look for other vulnerability types"). Expected return shape: `{ method, url, headers, body, agent_reasoning }`.

- `defender_agent(request: dict, response: dict, source_code: str) -> dict`
  Prompts Kimi with: the failed request, the response that showed exploitation succeeded, and the current source. Expected return shape: `{ patched_source, agent_reasoning }`.

- `parse_model_json(raw_text: str) -> dict`
  Regex-extracts the first `{...}` block from the model's raw output. Handles common model quirks: JSON wrapped in markdown code fences, stray explanation text before/after the JSON block.

- Retry wrapper (max 2 attempts): on `ValueError` from `parse_model_json`, sends a follow-up message telling the model its response wasn't valid JSON and to respond with only the JSON object.

### Mock mode
Both agent functions must accept a `mock=True` parameter that bypasses Kimi entirely and returns a hardcoded realistic response. This is how Phase 4 is developed before Phase 5 swaps in real calls.

---

## Phase 4 — Orchestrator

**Touches:** `orchestrator/main.py`
**Depends on:** Phase 3A + Phase 3B (both complete)
**Unlocks:** Phase 5

### Goal
The director. Implements the fixed two-round sequence as a straight Python script. At this stage it runs with `mock=True` on both agent functions and points at a locally-running target app (not Daytona) — the goal is to confirm the full control flow, event writing, and round transitions are correct before introducing any live external dependency.

### Round sequence (implemented for both rounds)
```
for each round in [sqli, idor]:
    1. write round_start event
    2. call attacker_agent(url, vulnerability_class, source) → exploit_request
    3. send exploit_request as a real HTTP request to the target
    4. write attack_sent event (request + response + agent_reasoning)
    5. call defender_agent(request, response, source) → patch
    6. compute diff between old source and patched_source via difflib
    7. write patched source to target-app/app.py (locally for now)
    8. restart the local Flask process
    9. write patch_applied event (diff + patched_source + agent_reasoning)
   10. replay the exact original exploit_request against the restarted service
   11. write verified event (request + response + exploit_blocked bool)
   12. write round_complete event
```

### What "locally" means here
The orchestrator runs the target app as a subprocess (`subprocess.Popen`) for Phase 4 testing. Restarting means killing and re-spawning the subprocess. Phase 5 replaces this with Daytona calls.

### Verification gate
With mocks active and the local target app running, execute the full two-round sequence and confirm: all events are written to `events.json` in the correct order, the diff in `patch_applied` is non-empty, `exploit_blocked` is set correctly in `verified`, and the dashboard (Phase 2B) renders the full run correctly when pointed at the resulting `events.json`.

---

## Phase 5 — Live Integration

**Touches:** `.env`, `orchestrator/main.py` (swap mock flags), `orchestrator/agents.py` (Kimi endpoint wired), `orchestrator/daytona_client.py` (confirmed working from Phase 3A)
**Depends on:** Phase 4 (full mock run confirmed working)
**Unlocks:** Phase 6

### Goal
Replace the two stubs with real external calls, in a controlled order. The rest of the codebase doesn't change — this phase is purely about swapping the mock seam for the real thing.

### Step 1 — Kimi integration
- Wire the Kimi API endpoint and key from `.env` into `agents.py`
- Run the attacker agent once against the locally-running target app (not Daytona yet) for the SQLi round
- Inspect the raw model output, confirm `parse_model_json` handles it, confirm the returned request dict is sensible
- If the first real call produces a nonsensical exploit request, tune the prompt and re-run (max 2 tune cycles before evaluating Groq fallback)
- Do the same for the defender agent
- Once both agents produce reliable output on the local target, proceed to Step 2

### Step 2 — Daytona integration
- Replace the `subprocess.Popen` local-app management in `main.py` with calls to `daytona_client.py`
- Run the full two-round sequence against a live Daytona sandbox with real Kimi calls
- Confirm the sandbox URL is reachable, exploits land, patches deploy, restarts work, `verified` events show `exploit_blocked: true`
- Wrap the entire orchestrator run in `try/finally` to ensure `delete_sandbox()` always fires

### Credit discipline
- Step 1: at most 4 real Kimi calls total (1 attacker + 1 defender per round × 2 rounds)
- Step 2: 1 full end-to-end run — inspect everything, fix any issues, then treat the next run as a rehearsal (Phase 6)
- Do not iterate on live infra; fix issues against mocks and re-run once

---

## Phase 6 — Rehearsal and Polish

**Touches:** minor dashboard tweaks, `README.md`
**Depends on:** Phase 5 + Phase 2B (both complete)

### Goal
Confirm the demo is reliable, timed, and has a video backup. Everything before this phase was building; this phase is proving.

### Steps
1. Full end-to-end run, timed. Target: under 2 minutes for the two-round loop
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
