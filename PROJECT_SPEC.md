# Attack on Sandbox — PRD

**Event:** Daytona HackSprint × AI Builders, NUS Singapore
**Format:** Solo or small team, one-day build, 2-minute live demo
**Status:** Pre-build — locked scope, ready to implement

---

## 1. Summary

Two AI agents — an attacker and a defender — face off over a small,
deliberately vulnerable Flask API running in a Daytona sandbox. Each round,
the attacker is scoped to one specific vulnerability class, exploits it for
real, and the defender patches the source in response. The attacker then
replays its own exploit against the patch to confirm it holds, before
moving to the next round. The sequence (which bugs, in what order) is fixed
and rehearsed — nothing is left to chance — but every request, response,
and patch shown live is genuinely real, against a genuinely running
service.

**One-line pitch:** "Most AI security demos are one agent checking its own
work. We built two agents that don't trust each other — one attacks, one
defends, and you watch the patch happen live."

---

## 2. Locked decisions

| Area | Decision |
|---|---|
| Concept | Two-agent adversarial loop (attacker vs. defender) — not a single self-checking agent |
| Target | Small Flask API, three deliberately seeded vulnerabilities |
| Round 1 | SQL injection |
| Round 2 | Broken auth / IDOR |
| Round 3 | Missing authentication on a sensitive action (stretch goal) |
| Sequence | Fully scripted: attack (scoped) → patch → re-verify → next round |
| Infra | Daytona sandboxes host the target app; torn down and respun between rounds |
| Orchestrator | Plain Python, runs locally, single source of truth for the fixed sequence |
| LLM calling style | Manual JSON-in-prompt, parsed by the orchestrator — not native tool-calling |
| Dashboard | Streamlit, all-Python, no separate frontend framework |
| Repo | Single repo, three components: `target-app/`, `orchestrator/`, `dashboard/` |
| Sponsor integrations | **Daytona + Kimi AI**, both load-bearing. Nosana: optional late stretch only (see §9) |
| Name | Attack on Sandbox |

**Still open / confirm day-of:**
- Exact Kimi API details (endpoint, auth, model tier) — confirm at the workshop
- Venue wifi reliability for Kimi + Daytona API calls — confirm morning-of, mobile hotspot as backup
- Dashboard visual polish — timeboxed, cut first if behind schedule

---

## 3. Architecture

```
attack-on-sandbox/
├── target-app/                 # plain Flask, JSON API only, no frontend
│   ├── app.py                   #  seeded SQLi + broken-auth/IDOR bugs
│   └── requirements.txt
├── orchestrator/                # the director — only place touching
│   │                             #  Daytona SDK + Kimi API
│   ├── main.py                    #  fixed round sequence
│   ├── daytona_client.py          #  create/upload/exec/get_url/delete wrapper
│   ├── agents.py                  #  attacker_agent(), defender_agent(),
│   │                                #  JSON parsing + retry logic
│   └── events.py                   #  appends structured events to events.json
├── dashboard/
│   ├── app.py                    #  Streamlit — reads events.json, renders
│   └── requirements.txt
├── events.json                  # shared state file (orchestrator writes,
│                                  #  dashboard polls)
├── .env                          # DAYTONA_API_KEY, KIMI_API_KEY
└── README.md
```

**Runtime:** two processes on one machine at demo time —
`streamlit run dashboard/app.py` and `python orchestrator/main.py`. Both
plain Python, no build step, no extra servers.

**Daytona's role:** hosts *only* the target app. The attacker/defender
agents are API calls from the orchestrator (running on your own machine) —
they don't need their own sandboxes. The thing that needs isolation is the
vulnerable service itself and the live exploit traffic hitting it.

---

## 4. The two seeded vulnerabilities

### Round 1 — SQL Injection
Planted via raw string concatenation in a login or search query
(`f"SELECT * FROM users WHERE username = '{username}'"` instead of a
parameterised query).

**Fix:** swap to a parameterised query — small, mechanical, one-pass
patchable.

### Round 2 — Broken Auth / IDOR
Planted as either a client-controlled role flag, or a predictable resource
ID with no ownership check (e.g. `/users/<id>/data` returns any user's data
regardless of who's authenticated).

**Fix:** add a server-side ownership/role check — same principle, small,
bounded, one clean patch.

### Round 3 — Missing Authentication on a Sensitive Action (Stretch Goal)
Planted as a destructive or privileged endpoint — `POST /reset` or a
`DELETE /users/<id>` route — that performs its action with no
`Authorization` header check at all. Any unauthenticated caller can trigger
it. The vulnerability is pure omission: the auth guard was simply never
added, just like Rounds 1 and 2.

**Fix:** add a token check at the top of the handler — require a valid
admin-role token before allowing the action to proceed.

**Condition:** only run Round 3 if the core two-round loop is rock solid
and time allows. Cut it entirely rather than rush it.

**Process:** all vulnerabilities are authored in advance, manually
verified exploitable via curl before any agent touches them, and tuned (if
needed) until the attacker agent reliably finds and exploits each one
within a rehearsed number of turns.

---

## 5. The scripted sequence, per round

1. **Attack** — orchestrator prompts the attacker agent, *scoped to one
   named vulnerability class only* ("look specifically for SQL injection...
   do not look for other vulnerability types this round"). Agent returns
   JSON describing an HTTP request. Orchestrator sends it for real, captures
   the real response. Event written: `attack_sent`.
2. **Patch** — orchestrator sends the failed request/response pair plus
   current source to the defender agent. Agent returns JSON with the full
   patched file contents. Orchestrator writes it, redeploys, restarts the
   service. Event written: `patch_applied` (diff computed locally via
   `difflib`, not trusted from the model's own description).
3. **Verify** — orchestrator replays the *exact same* request from step 1
   against the newly patched target. Expected: it now fails safely. Event
   written: `verified`.
4. Repeat for the next vulnerability class.

Scoping the attacker to one named vulnerability class per round (rather
than an unscoped "find the vulnerability") is what keeps the outcome
controlled — without this, the model could find something other than what
was seeded, or rediscover an already-patched bug.

---

## 6. LLM calling: manual JSON parsing

Prompt the model in plain English to respond with *only* a JSON object in
an exact specified shape; the orchestrator parses that text itself and
performs the real action (HTTP request, file write). No native
tool-calling / `tools` parameter used.

```python
import json, re

def parse_model_json(raw_text: str) -> dict:
    match = re.search(r'\{.*\}', raw_text, re.DOTALL)
    if not match:
        raise ValueError(f"No JSON found in response: {raw_text}")
    return json.loads(match.group())
```

Wrap every model call in a retry (hard cap: 2 attempts): on parse failure,
send a follow-up message telling the model its last response wasn't valid
JSON and to respond with *only* the JSON object.

---

## 7. Dashboard — what it shows

Four zones, updating live as the orchestrator writes to `events.json`
(Streamlit polls the file on an interval — no websockets):

1. **Round tracker** (top) — current round + stage (Vulnerable → Breached →
   Patched → Verified)
2. **Code panel** (left) — current target source, relevant lines
   highlighted; flips to a diff view the moment a patch lands
3. **Wire feed** (centre) — the actual HTTP request sent and raw response
   received, styled so a breach reads as alarming (red) and a blocked
   attempt reads as safe (green)
4. **Agent reasoning** (right) — two-layer display per agent action:
   - **Narration** (large, readable): first-person present-tense inner
     monologue written by the model itself, prompted into a terse dramatic
     voice. Attacker is clinical and predatory; defender is methodical.
     Example attacker line: *"Spotted an unsanitised input. Dropping a
     classic OR bypass — if this works, we're in without knowing any
     password."* Example defender line: *"Quote in the username field.
     Classic injection pattern. Switching to parameterised query — that
     closes it."*
   - **Technical** (small, monospace below): the model's actual reasoning
     about the vulnerability class, payload choice, and patch rationale.

Both fields are returned by the model in the same JSON response — the
`agent_reasoning` field is an object with `narration` and `technical`
subfields. The orchestrator writes both verbatim; no post-processing.
The request/response pair shown in the wire feed must always be the real,
live data — only the reasoning panel content is prompted into a specific
style.

---

## 8. Model & provider

**Kimi AI API** — sponsor-provided credits, confirm exact endpoint/auth/
model tier at the workshop before writing agent prompts around it.

**Reliability test (do this first, before building anything else):** write
the smallest possible script — one prompt asking for a fixed JSON shape,
run it 5–10 times against the actual Kimi model, confirm it reliably
returns clean, parseable JSON.

**If Kimi proves unreliable under test:** fall back to Groq free tier
(`openai/gpt-oss-120b`, confirm live at `console.groq.com/docs/models` —
catalog has been volatile in 2026) — but this changes the sponsor-usage
story, so only fall back if genuinely necessary.

---

## 9. Sponsor integration plan

**Committed: Daytona + Kimi AI, both load-bearing.** Daytona hosts and
isolates the target app (core to the architecture); Kimi's API powers both
the attacker and defender agents (core to the loop).

**Nosana: optional late-stage stretch only.** Not part of the core build —
only attempt after the core loop (§12 steps 1–7) is rock solid and
demo-ready. If time allows, a minimal add-on: run a second,
independently-hosted model on Nosana as a sanity-check validator for the
defender's patch. Do not architect the core system around this.

**Note on "Kimi on Daytona":** means calling Kimi's hosted API from code
running in the orchestrator/sandbox — not self-hosting Kimi's weights
inside a Daytona sandbox. Kimi K2 is a ~1T-parameter model requiring
multi-GPU clusters (8×H100/H200-class); a Daytona sandbox is a small
isolated Linux box and cannot run the actual weights. Confirmed infeasible
for a one-day build.

---

## 10. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Agent wanders / takes too many turns under time pressure | Extremely directive prompts ("act, do not ask questions, do not explain"); hard cap on max turns in code |
| Model doesn't reliably return clean JSON | Defensive regex + retry wrapper (max 2 attempts); reliability test before building; Groq fallback chosen in advance |
| Daytona/Kimi network flakiness live on stage | **Record a successful full rehearsal run as video backup**; play it if live infra fails |
| Venue wifi issues | Confirm morning-of; mobile hotspot as backup |
| Streamlit polling causes visual stutter | Test early; increase poll interval or use `st.empty()` placeholders correctly if distracting |
| Scope too large for the time available | Dashboard polish is the first thing to cut; Round 3 is the second; the two-round core loop is not cuttable |
| Attacker rediscovers an already-patched bug in a later round | Attacker prompt explicitly scoped to one named vulnerability class per round (§5) |
| Sponsor credits run out mid-build | See §11 credit discipline |

---

## 11. Credit discipline (read before running any real API/sandbox calls)

Kimi API calls and Daytona sandbox operations spend finite, sponsor-provided
credits for the day — not unlimited free infra. A previous hackathon burned
through limited credits via uncontrolled iteration; do not repeat that.

- **Do not loop, batch-test, or repeatedly re-run scripts that call Kimi or
  create/tear down Daytona sandboxes as a debugging strategy.**
- **Test logic with mocks/stubs first.** Debug the orchestrator's control
  flow, JSON parsing, event-writing, and dashboard rendering against fake/
  hardcoded responses. Only swap in real API calls once surrounding logic
  is already known to work.
- **When a real call is genuinely needed**, run it once, inspect the
  result, reason about what changed — don't re-run-and-see as a first
  response to an error.
- **Cap retries in code**, not just in intent (§6 — hard max-attempts
  limit of 2).
- **Sandbox lifecycle discipline:** pair every `daytona.create()` with a
  corresponding `daytona.delete()` once no longer needed — don't leave
  sandboxes accumulating while iterating on unrelated code.
- **Budget rehearsals deliberately.** Decide up front how many full
  end-to-end rehearsal runs the credit budget affords; treat it as a hard
  number.

---

## 12. Build order

1. **Connect Claude Code to Daytona's MCP server** (§12b) — one-time setup,
   do this first so manual sandbox checks throughout the build are fast.
2. `target-app/app.py` — plain Flask, two seeded bugs, manually verified
   exploitable via curl. No Daytona involved yet.
3. `orchestrator/daytona_client.py` — sandbox create/upload/exec/get URL/
   delete, tested manually against the target app.
4. Kimi reliability test (§8) — confirm before writing agent prompts around it.
5. `orchestrator/agents.py` — attacker/defender prompt functions + JSON
   parsing/retry.
6. `orchestrator/main.py` + `events.py` — the fixed round sequence.
7. `dashboard/app.py` — Streamlit, rendering events, styled deliberately.
8. Full rehearsal, twice minimum, timed. Record video backup on first
   clean pass.

Each step is independently testable before the next depends on it.

---

## 12b. Claude Code ↔ Daytona MCP server (development-time only)

This is separate from the project's own Daytona integration. `orchestrator/
daytona_client.py` (§3) is the Python SDK code the *orchestrator* uses at
runtime, during the actual demo, to create/manage the target app's sandbox.
The MCP server below is for *you*, while building — it lets Claude Code
itself create, inspect, and run commands in Daytona sandboxes directly from
a coding session, which is useful for quick manual testing (e.g. "spin up a
sandbox and curl the target app to confirm the SQLi payload works") without
writing a throwaway script each time.

**Setup:**

```bash
# 1. Install the Daytona CLI (Mac/Linux)
brew install daytonaio/cli/daytona

# 2. Authenticate
daytona login

# 3. Initialize the MCP server for Claude
daytona mcp init claude
```

After this, open/restart Claude Code — Daytona's tools should be available
in the session automatically. If they don't appear, `daytona mcp config`
prints the raw JSON config to paste into Claude Code's MCP settings
manually, and `daytona mcp start` starts the server directly if needed for
troubleshooting.

**Tools this exposes to Claude Code:** sandbox management, file system
operations, git operations, process/code execution, computer use, and
preview URL access — i.e. Claude Code can create a sandbox, upload/edit
files in it, run commands, and fetch its preview URL, all as part of a
normal coding conversation.

**Credit discipline still applies (§11).** Every sandbox Claude Code
creates via this MCP server spends the same pool of Daytona credits as the
orchestrator does. Don't use it to casually spin up sandboxes for
exploration — use it deliberately (e.g. confirming the target app deploys
correctly before wiring the full orchestrator around it), and clean up
(`daytona.delete()` / equivalent) when done with a manual check.

---

## 13. Hour-by-hour against the schedule

- **10:00–11:30** — kickoff + workshop (attend; mentally finalise the two
  vulnerabilities during this, don't build yet)
- **11:30–12:30** — build target app + plant both vulnerabilities, verify
  manually with curl
- **12:30–1:00** — lunch
- **1:00–2:30** — wire up Daytona client, agents, orchestrator sequence
- **2:30–3:30** — end-to-end rehearsal ×2 minimum, fix stalls/ugly output,
  record video backup
- **3:30–4:00** — dashboard polish (cuttable if behind)
- **4:00–4:30** — buffer / final rehearsal
- **4:30** — demo

---
---

# Appendix: Rationale & justification

*Reference material for pitching, Q&A, and judge conversations. Not needed
during implementation.*

## A1. Why two agents instead of one doing both roles?

A single agent playing both attacker and defender has information leakage
as an architectural problem: if it just wrote the exploit, patching it
isn't genuine discovery, it's "undo my last move." Two agents with
separate, isolated context means the defender is reasoning from scratch,
from evidence only (the request/response pair) — a harder and more honest
problem. It's also a least-privilege split: the attacker never needs
filesystem write access, the defender never needs to send network requests.

## A2. Why is this "real" if the vulnerabilities are scripted?

The vulnerability *classes* and *order* are fixed — same as scoping a real
pentest. What's genuinely live: the attacker's reasoning about where in the
code the bug is, the exact payload it constructs, the real HTTP request
sent to a real running service, the real response received, the defender's
actual patch, and the real re-verification request. Nothing is faked —
we've just bounded the search space so the outcome is reliable in a
2-minute demo window.

## A3. Why does this need Daytona specifically, not just local processes?

Isolation is a genuine requirement, not a checkbox — you don't want
agent-generated exploit code and agent-generated patches running anywhere
near your own machine or anything else. Fast spin-up (sub-second) is also
load-bearing: tearing down a compromised sandbox and standing up a patched
one between rounds needs to be fast enough to not create dead air in a live
demo.

## A4. Honest framing on novelty (have this ready if pushed)

Autonomous red-team/blue-team agent concepts aren't new as a category —
commercial autonomous pentesting tools exist, and "AI patches its own code
in a loop" is close to mainstream loop-engineering territory now. What's
distinct here is the adversarial two-agent framing (opposition, not
self-checking) and the fully choreographed live demo of it. Don't claim the
base concept is unprecedented; claim the framing and execution are.

## A5. Why manual JSON parsing instead of native tool-calling

Native tool-calling (Claude/GPT-4/some Groq models) requires a model
specifically fine-tuned to produce a structured `tool_use` format reliably.
Free-tier and sponsor-provided models can have inconsistent tool-calling
reliability, and testing that reliability is itself a time cost worth
avoiding. Manual JSON parsing is functionally the same agentic pattern —
the model still makes every decision based on real feedback each turn —
just with the parsing step done in our code instead of the provider's. It
widens model choice (no function-calling fine-tuning required) at the cost
of needing defensive parsing (models sometimes wrap JSON in code fences or
add stray text).

## A6. Sponsor usage — why two deep integrations over three shallow ones

The hackathon's stated requirement is to "integrate sponsors' products,"
not explicitly all three by name. Two genuinely load-bearing integrations
(Daytona for infra, Kimi for both agents) should score better on the
"Sponsored Product Usage" criterion than three shallow, forced ones — a
judge is likely to notice a token integration bolted on to chase a
checkbox. Nosana remains a clean, honest option to add if time allows, but
isn't required for the core pitch to be complete.

## A7. Anticipated Q&A

- **"Why two agents, not one?"** → see A1.
- **"Isn't this just loop engineering?"** → acknowledge the term directly,
  then pivot to the adversarial-framing distinction (A1, A4).
- **"What's the real-world use case?"** → a continuous red-teaming/training
  tool for a team to stress-test their own service, not a novel security
  primitive.
- **"Is this actually live, or scripted?"** → both, honestly: the
  vulnerability classes and order are fixed in advance (A2); the reasoning,
  payloads, requests, responses, and patches are genuinely generated and
  executed live against a real running service.
