# Attack on Sandbox

video demo: https://youtu.be/VJAmXWpQCRA

NOTE: due to time constraints i was not able to edit the video or refine the streaming. the llm will output garbage at first but will then form words and sentences 


**Two AI agents that don't trust each other.** One attacks a live, deliberately
vulnerable Flask API. The other patches it in response — from evidence alone,
with no idea what the attacker was told to look for. Every request, response,
and patch is real, running against a real service in an isolated
[Daytona](https://daytona.io) sandbox.


> Most AI security demos are one agent checking its own work. We built two
> agents that don't trust each other — one attacks, one defends, and you
> watch the patch happen live.

---

## What you're watching

1. **Attacker** gets the target app's source and live URL, scoped to one
   vulnerability class. It reasons about the code, builds a real exploit,
   and fires it at the sandbox for real.
2. **Defender** gets only the raw HTTP request, the raw response, and the
   current source — never told what the vulnerability *is*. It has to
   figure that out from the evidence, then rewrite the file.
3. The orchestrator deploys the patch, restarts the app, and **replays the
   attacker's exact original exploit** against it. If it now fails safely,
   the iteration is verified.
4. Repeat for the next vulnerability class.

The demo's note-taking API has intentionally trivial gaps built into it to show the concept and logic,
not a ceiling on what the loop can find. The attacker's reasoning, the exact
payload, the live request/response, the defender's patch, and the
re-verification are all generated and executed live against these bugs.

In theory, the same loop pointed at real, unscoped source can go hunting for
hidden vulnerabilities instead of intentional ones. Because the attacker
reasons over the source rather than pattern-matching against known
signatures, it's well-suited to catch the kind of logic-level flaws — a
missing ownership check, an auth path that was never wired up — that DAST,
SAST, and SCA scanners are more likely to miss. The request/response/patch
data it generates along the way (real exploit attempts paired with real
fixes) is also exactly the kind of labeled data you'd want to train a model
specifically for this task.

### Where this goes

What you're watching is three iterations of a loop with no upper bound. Drop
the scope constraint on the attacker prompt — one line — and every piece of
this scales independently:

- **No more fixed vulnerability list.** An unscoped attacker just gets
  source + a live URL and is told to find *anything* exploitable: SQLi,
  IDOR, missing auth, SSTI, command injection, insecure deserialization,
  hardcoded secrets, whatever's actually there. The defender still works
  from the request/response pair alone, so it stays honest regardless of
  what the attacker finds.
- **No upper bound on iterations.** Run it overnight against your whole
  codebase — one vulnerability found and patched per pass, indefinitely.
- **Parallel sandboxes.** Every iteration (or every service) gets its own
  isolated Daytona sandbox. Nothing stops you running hundreds or thousands
  of orchestrators concurrently, each hammering a different microservice at
  once — Daytona is built for exactly this.
- **Any stack.** The orchestrator and agents don't care what language the
  target is written in. Point the same loop at a Python, Node, Go, Java, or
  Ruby service and it reasons about the source the same way.

In production: remove the scope constraint, point it at your entire
infrastructure, and let it run — every service, every language, every
vulnerability class, continuously, with a defender patching each one as
it's found. Or point it as a specific area for targeted scanning.

---

## Architecture

```
target-app/       plain Flask JSON API, seeded with the 3 vulnerabilities above
                   → hosted in an isolated Daytona sandbox at demo time

orchestrator/      the director — the only code that talks to Daytona or ai&
  main.py            fixed iteration sequence (attack → patch → verify)
  agents.py          attacker_agent() / defender_agent(), calls ai&'s
                      deepseek-v4-flash in JSON mode
  daytona_client.py  sandbox create / deploy / patch / restart / destroy
  events.py          appends structured events to events.json

dashboard/          Streamlit — polls events.json, renders the live feed
  app.py
```

The orchestrator and dashboard are decoupled by `events.json`
(newline-delimited JSON). The orchestrator writes; the dashboard just tails
and renders. Any other consumer — a terminal, a Slack bot, a Grafana panel —
would work identically.

**Sponsor tech, both load-bearing:**
- **[Daytona](https://daytona.io)** — hosts and isolates the vulnerable
  target app; torn down and respun between iterations.
- **[ai&](https://aiand.com)** (`deepseek-ai/deepseek-v4-flash`) — powers
  both the attacker and defender agents via an OpenAI-compatible API.

---

## Running it

**Requirements:** Python 3.12, a Daytona account + API key, an ai& API key.

```bash
# install dependencies
pip install -r target-app/requirements.txt
pip install -r orchestrator/requirements.txt
pip install -r dashboard/requirements.txt

# configure
cp .env.example .env
# fill in DAYTONA_API_KEY and AIAND_API_KEY in .env
```

**Two processes, in separate terminals:**

```bash
streamlit run dashboard/app.py     # terminal 1 — opens the live dashboard
python orchestrator/main.py        # terminal 2 — runs the adversarial loop
```

The dashboard has a **Reset & Run** button for repeating a demo without
manual cleanup. To reset by hand: delete `events.json` and
`target-app/notes.db`, and `git checkout target-app/app.py` to restore the
vulnerable baseline.

note: The dashboard used was purely for demo purposes. it is not trivial (to my knowledge) to 'peer' into whats going on inside a daytona sandbox since it simply acts as a runtime, but in practice you could have a small menu that acts as a point of interaction, and have the app recursvely run iterations or on a schedule. You could also set an event listener to wait for events like bread found/patch/resolved and send it to slack/telegram/etc.
