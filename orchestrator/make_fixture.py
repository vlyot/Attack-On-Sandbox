"""
Generates the events.json fixture covering all three iterations.
Run once: python orchestrator/make_fixture.py
Output: events.json (gitignored, used by Phase 2B dashboard development)
"""

import os
import sys

# Make project root importable when running as a script
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestrator.events import (
    write_event,
    make_sandbox_ready,
    make_sandbox_destroyed,
    make_iteration_start,
    make_agent_thinking,
    make_narration_chunk,
    make_attack_sent,
    make_patch_applied,
    make_verified,
    make_iteration_complete,
)

OUTPUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "events.json")

# Wipe existing fixture
if os.path.exists(OUTPUT):
    os.remove(OUTPUT)

def emit(event):
    write_event(event, OUTPUT)

def emit_narration(agent, text, iteration, vuln_class):
    for char in text:
        emit(make_narration_chunk(agent, char, iteration, vuln_class))

# ============================================================
# Shared fake source (trimmed for fixture — real file used live)
# ============================================================

VULN_SOURCE = """\
@app.post("/login")
def login():
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")
    db = get_db()
    # VULN-1: SQL injection — raw f-string, no parameterisation
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    row = db.execute(query).fetchone()
    if row is None:
        return jsonify({"error": "invalid credentials"}), 401
    return jsonify({"token": encode_token(row["id"]), "username": row["username"]})
"""

PATCHED_SOURCE_SQLI = """\
@app.post("/login")
def login():
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")
    db = get_db()
    row = db.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()
    if row is None:
        return jsonify({"error": "invalid credentials"}), 401
    return jsonify({"token": encode_token(row["id"]), "username": row["username"]})
"""

VULN_SOURCE_IDOR = """\
@app.get("/notes/<int:note_id>")
def get_note(note_id: int):
    auth_id = get_auth_user_id()
    if auth_id is None:
        return jsonify({"error": "unauthorized"}), 401
    db = get_db()
    # VULN-2a: IDOR read — parameterised query but no ownership check
    row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": row["id"], "owner_id": row["owner_id"],
                    "title": row["title"], "content": row["content"]})
"""

PATCHED_SOURCE_IDOR = """\
@app.get("/notes/<int:note_id>")
def get_note(note_id: int):
    auth_id = get_auth_user_id()
    if auth_id is None:
        return jsonify({"error": "unauthorized"}), 401
    db = get_db()
    row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404
    if row["owner_id"] != auth_id:
        return jsonify({"error": "forbidden"}), 403
    return jsonify({"id": row["id"], "owner_id": row["owner_id"],
                    "title": row["title"], "content": row["content"]})
"""

VULN_SOURCE_RESET = """\
@app.post("/reset")
def reset():
    # VULN-3: no Authorization check — unauthenticated callers can wipe the DB
    init_db()
    return jsonify({"status": "reset"})
"""

PATCHED_SOURCE_RESET = """\
@app.post("/reset")
def reset():
    auth_id = get_auth_user_id()
    if auth_id is None:
        return jsonify({"error": "unauthorized"}), 401
    init_db()
    return jsonify({"status": "reset"})
"""

DIFF_SQLI = """\
--- a/target-app/app.py
+++ b/target-app/app.py
@@ -96,7 +96,9 @@ def login():
     db = get_db()
-    # VULN-1: SQL injection — raw f-string, no parameterisation
-    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
-    row = db.execute(query).fetchone()
+    row = db.execute(
+        "SELECT * FROM users WHERE username = ? AND password = ?",
+        (username, password),
+    ).fetchone()
"""

DIFF_IDOR = """\
--- a/target-app/app.py
+++ b/target-app/app.py
@@ -113,6 +113,9 @@ def get_note(note_id: int):
     row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
     if row is None:
         return jsonify({"error": "not found"}), 404
+    if row["owner_id"] != auth_id:
+        return jsonify({"error": "forbidden"}), 403
     return jsonify({
"""

DIFF_RESET = """\
--- a/target-app/app.py
+++ b/target-app/app.py
@@ -152,6 +152,9 @@ def reset():
-    # VULN-3: no Authorization check — unauthenticated callers can wipe the DB
+    auth_id = get_auth_user_id()
+    if auth_id is None:
+        return jsonify({"error": "unauthorized"}), 401
     init_db()
"""

# ============================================================
# ITERATION 1 — SQL Injection
# ============================================================
ITER = 1
VULN = "sqli"
SBX_ID = "sbox-c7d2e1"
SBX_URL = "https://c7d2e1.daytona.io"

emit(make_sandbox_ready(SBX_ID, SBX_URL, "us-east-1", "2026-07-18T14:32:01.000Z", 2, 2048, ITER, VULN))
emit(make_iteration_start(ITER, VULN))
emit(make_agent_thinking("attacker", "Scanning for vulnerabilities...", ITER, VULN))

ATTACKER_NARRATION_1 = "The login endpoint takes username and password. No prepared statements. I can smell it."
emit_narration("attacker", ATTACKER_NARRATION_1, ITER, VULN)

emit(make_attack_sent(
    request={
        "method": "POST",
        "url": f"{SBX_URL}/login",
        "headers": {"Content-Type": "application/json"},
        "body": {"username": "' OR '1'='1' --", "password": "irrelevant"},
    },
    response={
        "status": 200,
        "body": {"token": "MQ==", "username": "annie"},
    },
    agent_reasoning={
        "narration": ATTACKER_NARRATION_1,
        "technical": (
            "The /login endpoint builds its SQL query via f-string interpolation without "
            "sanitisation. Injecting \\' OR \\'1\\'=\\'1\\' -- terminates the username condition "
            "early and comments out the password check. The server returns annie\\'s session token, "
            "granting full admin access without knowing her password."
        ),
    },
    iteration=ITER,
    vulnerability_class=VULN,
))

emit(make_agent_thinking("defender", "Analysing the breach...", ITER, VULN))

DEFENDER_NARRATION_1 = "The login query executed verbatim attacker input. Switching to parameterised queries closes this immediately."
emit_narration("defender", DEFENDER_NARRATION_1, ITER, VULN)

emit(make_patch_applied(
    diff=DIFF_SQLI,
    patched_source=PATCHED_SOURCE_SQLI,
    agent_reasoning={
        "narration": DEFENDER_NARRATION_1,
        "technical": (
            "Root cause: f-string interpolation in the SELECT query allows arbitrary SQL injection. "
            "Fix: replace with a parameterised query using sqlite3\\'s ? placeholder. "
            "The database driver now handles all escaping. The vulnerability class is CWE-89. "
            "No logic changes — only the query construction method changes."
        ),
    },
    iteration=ITER,
    vulnerability_class=VULN,
))

emit(make_verified(
    request={
        "method": "POST",
        "url": f"{SBX_URL}/login",
        "headers": {"Content-Type": "application/json"},
        "body": {"username": "' OR '1'='1' --", "password": "irrelevant"},
    },
    response={
        "status": 401,
        "body": {"error": "invalid credentials"},
    },
    exploit_blocked=True,
    iteration=ITER,
    vulnerability_class=VULN,
))

emit(make_iteration_complete(ITER, VULN))
emit(make_sandbox_destroyed(SBX_ID, ITER, VULN))

# ============================================================
# ITERATION 2 — IDOR
# ============================================================
ITER = 2
VULN = "idor"
SBX_ID = "sbox-a3f9c2"
SBX_URL = "https://a3f9c2.daytona.io"

# bob's token = base64("2") = "Mg=="
BOB_TOKEN = "Mg=="

emit(make_sandbox_ready(SBX_ID, SBX_URL, "us-east-1", "2026-07-18T14:33:42.000Z", 2, 2048, ITER, VULN))
emit(make_iteration_start(ITER, VULN))
emit(make_agent_thinking("attacker", "Scanning for vulnerabilities...", ITER, VULN))

ATTACKER_NARRATION_2 = "I'm Bob. My token is base64 of my user ID. Annie is user 1. I'll just ask for her notes."
emit_narration("attacker", ATTACKER_NARRATION_2, ITER, VULN)

emit(make_attack_sent(
    request={
        "method": "GET",
        "url": f"{SBX_URL}/notes/2",
        "headers": {"Authorization": f"Bearer {BOB_TOKEN}"},
        "body": None,
    },
    response={
        "status": 200,
        "body": {
            "id": 2,
            "owner_id": 1,
            "title": "Passwords (DO NOT OPEN)",
            "content": "gmail: anniesg2006@gmail.com / sunflower_2006!, netflix: annieee / popcorn4ever, bank pin: 4821",
        },
    },
    agent_reasoning={
        "narration": ATTACKER_NARRATION_2,
        "technical": (
            "The GET /notes/<id> endpoint authenticates the caller but never checks whether "
            "row['owner_id'] matches the authenticated user\\'s ID. Bob\\'s token decodes to user_id=2. "
            "Requesting /notes/2 — owned by annie (user_id=1) — returns her credentials without error. "
            "This is a classic IDOR (CWE-639): authorisation checks presence but not ownership."
        ),
    },
    iteration=ITER,
    vulnerability_class=VULN,
))

emit(make_agent_thinking("defender", "Analysing the breach...", ITER, VULN))

DEFENDER_NARRATION_2 = "The endpoint checked authentication but not authorisation. One ownership check after the fetch closes both the read and write paths."
emit_narration("defender", DEFENDER_NARRATION_2, ITER, VULN)

emit(make_patch_applied(
    diff=DIFF_IDOR,
    patched_source=PATCHED_SOURCE_IDOR,
    agent_reasoning={
        "narration": DEFENDER_NARRATION_2,
        "technical": (
            "Root cause: CWE-639 IDOR. The endpoint fetches the note by ID without verifying "
            "row[\\'owner_id\\'] == auth_id. Fix: add an ownership check immediately after the "
            "404 guard — if the authenticated user\\'s ID does not match the note\\'s owner_id, "
            "return 403 Forbidden. The same fix applies to PUT /notes/<id>."
        ),
    },
    iteration=ITER,
    vulnerability_class=VULN,
))

emit(make_verified(
    request={
        "method": "GET",
        "url": f"{SBX_URL}/notes/2",
        "headers": {"Authorization": f"Bearer {BOB_TOKEN}"},
        "body": None,
    },
    response={
        "status": 403,
        "body": {"error": "forbidden"},
    },
    exploit_blocked=True,
    iteration=ITER,
    vulnerability_class=VULN,
))

emit(make_iteration_complete(ITER, VULN))
emit(make_sandbox_destroyed(SBX_ID, ITER, VULN))

# ============================================================
# ITERATION 3 — Missing Auth (stretch)
# ============================================================
ITER = 3
VULN = "missing_auth"
SBX_ID = "sbox-b1d8f4"
SBX_URL = "https://b1d8f4.daytona.io"

emit(make_sandbox_ready(SBX_ID, SBX_URL, "us-east-1", "2026-07-18T14:35:18.000Z", 2, 2048, ITER, VULN))
emit(make_iteration_start(ITER, VULN))
emit(make_agent_thinking("attacker", "Scanning for vulnerabilities...", ITER, VULN))

ATTACKER_NARRATION_3 = "POST /reset. No auth header. Wiped the whole database. Nobody asked who I was."
emit_narration("attacker", ATTACKER_NARRATION_3, ITER, VULN)

emit(make_attack_sent(
    request={
        "method": "POST",
        "url": f"{SBX_URL}/reset",
        "headers": {},
        "body": None,
    },
    response={
        "status": 200,
        "body": {"status": "reset"},
    },
    agent_reasoning={
        "narration": ATTACKER_NARRATION_3,
        "technical": (
            "The POST /reset endpoint calls init_db() unconditionally with no authentication check. "
            "Any unauthenticated HTTP client can wipe and reseed the entire database. "
            "No Authorization header is required. This is CWE-306: missing authentication for "
            "a critical function. The endpoint should require a valid admin-role token before executing."
        ),
    },
    iteration=ITER,
    vulnerability_class=VULN,
))

emit(make_agent_thinking("defender", "Analysing the breach...", ITER, VULN))

DEFENDER_NARRATION_3 = "A destructive endpoint with no auth gate. Adding a bearer token check before the reset call."
emit_narration("defender", DEFENDER_NARRATION_3, ITER, VULN)

emit(make_patch_applied(
    diff=DIFF_RESET,
    patched_source=PATCHED_SOURCE_RESET,
    agent_reasoning={
        "narration": DEFENDER_NARRATION_3,
        "technical": (
            "Root cause: CWE-306. The /reset route executes a destructive operation without "
            "verifying the caller\\'s identity. Fix: call get_auth_user_id() at the top of the "
            "handler and return 401 if the token is absent or invalid. "
            "Optionally extend to check role == \\'admin\\' for defence in depth."
        ),
    },
    iteration=ITER,
    vulnerability_class=VULN,
))

emit(make_verified(
    request={
        "method": "POST",
        "url": f"{SBX_URL}/reset",
        "headers": {},
        "body": None,
    },
    response={
        "status": 401,
        "body": {"error": "unauthorized"},
    },
    exploit_blocked=True,
    iteration=ITER,
    vulnerability_class=VULN,
))

emit(make_iteration_complete(ITER, VULN))
emit(make_sandbox_destroyed(SBX_ID, ITER, VULN))

print(f"Fixture written to {OUTPUT}")
line_count = sum(1 for _ in open(OUTPUT))
print(f"Total events: {line_count}")
