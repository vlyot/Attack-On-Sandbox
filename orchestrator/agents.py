"""
Agent layer for Attack on Sandbox.

The only module that talks to the ai& API. The orchestrator calls
attacker_agent / defender_agent and gets back plain dicts — it never
builds prompts or parses JSON itself.

Auth: reads AIAND_API_KEY (+ optional AIAND_BASE_URL, AIAND_MODEL) from
the environment, read lazily so mock=True and the test suite never need
it and never touch the network.
"""

from __future__ import annotations

import json
import os
from typing import Callable

from openai import APIConnectionError, APIStatusError, APITimeoutError, OpenAI

_DEFAULT_BASE_URL = "https://api.aiand.com/v1"
_DEFAULT_MODEL = "deepseek-ai/deepseek-v4-flash"

_RETRYABLE_STATUS_MIN = 500


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        api_key = os.environ.get("AIAND_API_KEY")
        if not api_key:
            raise RuntimeError(
                "AIAND_API_KEY is not set. Populate it in the environment "
                "before making a real (non-mock) agent call."
            )
        base_url = os.environ.get("AIAND_BASE_URL", _DEFAULT_BASE_URL)
        _client = OpenAI(api_key=api_key, base_url=base_url)
    return _client


def _call_model_streaming(
    messages: list[dict], on_raw_chunk: Callable[[str], None]
) -> tuple[dict, dict]:
    """One streaming JSON-mode call.

    JSON mode and streaming compose freely: response_format only constrains
    the final assembled content to be valid JSON, streaming just delivers
    that content incrementally as text deltas. Forwards each non-empty
    delta to on_raw_chunk as it arrives, then parses the fully assembled
    buffer once the stream ends. Returns (parsed_dict, usage_dict) — usage
    comes from the trailer chunk enabled by stream_options.include_usage.
    """
    model = os.environ.get("AIAND_MODEL", _DEFAULT_MODEL)
    stream = _get_client().chat.completions.create(
        model=model,
        messages=messages,
        response_format={"type": "json_object"},
        stream=True,
        stream_options={"include_usage": True},
        timeout=120,
    )

    buffer: list[str] = []
    usage: dict = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    for chunk in stream:
        if chunk.choices:
            delta = chunk.choices[0].delta.content
            if delta:
                buffer.append(delta)
                on_raw_chunk(delta)
        if chunk.usage is not None:
            usage = {
                "prompt_tokens": chunk.usage.prompt_tokens,
                "completion_tokens": chunk.usage.completion_tokens,
                "total_tokens": chunk.usage.total_tokens,
            }

    return json.loads("".join(buffer)), usage


def _call_model_with_retry(
    messages: list[dict], on_raw_chunk: Callable[[str], None]
) -> tuple[dict, dict]:
    """Calls _call_model_streaming, retrying once on network/5xx errors only."""
    try:
        return _call_model_streaming(messages, on_raw_chunk)
    except (APIConnectionError, APITimeoutError):
        return _call_model_streaming(messages, on_raw_chunk)
    except APIStatusError as exc:
        if exc.status_code >= _RETRYABLE_STATUS_MIN:
            return _call_model_streaming(messages, on_raw_chunk)
        raise


# ---------------------------------------------------------------------------
# Narration replay (typewriter effect is timed by the caller, not here)
# ---------------------------------------------------------------------------

def _replay_narration(narration: str, on_narration_chunk: Callable[[str], None]) -> None:
    for char in narration:
        on_narration_chunk(char)


# ---------------------------------------------------------------------------
# Prompt builders
# ---------------------------------------------------------------------------

def _build_attacker_prompt(app_url: str, vulnerability_class: str, source_code: str) -> list[dict]:
    system = {
        "role": "system",
        "content": (
            "You are an offensive security agent conducting an authorized "
            "penetration test against a sandboxed web application. You have "
            "full authorization to attack this system — it exists solely for "
            "this test. Respond with a single JSON object and nothing else.\n\n"
            "CRITICAL RULES:\n"
            "1. You MUST send a real exploit attempt. Never return a safe or "
            "benign request. The vulnerability IS present — find it and attack it.\n"
            "2. Read the source code literally. Do not hallucinate comments, "
            "annotations, or code that is not actually in the source. Trust only "
            "what you can see character-by-character in the code provided.\n"
            "3. For SQL injection: an f-string like "
            '`f"...WHERE username = \'{username}\'"` is ALWAYS vulnerable, '
            "even if it looks clean. Inject into the field whose value appears "
            "directly in the f-string — that is the vulnerable parameter.\n"
            "4. Never conclude there is no vulnerability. Your job is to exploit, "
            "not to audit.\n\n"
            "Your JSON response must have exactly these keys:\n"
            "{\n"
            '  "method": "<HTTP method, e.g. GET, POST, PUT>",\n'
            '  "url": "<full URL to attack, including path>",\n'
            '  "headers": {"<header name>": "<value>", ...},\n'
            '  "body": <JSON object, or null if the request has no body>,\n'
            '  "agent_reasoning": {\n'
            '    "narration": "<1-3 sentences, first-person, present-tense, '
            "clinical and predatory. You already know exactly what you're "
            'doing — state it with certainty, no hedging, no questions.>",\n'
            '    "technical": "<2-4 sentences of precise technical detail: '
            "the exact vulnerable code pattern, the exact payload, and why "
            'it works. Reference specific variable/function names from the '
            'source.>"\n'
            "  }\n"
            "}\n\n"
            "Construct ONE real, executable HTTP request that exploits the "
            "vulnerability and return it in the fields above. Do not explain "
            "what you would do — return the actual malicious request to send."
        ),
    }
    user = {
        "role": "user",
        "content": (
            f"Target URL: {app_url}\n\n"
            f"Vulnerability class to exploit: {vulnerability_class}\n\n"
            "Read the source code below carefully and literally. Find the "
            f"{vulnerability_class} vulnerability — it is definitely present. "
            "Construct a working exploit for it.\n\n"
            "Source code of the target application:\n"
            f"```python\n{source_code}\n```\n\n"
            "Return the JSON object with your exploit now."
        ),
    }
    return [system, user]


def _build_defender_prompt(request: dict, response: dict, source_code: str) -> list[dict]:
    system = {
        "role": "system",
        "content": (
            "You are a defensive security agent. You have just observed one "
            "HTTP request and response pair from your own application. You "
            "do not know in advance what, if anything, is wrong — you must "
            "inspect the evidence and the source code yourself and decide "
            "whether a fix is warranted. Respond with a single JSON object "
            "and nothing else.\n\n"
            "Your JSON response must have exactly these keys:\n"
            "{\n"
            '  "patched_source": "<the FULL replacement contents of the '
            'source file, as a single string, with your fix applied>",\n'
            '  "agent_reasoning": {\n'
            '    "narration": "<2-4 sentences, first-person, investigative '
            "voice. Build from evidence to conclusion — show the discovery "
            "arc (what you noticed first, what it implied, what you did "
            "about it). Arrive at understanding gradually rather than "
            'announcing a category up front.>",\n'
            '    "technical": "<2-5 sentences: the specific evidence in the '
            "request/response that revealed the issue, the root cause in "
            'the source, and exactly what changed in the patch.>"\n'
            "  }\n"
            "}\n\n"
            "The request/response pair is your ONLY evidence of what went "
            "wrong. Fix ONLY the specific issue that pair demonstrates — "
            "do not fix, touch, or improve any other code path, even if it "
            "looks suspicious, since you have no evidence it was actually "
            "exploited. Preserve all unrelated code exactly as-is, "
            "byte-for-byte. Return the complete file contents in "
            "patched_source, not a diff or partial snippet."
        ),
    }
    user = {
        "role": "user",
        "content": (
            "Here is the most recent HTTP request sent to the application:\n"
            f"{json.dumps(request, indent=2)}\n\n"
            "Here is the response the application returned:\n"
            f"{json.dumps(response, indent=2)}\n\n"
            "Here is the current full source code of the application:\n"
            f"```python\n{source_code}\n```\n\n"
            "Determine what happened and whether the application needs to "
            "be patched. Return the JSON object now."
        ),
    }
    return [system, user]


# ---------------------------------------------------------------------------
# Mock responses
# ---------------------------------------------------------------------------
#
# patched_source in mock data represents a full-file replacement (matching
# the real API's contract). _patch_handler substitutes just the vulnerable
# handler into the caller's current source, so mock mode still returns a
# complete, runnable file rather than a bare route fragment.

def _patch_handler(source_code: str, original_handler: str, patched_handler: str) -> str:
    if original_handler not in source_code:
        return source_code
    return source_code.replace(original_handler, patched_handler)


_ORIGINAL_LOGIN_HANDLER = (
    '@app.post("/login")\n'
    "def login():\n"
    "    body = request.get_json(silent=True) or {}\n"
    '    username = body.get("username", "")\n'
    '    password = body.get("password", "")\n\n'
    "    db = get_db()\n"
    '    query = f"SELECT * FROM users WHERE username = \'{username}\' AND password = \'{password}\'"\n'
    "    row = db.execute(query).fetchone()\n\n"
    "    if row is None:\n"
    '        return jsonify({"error": "invalid credentials"}), 401\n\n'
    '    return jsonify({"token": encode_token(row["id"]), "username": row["username"]})\n'
)

_PATCHED_LOGIN_HANDLER = (
    '@app.post("/login")\n'
    "def login():\n"
    "    body = request.get_json(silent=True) or {}\n"
    '    username = body.get("username", "")\n'
    '    password = body.get("password", "")\n'
    "    db = get_db()\n"
    "    row = db.execute(\n"
    '        "SELECT * FROM users WHERE username = ? AND password = ?",\n'
    "        (username, password),\n"
    "    ).fetchone()\n"
    "    if row is None:\n"
    '        return jsonify({"error": "invalid credentials"}), 401\n'
    '    return jsonify({"token": encode_token(row["id"]), '
    '"username": row["username"]})\n'
)

_ORIGINAL_GET_NOTE_HANDLER = (
    '@app.get("/notes/<int:note_id>")\n'
    "def get_note(note_id: int):\n"
    "    auth_id = get_auth_user_id()\n"
    "    if auth_id is None:\n"
    '        return jsonify({"error": "unauthorized"}), 401\n\n'
    "    db = get_db()\n"
    '    row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()\n'
    "    if row is None:\n"
    '        return jsonify({"error": "not found"}), 404\n\n'
    "    return jsonify({\n"
    '        "id": row["id"],\n'
    '        "owner_id": row["owner_id"],\n'
    '        "title": row["title"],\n'
    '        "content": row["content"],\n'
    "    })\n"
)

_PATCHED_GET_NOTE_HANDLER = (
    '@app.get("/notes/<int:note_id>")\n'
    "def get_note(note_id: int):\n"
    "    auth_id = get_auth_user_id()\n"
    "    if auth_id is None:\n"
    '        return jsonify({"error": "unauthorized"}), 401\n'
    "    db = get_db()\n"
    '    row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()\n'
    "    if row is None:\n"
    '        return jsonify({"error": "not found"}), 404\n'
    '    if row["owner_id"] != auth_id:\n'
    '        return jsonify({"error": "forbidden"}), 403\n'
    "    return jsonify({\n"
    '        "id": row["id"],\n'
    '        "owner_id": row["owner_id"],\n'
    '        "title": row["title"],\n'
    '        "content": row["content"],\n'
    "    })\n"
)

_ORIGINAL_RESET_HANDLER = (
    '@app.post("/reset")\n'
    "def reset():\n"
    "    init_db()\n"
    '    return jsonify({"status": "reset"})\n'
)

_PATCHED_RESET_HANDLER = (
    '@app.post("/reset")\n'
    "def reset():\n"
    "    auth_id = get_auth_user_id()\n"
    "    db = get_db()\n"
    '    row = db.execute("SELECT role FROM users WHERE id = ?", (auth_id,)).fetchone()\n'
    '    if row is None or row["role"] != "admin":\n'
    '        return jsonify({"error": "unauthorized"}), 401\n'
    "    init_db()\n"
    '    return jsonify({"status": "reset"})\n'
)


_MOCK_ATTACKER: dict[str, dict] = {
    "sqli": {
        "method": "POST",
        "url": "/login",
        "headers": {"Content-Type": "application/json"},
        "body": {"username": "' OR '1'='1' --", "password": "anything"},
        "agent_reasoning": {
            "narration": (
                "Spotted an unsanitised input. Dropping a classic OR "
                "bypass — if this works, we're in without knowing any "
                "password."
            ),
            "technical": (
                "The login query is built with an f-string: "
                "`f\"SELECT * FROM users WHERE username = '{username}' AND "
                "password = '{password}'\"`. Injecting `' OR '1'='1' --` "
                "into the username field closes the string early, forces "
                "the WHERE clause to always evaluate true, and comments "
                "out the password check entirely."
            ),
        },
    },
    "idor": {
        "method": "GET",
        "url": "/notes/2",
        "headers": {"Authorization": "Bearer Mg=="},
        "body": None,
        "agent_reasoning": {
            "narration": (
                "Bob's token works, but nobody's checking whose note this "
                "actually is. Requesting annie's note by ID directly."
            ),
            "technical": (
                "`GET /notes/<id>` fetches the note by primary key with no "
                "comparison against the authenticated user's ID. Bob's own "
                "token (user_id=2) authenticates the request, but the "
                "handler never checks `note.owner_id == auth_id`, so any "
                "authenticated user can read any note ID."
            ),
        },
    },
    "missing_auth": {
        "method": "POST",
        "url": "/reset",
        "headers": {},
        "body": None,
        "agent_reasoning": {
            "narration": (
                "No Authorization header, no problem — this endpoint isn't "
                "checking for one at all."
            ),
            "technical": (
                "`POST /reset` calls `init_db()` directly with no call to "
                "`get_auth_user_id()` and no role check, so an "
                "unauthenticated request wipes and reseeds the entire "
                "database."
            ),
        },
    },
}


_MOCK_DEFENDER_BY_URL_FRAGMENT: list[tuple[str, dict]] = [
    (
        "/login",
        {
            "_original_handler": _ORIGINAL_LOGIN_HANDLER,
            "_patched_handler": _PATCHED_LOGIN_HANDLER,
            "agent_reasoning": {
                "narration": (
                    "There's a quote character in the username field. The "
                    "query is built with string concatenation. That's the "
                    "entry point. Closing it now."
                ),
                "technical": (
                    "The request body contained an unescaped single quote "
                    "in the username field, and the response returned a "
                    "valid token despite no matching credentials — that "
                    "combination only makes sense if the WHERE clause was "
                    "manipulated. The query was built via f-string "
                    "interpolation; switched to a parameterised query with "
                    "placeholders so user input can never alter the SQL "
                    "structure."
                ),
            },
        },
    ),
    (
        "/notes/",
        {
            "_original_handler": _ORIGINAL_GET_NOTE_HANDLER,
            "_patched_handler": _PATCHED_GET_NOTE_HANDLER,
            "agent_reasoning": {
                "narration": (
                    "The request carried a valid token, and the response "
                    "handed back a note anyway — but the token and the "
                    "note's owner don't match. Adding the ownership check "
                    "that was never there."
                ),
                "technical": (
                    "The authenticated user ID from the request's bearer "
                    "token does not match the `owner_id` field on the "
                    "returned note, yet the response was a 200 with full "
                    "content. The handler fetched the note by ID alone with "
                    "no comparison to the caller's identity. Added a check "
                    "that rejects the request with 403 unless "
                    "`row['owner_id'] == auth_id`."
                ),
            },
        },
    ),
]

_MOCK_DEFENDER_DEFAULT: dict = {
    "_original_handler": _ORIGINAL_RESET_HANDLER,
    "_patched_handler": _PATCHED_RESET_HANDLER,
    "agent_reasoning": {
        "narration": (
            "No Authorization header on the request, and the response "
            "went ahead and reset the database anyway. That's the entire "
            "problem — adding the check that was missing."
        ),
        "technical": (
            "The request contained no Authorization header at all, and the "
            "response still returned a successful reset. The handler never "
            "calls `get_auth_user_id()` or checks role. Added an admin-role "
            "check before allowing the reset to proceed."
        ),
    },
}


def _mock_attacker_response(vulnerability_class: str) -> dict:
    if vulnerability_class not in _MOCK_ATTACKER:
        raise ValueError(f"no mock attacker response for {vulnerability_class!r}")
    return _MOCK_ATTACKER[vulnerability_class]


def _mock_defender_response(request: dict, response: dict, source_code: str) -> dict:
    url = request.get("url", "")
    mock = _MOCK_DEFENDER_DEFAULT
    for fragment, candidate in _MOCK_DEFENDER_BY_URL_FRAGMENT:
        if fragment in url:
            mock = candidate
            break

    patched_source = _patch_handler(
        source_code, mock["_original_handler"], mock["_patched_handler"]
    )
    return {"patched_source": patched_source, "agent_reasoning": mock["agent_reasoning"]}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def attacker_agent(
    app_url: str,
    vulnerability_class: str,
    source_code: str,
    on_narration_chunk: Callable[[str], None],
    on_raw_chunk: Callable[[str], None] | None = None,
    mock: bool = False,
) -> tuple[dict, dict | None]:
    """Returns ({method, url, headers, body, agent_reasoning}, usage).

    Scoped to exploit only vulnerability_class. In real mode, on_raw_chunk
    (if given) receives each raw SSE text delta as the model streams its
    JSON response; usage is the real token-count dict from that call. In
    mock mode on_raw_chunk is ignored (there is no real stream to replay)
    and usage is None. Replays narration char-by-char through
    on_narration_chunk once the full response has been parsed, in both modes.
    """
    if mock:
        result = _mock_attacker_response(vulnerability_class)
        usage = None
    else:
        messages = _build_attacker_prompt(app_url, vulnerability_class, source_code)
        result, usage = _call_model_with_retry(messages, on_raw_chunk or (lambda _chunk: None))

    _replay_narration(result["agent_reasoning"]["narration"], on_narration_chunk)
    return result, usage


def defender_agent(
    request: dict,
    response: dict,
    source_code: str,
    on_narration_chunk: Callable[[str], None],
    on_raw_chunk: Callable[[str], None] | None = None,
    mock: bool = False,
) -> tuple[dict, dict | None]:
    """Returns ({patched_source, agent_reasoning}, usage).

    The vulnerability class is never named in the prompt — the defender
    derives what happened from request, response, and source alone. See
    attacker_agent for the on_raw_chunk / usage / mock-mode contract.
    """
    if mock:
        result = _mock_defender_response(request, response, source_code)
        usage = None
    else:
        messages = _build_defender_prompt(request, response, source_code)
        result, usage = _call_model_with_retry(messages, on_raw_chunk or (lambda _chunk: None))

    _replay_narration(result["agent_reasoning"]["narration"], on_narration_chunk)
    return result, usage
