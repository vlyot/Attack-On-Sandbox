"""
Tests for the streaming-related event constructors in orchestrator/events.py.

The pre-existing event constructors (sandbox_ready, attack_sent, etc.) are
already exercised indirectly through test_main.py's run_iteration test; this
file covers only the two constructors added for real SSE streaming.
"""

from orchestrator.events import make_llm_usage, make_stream_chunk


def test_make_stream_chunk_shape():
    event = make_stream_chunk("attacker", '{"method": "POST"', 1, "sqli")
    assert event["type"] == "stream_chunk"
    assert event["iteration"] == 1
    assert event["vulnerability_class"] == "sqli"
    assert event["payload"] == {"agent": "attacker", "chunk": '{"method": "POST"'}


def test_make_stream_chunk_allows_multi_character_chunk():
    # Unlike narration_chunk, chunk length is unconstrained.
    event = make_stream_chunk("defender", "a much longer delta fragment", 2, "idor")
    assert event["payload"]["chunk"] == "a much longer delta fragment"


def test_make_stream_chunk_allows_empty_chunk():
    event = make_stream_chunk("attacker", "", 1, "sqli")
    assert event["payload"]["chunk"] == ""


def test_make_llm_usage_shape():
    event = make_llm_usage("attacker", 120, 45, 165, 1, "sqli")
    assert event["type"] == "llm_usage"
    assert event["iteration"] == 1
    assert event["vulnerability_class"] == "sqli"
    assert event["payload"] == {
        "agent": "attacker",
        "prompt_tokens": 120,
        "completion_tokens": 45,
        "total_tokens": 165,
    }
