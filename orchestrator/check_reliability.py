"""
One-time manual check: does deepseek-v4-flash reliably return parseable
JSON in JSON mode? Not a pytest file, not auto-run, makes real paid API
calls.

Usage:
    python orchestrator/check_reliability.py

Requires AIAND_API_KEY (and optionally AIAND_BASE_URL, AIAND_MODEL) set
in the environment.
"""

from __future__ import annotations

import json
import os
import sys

from openai import OpenAI

_ATTEMPTS = 10
_MAX_ALLOWED_FAILURES = 1


def _build_test_messages() -> list[dict]:
    return [
        {
            "role": "system",
            "content": (
                "Respond with a single JSON object and nothing else, with "
                'exactly these keys: {"status": "ok", "count": <integer>}. '
                "Pick any integer for count."
            ),
        },
        {"role": "user", "content": "Return the JSON object now."},
    ]


def _run_once(client: OpenAI, model: str) -> tuple[bool, str]:
    try:
        response = client.chat.completions.create(
            model=model,
            messages=_build_test_messages(),
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content
        json.loads(content)
        return True, content
    except Exception as exc:  # noqa: BLE001 - this script exists to surface any failure
        return False, repr(exc)


def main() -> None:
    api_key = os.environ.get("AIAND_API_KEY")
    if not api_key:
        print("AIAND_API_KEY is not set. Export it before running this script.")
        sys.exit(1)

    base_url = os.environ.get("AIAND_BASE_URL", "https://api.aiand.com/v1")
    model = os.environ.get("AIAND_MODEL", "deepseek-ai/deepseek-v4-flash")
    client = OpenAI(api_key=api_key, base_url=base_url)

    print(f"Checking JSON-mode reliability for model={model!r} ({_ATTEMPTS} attempts)...\n")

    failures = 0
    for i in range(1, _ATTEMPTS + 1):
        ok, detail = _run_once(client, model)
        if ok:
            print(f"attempt {i}/{_ATTEMPTS}: OK")
        else:
            failures += 1
            print(f"attempt {i}/{_ATTEMPTS}: FAILED - {detail}")

    passed = _ATTEMPTS - failures
    print(f"\n{passed}/{_ATTEMPTS} parsed successfully")

    if failures > _MAX_ALLOWED_FAILURES:
        print(
            f"More than {_MAX_ALLOWED_FAILURES} failure(s) — consider switching "
            "AIAND_MODEL to deepseek-ai/deepseek-v4-pro in .env and re-running."
        )
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
