"""
Attack on Sandbox — pre-warm script (Phase 5).

Sandbox creation + app deployment takes 10-30 seconds. Running that inside
main.py would create dead air at the very start of the demo, so it's
extracted here to run during the presenter's verbal intro instead:

    python orchestrator/setup.py   # run during the intro
    python orchestrator/main.py    # iteration loop starts immediately

Writes the sandbox ID to orchestrator/.sandbox_id so main.py picks up the
already-warm sandbox instead of creating a second one.
"""

from __future__ import annotations

import sys
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

load_dotenv()

from orchestrator.load_daytona_env import inject_env as inject_daytona_env

inject_daytona_env()

from orchestrator.main import SANDBOX_ID_PATH, start_sandbox


def main() -> None:
    sandbox_id, url = start_sandbox()
    SANDBOX_ID_PATH.write_text(sandbox_id, encoding="utf-8")
    print(f"Sandbox ready: {sandbox_id}")
    print(f"URL: {url}")


if __name__ == "__main__":
    main()
