"""
Attack on Sandbox — FastAPI dashboard server.

Replaces the old Streamlit app.py. Serves a single-page HTML dashboard
(dashboard/static/index.html) and three API routes:

  GET  /events/stream   — SSE stream that tails events.json
  POST /control/run     — kill any running orchestrator, reset, start fresh
  POST /control/abort   — kill any running orchestrator, reset state
  GET  /control/status  — current orchestrator + events state

The orchestrator is completely unchanged — it still writes events.json.
The browser JS polls /events/stream and patches its own DOM; no server-side
rendering, no session state, no reruns.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import AsyncGenerator

import psutil
from fastapi import FastAPI
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

ROOT             = Path(__file__).resolve().parent.parent
EVENTS_PATH      = ROOT / "events.json"
TARGET_APP_SRC   = ROOT / "target-app" / "app.py"
TARGET_APP_DB    = ROOT / "target-app" / "notes.db"
ORCHESTRATOR     = ROOT / "orchestrator" / "main.py"
STATIC_DIR       = Path(__file__).parent / "static"

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI()

# ---------------------------------------------------------------------------
# Orchestrator process management
# ---------------------------------------------------------------------------

_proc: subprocess.Popen | None = None


def _is_running() -> bool:
    return _proc is not None and _proc.poll() is None


def _kill_all_orchestrators() -> None:
    global _proc
    if _proc is not None and _proc.poll() is None:
        _proc.terminate()
        try:
            _proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _proc.kill()
            _proc.wait(timeout=3)
    _proc = None
    try:
        for p in psutil.process_iter(["pid", "cmdline"]):
            cmdline = " ".join(p.info.get("cmdline") or [])
            if "orchestrator" in cmdline and "main.py" in cmdline:
                p.terminate()
    except Exception:
        pass


def _reset_state() -> None:
    """Delete events + DB, restore vulnerable source via git."""
    _kill_all_orchestrators()
    for path in (EVENTS_PATH,):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
    subprocess.run(
        ["git", "checkout", "--", str(TARGET_APP_SRC)],
        cwd=str(ROOT),
        check=False,
    )
    try:
        TARGET_APP_DB.unlink(missing_ok=True)
    except OSError:
        pass


def _start_orchestrator() -> None:
    global _proc
    _proc = subprocess.Popen(
        [sys.executable, str(ORCHESTRATOR)],
        cwd=str(ROOT),
    )

# ---------------------------------------------------------------------------
# SSE — tail events.json and stream new lines to browser
# ---------------------------------------------------------------------------

async def _event_generator() -> AsyncGenerator[str, None]:
    cursor = 0
    # Send a heartbeat comment every 15s so proxies don't close the connection
    while True:
        try:
            if EVENTS_PATH.exists():
                with EVENTS_PATH.open("rb") as fh:
                    fh.seek(cursor)
                    chunk = fh.read()
                if chunk:
                    cursor += len(chunk)
                    for line in chunk.decode("utf-8", errors="replace").splitlines():
                        line = line.strip()
                        if line:
                            yield f"data: {line}\n\n"
            else:
                # File was deleted (reset) — tell browser to clear its state
                if cursor > 0:
                    cursor = 0
                    yield "data: {\"type\":\"_reset\"}\n\n"
        except Exception:
            pass
        await asyncio.sleep(0.12)   # 120ms — same cadence as the old JS poll


@app.get("/events/stream")
async def events_stream():
    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )

# ---------------------------------------------------------------------------
# Control routes
# ---------------------------------------------------------------------------

@app.post("/control/run")
async def control_run():
    _reset_state()
    await asyncio.sleep(0.2)   # let file deletions settle
    _start_orchestrator()
    return JSONResponse({"status": "started"})


@app.post("/control/abort")
async def control_abort():
    _reset_state()
    return JSONResponse({"status": "aborted"})


@app.get("/control/status")
async def control_status():
    return JSONResponse({
        "running": _is_running(),
        "events_exist": EVENTS_PATH.exists(),
    })

# ---------------------------------------------------------------------------
# Static files — index.html + any assets
# Mounted LAST so API routes take priority
# ---------------------------------------------------------------------------

STATIC_DIR.mkdir(exist_ok=True)
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8600))
    uvicorn.run("dashboard.server:app", host="0.0.0.0", port=port, reload=False)
