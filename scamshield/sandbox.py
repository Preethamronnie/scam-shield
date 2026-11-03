"""Run file inspection in a separate, disposable process.

Uploaded PDFs, APKs and emails may be crafted to crash or hang a parser, or
to exhaust memory. Each inspection therefore runs as its own short-lived
Python process (scamshield/sandbox_worker.py):

  * the file's bytes go in on stdin, and only plain JSON comes back out;
  * a time limit: if it takes too long, the process is killed;
  * a memory limit (on Linux, which Streamlit Cloud uses), so the child
    can't take down the app by allocating huge amounts of memory;
  * a fresh interpreter, so it shares no threads, sockets or state with the
    web server, and nothing in the file is ever executed or opened.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

TIMEOUT_SECONDS = 20
MEMORY_LIMIT_MB = 768
KINDS = ("pdf", "apk", "email", "html")
_ROOT = Path(__file__).resolve().parents[1]


class SandboxError(RuntimeError):
    """The inspection failed, timed out or ran out of memory. Safe to show."""


def _limits():   # runs in the child just before it starts (Unix only)
    try:
        import resource
        limit = MEMORY_LIMIT_MB * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))   # no crash dumps of user files
    except Exception:
        pass


def run_isolated(kind: str, data: bytes, timeout: float = TIMEOUT_SECONDS, arg: str = "") -> dict:
    if kind not in KINDS:
        raise ValueError(kind)
    # A minimal environment: no API keys or other secrets reach the inspector. The
    # Windows variables let Python start and find packages installed with --user.
    env = {"PYTHONPATH": str(_ROOT), "PYTHONDONTWRITEBYTECODE": "1"}
    for var in ("PATH", "SYSTEMROOT", "APPDATA", "LOCALAPPDATA", "USERPROFILE", "HOME", "TEMP", "TMP", "PYTHONHOME"):
        if os.environ.get(var):
            env[var] = os.environ[var]
    try:
        proc = subprocess.run([sys.executable, "-m", "scamshield.sandbox_worker", kind, arg], input=data,
                              capture_output=True, timeout=timeout, env=env, cwd=str(_ROOT),
                              preexec_fn=_limits if os.name == "posix" else None)
    except subprocess.TimeoutExpired:
        raise SandboxError("Inspecting the file took too long, so it was stopped.")
    try:
        result = json.loads(proc.stdout.decode("utf-8"))
    except Exception:
        raise SandboxError("The file couldn't be inspected safely (the inspector stopped unexpectedly).")
    if result.get("status") != "ok":
        raise SandboxError(result.get("error", "The file couldn't be read."))
    return result["value"]
