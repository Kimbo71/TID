#!/usr/bin/env python3
"""Helper script to compile tid_fail.c with the Napatech SDK if available."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "tid_fail.c"
OUT = ROOT / "tid_fail"

if not SRC.exists():
    sys.stderr.write("Error: tid_fail.c not found next to this script.\n")
    sys.exit(1)

cc = os.environ.get("CC", "gcc")
cflags = os.environ.get("CFLAGS", "-O2 -g -pthread").split()

nt_include = os.environ.get("NT_INCLUDE", "").strip()
if not nt_include:
    for candidate in (
        "/opt/napatech3/include",
        "/opt/napatech4/include",
        "/usr/local/include",
        "/usr/include",
    ):
        if Path(candidate, "nt.h").exists():
            nt_include = candidate
            break

if not nt_include:
    sys.stderr.write(
        "Error: Could not locate nt.h. Install the Napatech SDK and set NT_INCLUDE "
        "or place the headers in a standard include directory.\n"
    )
    sys.exit(2)

nt_lib = os.environ.get("NT_LIB", "").strip()
if not nt_lib:
    for candidate in (
        "/opt/napatech3/lib64",
        "/opt/napatech4/lib64",
        "/usr/local/lib",
        "/usr/lib",
    ):
        if any(Path(candidate, libname).exists() for libname in ("libntapi.so", "libntapi.a")):
            nt_lib = candidate
            break

if not nt_lib:
    sys.stderr.write(
        "Error: Could not locate libntapi.{so,a}. Install the Napatech SDK and set NT_LIB "
        "or place the library in a standard library directory.\n"
    )
    sys.exit(3)

cmd = [
    cc,
    *cflags,
    str(SRC),
    f"-I{nt_include}",
    f"-L{nt_lib}",
    "-lpcap",
    "-lntapi",
    "-o",
    str(OUT),
]

sys.stderr.write("Running: {}\n".format(" ".join(cmd)))

try:
    subprocess.run(cmd, check=True)
except (OSError, subprocess.CalledProcessError) as exc:
    sys.stderr.write(f"Compilation failed: {exc}\n")
    sys.exit(4 if isinstance(exc, OSError) else exc.returncode)

if not os.access(OUT, os.X_OK):
    OUT.chmod(0o755)

print(f"Built {OUT}")
