"""Contain real-machine inputs and outputs below the ignored private directory."""

import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlparse

from .config import AGENT_DIR

PRIVATE_DIR = AGENT_DIR / "private"


def private_path(value):
    path = Path(value).resolve()
    if not path.is_relative_to(PRIVATE_DIR.resolve()) or path == PRIVATE_DIR.resolve():
        raise ValueError("Real shadow-run artifacts must stay below Prognostic_Agent/private")
    return path


def write_private(path, value):
    path = private_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")
    return path


def confine_private_runtime():
    """CLI audit boundary: private writes/SQLite only; no network connections."""
    sys.dont_write_bytecode = True

    def check(value):
        if isinstance(value, (str, bytes, os.PathLike)):
            value = os.fsdecode(value)
            if value == ":memory:":
                return
            if value.startswith("file:"):
                value = unquote(urlparse(value).path)
                if os.name == "nt" and re.match(r"^/[A-Za-z]:", value):
                    value = value[1:]
            private_path(value)

    def audit(event, args):
        if event == "open":
            path, mode, flags = args
            if (mode and any(char in mode for char in "wax+")) or flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                check(path)
        elif event in {"os.mkdir", "os.remove", "os.rmdir", "os.chmod", "os.utime", "sqlite3.connect"}:
            check(args[0])
        elif event in {"os.rename", "os.link", "os.symlink"}:
            check(args[0])
            check(args[1])
        elif event == "socket.connect":
            raise PermissionError("Re-triage replay has no network access")

    sys.addaudithook(audit)
