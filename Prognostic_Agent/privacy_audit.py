"""Check public test/report areas for identities from a local raw export.

Never prints identity values or matching content. Audit artifacts stay private.
"""

import argparse
from contextlib import closing
import json
from pathlib import Path
import re
import sqlite3
from tempfile import TemporaryDirectory
import uuid

from .config import AGENT_DIR
from .private_paths import write_private, private_path

BUILTINS = {"administrator", "guest", "defaultaccount", "wdagutilityaccount", "defaultuser0",
            "system", "local service", "network service", "anonymous logon", "-", "unknown"}


def identity_pattern(token):
    if token == "admin":
        # The privilege enum/prose "admin" is not an identity disclosure. Still
        # detect this common account name in explicit identity contexts.
        return re.compile(r'(?:user:admin(?![\w-])|\\admin(?![\w-])|'
                          r'(?:user(?:name|_id)?|source_identifier)["\x27]?\s*[:=]\s*["\x27]?admin(?![\w-])|'
                          r'account\s+name\s*:\s*admin(?![\w-]))', re.I)
    return re.compile(r"(?<![\w-])" + re.escape(token) + r"(?![\w-])", re.I)


def audit_identities(raw_export, *, root=AGENT_DIR, extra_identities=()):
    raw = json.loads(Path(raw_export).read_text(encoding="utf-8-sig"))
    tokens = {raw["host"]["hostname"].casefold()}
    accounts = raw.get("accounts") or []
    if isinstance(accounts, dict):
        accounts = [accounts]
    tokens.update(row["name"].casefold() for row in accounts if isinstance(row.get("name"), str)
                  and row["name"].casefold() not in BUILTINS)
    for value in extra_identities:
        if not isinstance(value, str) or not value.strip():
            continue
        normalized = value.strip().casefold()
        if normalized not in BUILTINS:
            tokens.add(normalized)
        bare = normalized.rsplit("\\", 1)[-1]
        if bare not in BUILTINS:
            tokens.add(bare)
    patterns = [identity_pattern(token) for token in tokens if token]
    areas = [root / "forecasts", root / "README.md", root / "tests", root / "examples", root / "assets"]
    files = [path for area in areas if area.exists() for path in ([area] if area.is_file() else area.rglob("*"))
             if path.is_file() and "__pycache__" not in path.parts]
    matches, unreadable = [], []
    for path in files:
        try:
            content = path.read_bytes().decode("utf-8-sig", errors="replace")
            if any(pattern.search(content) for pattern in patterns):
                matches.append(str(path.relative_to(root)))
        except OSError:
            unreadable.append(str(path.relative_to(root)))
    return {"schema_version": 1, "environment": "test", "clean": not matches and not unreadable,
            "files_checked": len(files), "identity_token_count": len(tokens), "matching_files": sorted(matches),
            "unreadable_files": sorted(unreadable),
            "scope": "Local hostname, non-built-in exported accounts and optional source-event host/user identities; forecasts, README, tests, examples and assets. Built-in/service names excluded; the ambiguous admin role word requires explicit identity context. Token matching is not a general personal-data detector."}


def event_identities(source_db, output_directory):
    """Read backend identities through a disposable private snapshot only."""
    from .shadow_source import snapshot_source
    result = set()
    with TemporaryDirectory(prefix="privacy-source-", dir=output_directory) as work:
        snapshot = snapshot_source(source_db, Path(work) / "snapshot")
        with closing(sqlite3.connect(Path(snapshot["snapshot_path"]).as_uri() + "?mode=ro&immutable=1", uri=True)) as connection:
            connection.execute("PRAGMA query_only=ON")
            for row in connection.execute("SELECT payload FROM incidents"):
                document = json.loads(row[0])
                if isinstance(document, dict):
                    for event in document.get("events") or []:
                        if isinstance(event, dict):
                            result.update(value for value in (event.get("host"), event.get("user")) if isinstance(value, str))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-export", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--environment", choices=["test"], required=True)
    parser.add_argument("--backend-db", help="Also audit identities from stored incidents, via read-only source snapshot")
    args = parser.parse_args(argv)
    destination = private_path(args.output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    identities = event_identities(args.backend_db, destination) if args.backend_db else ()
    result = audit_identities(private_path(args.raw_export), extra_identities=identities)
    write_private(destination / ("privacy_audit_" + uuid.uuid4().hex[:8] + ".json"), result)
    print(json.dumps(result, indent=2))
    return 0 if result["clean"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
