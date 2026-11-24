"""One-shot offline inventory import. No watcher or AD adapter."""

import argparse
import json
from pathlib import Path

from .importers.core import import_inventory


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", choices=["local_export"], default="local_export")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--environment", choices=["test", "demo", "production"], required=True)
    args = parser.parse_args(argv)
    try:
        result = import_inventory(args.input, adapter_name=args.adapter, environment=args.environment, output_root=args.output_root)
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({"schema_version": 1, "response_type": "inventory_import_error", "environment": args.environment,
                          "reason": "source_or_output_error", "detail": str(exc)}, indent=2))
        return 1
    print(json.dumps(result, indent=2))
    return 0 if result["publishable"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
