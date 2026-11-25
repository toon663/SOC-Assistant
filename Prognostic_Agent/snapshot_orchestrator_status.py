"""Read-only local status snapshot for use before a backend restart."""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
from urllib.parse import urlsplit
from urllib.request import build_opener, ProxyHandler, HTTPRedirectHandler, Request
import uuid

from .contracts import utc_text
from .private_paths import PRIVATE_DIR, private_path, write_private


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Status redirects are refused")


def snapshot_status(*, url="http://localhost:8000/orchestrator/status", output_dir=None, opener=None):
    parsed = urlsplit(url)
    local = parsed.hostname == "localhost"
    if not local:
        try:
            local = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            local = False
    if (parsed.scheme != "http" or not local or parsed.username or parsed.password or
        parsed.path != "/orchestrator/status" or parsed.query or parsed.fragment):
        raise ValueError("Only the unauthenticated loopback status endpoint is allowed")
    directory = private_path(output_dir or PRIVATE_DIR / "status-snapshots")
    opener = opener or build_opener(ProxyHandler({}), NoRedirect())
    with opener.open(Request(url, method="GET", headers={"Accept":"application/json"}), timeout=3) as response:
        raw = response.read(65537)
    if len(raw) > 65536:
        raise ValueError("Status response too large")
    data = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(data, dict) or type(data.get("model_loaded")) is not bool:
        raise ValueError("Invalid status response")
    now = datetime.now(timezone.utc)
    data["snapshot_metadata"] = {"captured_at":utc_text(now), "method":"GET", "endpoint":"/orchestrator/status"}
    path = directory / ("status_"+now.strftime("%Y%m%dT%H%M%S%fZ")+"_"+uuid.uuid4().hex[:8]+".json")
    write_private(path, data)
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://localhost:8000/orchestrator/status")
    parser.add_argument("--output-dir")
    args = parser.parse_args(argv)
    try:
        path = snapshot_status(url=args.url, output_dir=args.output_dir)
    except Exception:
        parser.error("Status snapshot failed; no backend state was changed")
    print(json.dumps({"snapshot_file":str(path.relative_to(PRIVATE_DIR.parent)), "method":"GET"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
