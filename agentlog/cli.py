from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import tempfile
import urllib.request

from .catalog import load_catalog
from .funnel import rung0_status
from .server import AgentLogServer
from .store import Store
from .vault import FileVault
from .verify import SocketResolver, load_ranges

ROOT = Path(__file__).resolve().parent.parent


def paths():
    data = Path(os.environ.get("AGENTLOG_DATA_DIR", ROOT / "runtime"))
    data.mkdir(parents=True, exist_ok=True)
    return data


def _positive(value):
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def _proxy_network(value):
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid trusted-proxy CIDR: {value}") from exc


def trusted_proxies(cli_values=(), environment=None):
    """Combine repeatable CLI CIDRs with AGENTLOG_TRUSTED_PROXIES."""
    environment = os.environ if environment is None else environment
    result = list(cli_values or ())
    for value in environment.get("AGENTLOG_TRUSTED_PROXIES", "").split(","):
        if value.strip():
            result.append(_proxy_network(value))
    return result


def refresh_ranges(catalog, destination):
    previous = load_ranges(destination)
    result = {"agents": dict(previous.get("agents", {}))}
    now = datetime.now(timezone.utc).isoformat()
    updated = 0
    for entry in catalog:
        url = entry["verify"].get("ranges_url")
        if entry["verify"]["method"] != "ip_ranges" or not url or not url.startswith("https://"):
            continue
        try:
            with urllib.request.urlopen(url, timeout=15) as response:
                raw = response.read(10 * 1024 * 1024 + 1)
            if len(raw) > 10 * 1024 * 1024:
                continue
            ranges = []
            try:
                obj = json.loads(raw)
                values = obj.get("prefixes", obj.get("ranges", [])) if isinstance(obj, dict) else []
                for value in values:
                    candidate = value if isinstance(value, str) else value.get("ipv4Prefix") or value.get("ipv6Prefix") or value.get("prefix") if isinstance(value, dict) else None
                    if candidate:
                        ranges.append(str(ipaddress.ip_network(candidate, strict=False)))
            except (UnicodeDecodeError, json.JSONDecodeError):
                for line in raw.decode("utf-8", "replace").splitlines():
                    line = line.strip().split("#", 1)[0].strip()
                    if line:
                        ranges.append(str(ipaddress.ip_network(line, strict=False)))
            ranges = sorted(set(ranges))
            if not ranges:
                continue
            result["agents"][entry["id"]] = {"fetched_at": now, "ranges": ranges}
            updated += 1
        except (OSError, ValueError, TypeError):
            continue
    if not updated:
        return 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=destination.parent, prefix=".ranges-", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as target:
            json.dump(result, target, indent=2)
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return updated


def main(argv=None):
    parser = argparse.ArgumentParser(prog="agentlog")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument(
        "--trusted-proxy",
        action="append",
        default=[],
        type=_proxy_network,
        metavar="CIDR",
        help="trust X-Forwarded-For only from this proxy CIDR; repeat as needed",
    )
    sub.add_parser("refresh-ranges")
    sub.add_parser("rung0-status")
    sub.add_parser("purge")
    paid = sub.add_parser("record-payment")
    paid.add_argument("--count", type=_positive, required=True)
    paid.add_argument("--idempotency-key", required=True)
    args = parser.parse_args(argv)
    data = paths()
    store = Store(data / "agentlog.sqlite3")
    vault = FileVault(data / "vault.jsonl")
    catalog = load_catalog()
    if args.command == "refresh-ranges":
        print("range sources updated:", refresh_ranges(catalog, data / "ranges.json"))
    elif args.command == "rung0-status":
        status = rung0_status(store)
        for number, passed in enumerate(status.pop("conditions"), 1):
            print(f"{number}: {'PASS' if passed else 'FAIL'}")
        print(json.dumps(status, indent=2))
    elif args.command == "record-payment":
        for number in range(args.count):
            store.event("payment", dedupe_key=f"{args.idempotency_key}:{number}")
    elif args.command == "purge":
        print("reports/events/vault purged:", *store.purge(), vault.purge())
    else:
        secret = os.environ.get("AGENTLOG_SECRET")
        if not secret or len(secret) < 32:
            parser.error("AGENTLOG_SECRET must be set to at least 32 characters")
        try:
            proxies = trusted_proxies(args.trusted_proxy)
        except argparse.ArgumentTypeError as exc:
            parser.error(str(exc))
        snapshot = load_ranges(data / "ranges.json")
        server = AgentLogServer(
            (args.host, args.port), store, catalog, snapshot, SocketResolver(),
            ROOT / "static",
            int(os.environ.get("AGENTLOG_MAX_UPLOAD_MB", "50")) * 1024 * 1024,
            os.environ.get("AGENTLOG_PREORDER_URL", "/"), vault, secret,
            int(os.environ.get("AGENTLOG_UPLOAD_CONCURRENCY", "2")),
            trusted_proxies=proxies,
        )
        print(f"AgentLog listening on http://{args.host}:{args.port}")
        server.serve_forever()


if __name__ == "__main__":
    main()
