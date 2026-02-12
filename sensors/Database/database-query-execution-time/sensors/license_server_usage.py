from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from dateutil import parser as date_parser

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent))
    from prtg_helpers import build_channel, print_prtg_error, print_prtg_results
else:
    from .prtg_helpers import build_channel, print_prtg_error, print_prtg_results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Monitor license server pool usage for PRTG.")
    parser.add_argument("--url", required=True, help="License server API endpoint returning JSON.")
    parser.add_argument("--api-key", help="Optional API key placed into the Authorization header.")
    parser.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds.")
    parser.add_argument("--verify", action="store_true", default=True, help="Verify TLS certificates (default).")
    parser.add_argument("--no-verify", dest="verify", action="store_false", help="Disable TLS verification.")
    return parser.parse_args()


def extract_number(payload: dict[str, Any], *keys: str) -> float:
    for key in keys:
        if key in payload:
            value = payload[key]
            if isinstance(value, (int, float)):
                return float(value)
    raise KeyError(f"Missing numeric field (tried {', '.join(keys)})")


def parse_expiration(payload: dict[str, Any]) -> float:
    for key in ("expires_on", "expires", "expiry", "expiration"):
        value = payload.get(key)
        if not value:
            continue
        dt = date_parser.parse(str(value))
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        delta = dt - now
        return max(delta.total_seconds() / 86400, 0.0)
    raise KeyError("Missing expiration timestamp")


def main() -> None:
    args = parse_args()
    headers = {"Accept": "application/json"}
    if args.api_key:
        headers["Authorization"] = f"Bearer {args.api_key}"

    try:
        resp = requests.get(args.url, headers=headers, timeout=args.timeout, verify=args.verify)
    except requests.RequestException as exc:
        print_prtg_error(f"Request failed: {exc}")
        return

    if resp.status_code >= 400:
        print_prtg_error(f"API returned {resp.status_code}")
        return

    try:
        payload = resp.json()
    except ValueError as exc:
        print_prtg_error(f"Invalid JSON: {exc}")
        return

    try:
        total = extract_number(payload, "total", "total_licenses", "max", "capacity")
        used = extract_number(payload, "used", "in_use", "consumed")
        days_left = parse_expiration(payload)
    except KeyError as exc:
        print_prtg_error(str(exc))
        return

    if total <= 0:
        print_prtg_error("Total license count is zero or negative")
        return

    remaining = max(total - used, 0.0)
    usage_pct = min((used / total) * 100, 100.0)

    results = [
        build_channel("Licenses Used", round(used, 2), "Count"),
        build_channel("Licenses Remaining", round(remaining, 2), "Count"),
        build_channel("License Pool Usage", round(usage_pct, 2), "Percent"),
        build_channel("Days Until Expiration", round(days_left, 2), "TimeDays"),
    ]
    print_prtg_results(results)


if __name__ == "__main__":
    main()
