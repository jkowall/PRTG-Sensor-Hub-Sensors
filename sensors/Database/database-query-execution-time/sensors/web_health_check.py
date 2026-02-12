from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any, Dict

import requests

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent))
    from prtg_helpers import build_channel, print_prtg_error, print_prtg_results
else:
    from .prtg_helpers import build_channel, print_prtg_error, print_prtg_results


HEALTHY_STATES = {"up", "ok", "pass", "healthy", "available"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check application /health endpoints for PRTG.")
    parser.add_argument("--url", required=True, help="Full URL to the health endpoint.")
    parser.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds.")
    parser.add_argument("--allow-status", action="append", default=[], help="Additional strings treated as healthy.")
    parser.add_argument("--verify", action="store_true", default=True, help="Verify TLS certificates (default).")
    parser.add_argument("--no-verify", dest="verify", action="store_false", help="Disable TLS verification.")
    return parser.parse_args()


def flatten_components(payload: Dict[str, Any]) -> Dict[str, Any]:
    components = payload.get("components")
    if isinstance(components, dict):
        return components
    return payload


def to_state(value: Any, healthy_values: set[str]) -> int:
    state = None
    if isinstance(value, dict):
        state = value.get("status")
    elif isinstance(value, str):
        state = value
    if state is None:
        return 0
    normalized = str(state).strip().lower()
    return 1 if normalized in healthy_values else 0


def main() -> None:
    args = parse_args()
    healthy_values = HEALTHY_STATES | {s.lower() for s in args.allow_status}
    try:
        start = time.perf_counter()
        resp = requests.get(args.url, timeout=args.timeout, verify=args.verify)
        elapsed_ms = (time.perf_counter() - start) * 1000
    except requests.RequestException as exc:
        print_prtg_error(f"Request failed: {exc}")
        return

    if resp.status_code >= 400:
        print_prtg_error(f"Endpoint returned {resp.status_code}")
        return

    try:
        payload = resp.json()
    except ValueError as exc:
        print_prtg_error(f"Invalid JSON response: {exc}")
        return

    components = flatten_components(payload)
    if not isinstance(components, dict):
        print_prtg_error("Health payload missing components")
        return

    results = [
        build_channel("Health Response Time", round(elapsed_ms, 2), "TimeResponse")
    ]

    for name, value in components.items():
        status_value = to_state(value, healthy_values)
        channel_name = f"{name} Healthy"
        results.append(build_channel(channel_name, status_value, "Count", ValueLookup="prtg.standardlookups.yesno.state"))

    print_prtg_results(results)


if __name__ == "__main__":
    main()
