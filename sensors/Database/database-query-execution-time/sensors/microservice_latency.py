from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import List, Tuple

import requests

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent))
    from prtg_helpers import build_channel, print_prtg_error, print_prtg_results
else:
    from .prtg_helpers import build_channel, print_prtg_error, print_prtg_results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Measure microservice latency and status for PRTG.")
    parser.add_argument(
        "--endpoint",
        action="append",
        metavar="NAME=URL",
        required=True,
        help="Endpoint definition (repeatable). Example: auth=https://svc/auth/health",
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-request timeout in seconds.")
    parser.add_argument("--verify", action="store_true", default=True, help="Verify TLS certificates (default).")
    parser.add_argument("--no-verify", dest="verify", action="store_false", help="Disable TLS verification.")
    return parser.parse_args()


def parse_endpoint(spec: str) -> Tuple[str, str]:
    if "=" not in spec:
        raise ValueError("Endpoint must look like name=url")
    name, url = spec.split("=", 1)
    return name.strip() or "endpoint", url.strip()


def main() -> None:
    args = parse_args()
    try:
        targets = [parse_endpoint(spec) for spec in args.endpoint]
    except ValueError as exc:
        print_prtg_error(str(exc))
        return

    results: List[dict] = []

    for name, url in targets:
        latency_ms = 0.0
        status_code = 0
        success = 0
        try:
            start = time.perf_counter()
            resp = requests.get(url, timeout=args.timeout, verify=args.verify)
            latency_ms = (time.perf_counter() - start) * 1000
            status_code = resp.status_code
            success = 1 if resp.status_code == 200 else 0
        except requests.RequestException:
            success = 0
            latency_ms = 0.0
            status_code = 0

        prefix = name.replace(" ", "_")
        results.append(build_channel(f"{prefix} Response Time", round(latency_ms, 2), "TimeResponse"))
        results.append(
            build_channel(
                f"{prefix} Success",
                success,
                "Count",
                ValueLookup="prtg.standardlookups.yesno.state",
            )
        )
        results.append(build_channel(f"{prefix} HTTP Status", status_code, "Count"))

    print_prtg_results(results)


if __name__ == "__main__":
    main()
