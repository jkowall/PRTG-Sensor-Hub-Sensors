from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict

import requests

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent))
    from prtg_helpers import build_channel, print_prtg_error, print_prtg_results
else:
    from .prtg_helpers import build_channel, print_prtg_error, print_prtg_results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch queue depth metrics from HTTP APIs for PRTG.")
    parser.add_argument("--url", required=True, help="Queue metrics endpoint returning JSON.")
    parser.add_argument("--queue", action="append", required=True, help="Queue name to extract (repeatable).")
    parser.add_argument("--collection", default="queues", help="Dot path to the list/dict containing queue entries.")
    parser.add_argument("--name-field", default="name", help="Field providing the queue name when collection is a list.")
    parser.add_argument("--value-field", default="messages", help="Field containing the queue depth.")
    parser.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds.")
    parser.add_argument("--verify", action="store_true", default=True, help="Verify TLS certificates (default).")
    parser.add_argument("--no-verify", dest="verify", action="store_false", help="Disable TLS verification.")
    return parser.parse_args()


def extract_collection(payload: Dict[str, Any], path: str) -> Any:
    node: Any = payload
    for part in [p for p in path.split(".") if p]:
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            raise KeyError(f"Collection path '{path}' not found")
    return node


def normalize(collection: Any, name_field: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    if isinstance(collection, dict):
        for key, value in collection.items():
            result[str(key)] = value
    elif isinstance(collection, list):
        for item in collection:
            if isinstance(item, dict) and name_field in item:
                result[str(item[name_field])] = item
    else:
        raise ValueError("Collection must be dict or list")
    return result


def main() -> None:
    args = parse_args()
    try:
        resp = requests.get(args.url, timeout=args.timeout, verify=args.verify)
        resp.raise_for_status()
    except requests.RequestException as exc:
        print_prtg_error(f"Request failed: {exc}")
        return

    try:
        payload = resp.json()
    except ValueError as exc:
        print_prtg_error(f"Invalid JSON: {exc}")
        return

    try:
        collection = extract_collection(payload, args.collection)
        queue_map = normalize(collection, args.name_field)
    except (KeyError, ValueError) as exc:
        print_prtg_error(str(exc))
        return

    results = []
    missing = []
    for queue in args.queue:
        record = queue_map.get(queue)
        if record is None:
            missing.append(queue)
            continue
        value = record.get(args.value_field) if isinstance(record, dict) else record
        try:
            depth = float(value)
        except (TypeError, ValueError):
            missing.append(queue)
            continue
        results.append(build_channel(f"Queue: {queue}", round(depth, 2), "Count"))

    if missing:
        results.append(build_channel("Queues Missing", len(missing), "Count"))

    if not results:
        print_prtg_error("No queue metrics were collected")
        return

    print_prtg_results(results)


if __name__ == "__main__":
    main()
