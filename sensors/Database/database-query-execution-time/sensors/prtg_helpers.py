"""Utilities shared by the standalone Script v2 sensor implementations."""
from __future__ import annotations

import json
import sys
from typing import Any, Dict, List


def build_channel(channel: str, value: float | int, unit: str, **extra: Any) -> Dict[str, Any]:
    """Return a single PRTG channel dictionary."""
    entry: Dict[str, Any] = {"channel": channel, "value": value, "unit": unit}
    for key, val in extra.items():
        if val is None:
            continue
        entry[key] = val
    return entry


def print_prtg_results(results: List[Dict[str, Any]]) -> None:
    """Emit a JSON payload understood by PRTG and exit successfully."""
    payload = {"prtg": {"result": results}}
    print(json.dumps(payload))
    raise SystemExit(0)


def print_prtg_error(message: str, *, code: int = 1) -> None:
    """Print an error payload and exit with the provided code."""
    payload = {"prtg": {"error": 1, "text": message}}
    print(json.dumps(payload))
    raise SystemExit(code)
