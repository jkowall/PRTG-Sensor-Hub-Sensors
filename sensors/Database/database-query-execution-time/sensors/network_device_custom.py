from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Tuple

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent))
    from prtg_helpers import build_channel, print_prtg_error, print_prtg_results
else:
    from .prtg_helpers import build_channel, print_prtg_error, print_prtg_results

try:
    from pysnmp.hlapi import (  # type: ignore[import]
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        getCmd,
    )
except ImportError as exc:  # pragma: no cover - optional dep
    print_prtg_error(f"pysnmp is required: {exc}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect custom SNMP metrics for PRTG.")
    parser.add_argument("--host", required=True, help="Target host/IP.")
    parser.add_argument("--port", type=int, default=161, help="SNMP port (default: 161).")
    parser.add_argument("--community", default="public", help="SNMP community string.")
    parser.add_argument("--oid", action="append", metavar="NAME=OID", required=True, help="Named OID to query (repeatable).")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout in seconds.")
    parser.add_argument("--retries", type=int, default=2, help="Retry count.")
    return parser.parse_args()


def parse_oid_spec(spec: str) -> Tuple[str, str]:
    if "=" not in spec:
        raise ValueError("OID spec must be NAME=OID")
    name, oid = spec.split("=", 1)
    return name.strip(), oid.strip()


def fetch_oid(engine: SnmpEngine, community: str, host: str, port: int, timeout: float, retries: int, oid: str) -> float:
    iterator = getCmd(
        engine,
        CommunityData(community, mpModel=1),
        UdpTransportTarget((host, port), timeout=timeout, retries=retries),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
    )
    error_indication, error_status, error_index, var_binds = next(iterator)
    if error_indication:
        raise RuntimeError(str(error_indication))
    if error_status:
        index = int(error_index) - 1
        raise RuntimeError(f"{error_status.prettyPrint()} at index {index}")
    value = var_binds[0][1]
    return float(value)


def main() -> None:
    args = parse_args()
    try:
        oids = [parse_oid_spec(spec) for spec in args.oid]
    except ValueError as exc:
        print_prtg_error(str(exc))
        return

    engine = SnmpEngine()
    channels: List[dict] = []

    for name, oid in oids:
        try:
            value = fetch_oid(engine, args.community, args.host, args.port, args.timeout, args.retries, oid)
        except Exception as exc:  # noqa: BLE001
            print_prtg_error(f"SNMP query failed for {oid}: {exc}")
            return
        channels.append(build_channel(name, value, "Count"))

    print_prtg_results(channels)


if __name__ == "__main__":
    main()
