from __future__ import annotations

import argparse
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent))
    from prtg_helpers import build_channel, print_prtg_error, print_prtg_results
else:
    from .prtg_helpers import build_channel, print_prtg_error, print_prtg_results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Report SSL certificate expiration for PRTG.")
    parser.add_argument("--host", required=True, help="Hostname to connect to.")
    parser.add_argument("--port", type=int, default=443, help="TLS port (default: 443).")
    parser.add_argument("--timeout", type=float, default=5.0, help="Socket timeout in seconds.")
    parser.add_argument("--sni", help="Override SNI/Server Name (defaults to host).")
    parser.add_argument("--allow-expired", action="store_true", help="Do not fail when certificate already expired.")
    return parser.parse_args()


def get_certificate(host: str, port: int, timeout: float, sni: str | None):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=sni or host) as wrapped:
                return wrapped.getpeercert()
    except OSError as exc:
        print_prtg_error(f"Failed to fetch certificate: {exc}")
        return None


def parse_expiry(cert: dict) -> float:
    not_after = cert.get("notAfter")
    if not not_after:
        raise ValueError("Certificate missing notAfter field")
    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    delta = expiry - now
    return delta.total_seconds() / 86400


def main() -> None:
    args = parse_args()
    cert = get_certificate(args.host, args.port, args.timeout, args.sni)
    if cert is None:
        return

    try:
        days_left = parse_expiry(cert)
    except Exception as exc:  # noqa: BLE001
        print_prtg_error(f"Unable to parse certificate: {exc}")
        return

    if days_left < 0 and not args.allow_expired:
        print_prtg_error(f"Certificate expired {-round(days_left, 2)} days ago")
        return

    seconds_left = max(days_left, 0) * 86400
    results = [
        build_channel("Certificate Days Remaining", round(max(days_left, 0), 2), "TimeDays"),
        build_channel("Certificate Seconds Remaining", round(seconds_left), "TimeSeconds"),
    ]
    print_prtg_results(results)


if __name__ == "__main__":
    main()
