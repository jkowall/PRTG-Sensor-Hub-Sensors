from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Callable

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent))
    from prtg_helpers import build_channel, print_prtg_error, print_prtg_results
else:
    from .prtg_helpers import build_channel, print_prtg_error, print_prtg_results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Execute a SQL query and report latency for PRTG.")
    parser.add_argument("--driver", choices=["psycopg2", "pymysql", "cx_Oracle"], required=True, help="Database driver to use.")
    parser.add_argument("--host", required=True, help="Database host or IP address.")
    parser.add_argument("--port", type=int, help="Port number.")
    parser.add_argument("--user", required=True, help="Database username.")
    parser.add_argument("--password", required=True, help="Database password.")
    parser.add_argument("--database", help="Database/schema/service name.")
    parser.add_argument("--dsn", help="Optional DSN (Oracle). Overrides host/port/database.")
    parser.add_argument("--query", required=True, help="SQL query to execute.")
    parser.add_argument("--timeout", type=int, default=10, help="Optional statement timeout (driver specific).")
    return parser.parse_args()


def connect_psycopg2(args: argparse.Namespace):
    try:
        import psycopg2
    except ImportError as exc:
        print_prtg_error(f"psycopg2 not installed: {exc}")
        return None
    params = {
        "host": args.host,
        "user": args.user,
        "password": args.password,
        "dbname": args.database,
    }
    if args.port:
        params["port"] = args.port
    conn = psycopg2.connect(**params)
    conn.autocommit = True
    if args.timeout:
        with conn.cursor() as cur:
            cur.execute(f"SET statement_timeout TO {int(args.timeout) * 1000}")
    return conn


def connect_pymysql(args: argparse.Namespace):
    try:
        import pymysql
    except ImportError as exc:
        print_prtg_error(f"PyMySQL not installed: {exc}")
        return None
    params = {
        "host": args.host,
        "user": args.user,
        "password": args.password,
        "database": args.database,
        "connect_timeout": args.timeout,
    }
    if args.port:
        params["port"] = args.port
    return pymysql.connect(**params)


def connect_cx_oracle(args: argparse.Namespace):
    try:
        import cx_Oracle
    except ImportError as exc:
        print_prtg_error(f"cx_Oracle not installed: {exc}")
        return None
    dsn = args.dsn or cx_Oracle.makedsn(args.host, args.port or 1521, service_name=args.database)
    return cx_Oracle.connect(args.user, args.password, dsn, timeout=args.timeout)


CONNECTORS: dict[str, Callable[[argparse.Namespace], object]] = {
    "psycopg2": connect_psycopg2,
    "pymysql": connect_pymysql,
    "cx_Oracle": connect_cx_oracle,
}


def main() -> None:
    args = parse_args()
    if args.driver in {"psycopg2", "pymysql"} and not args.database:
        print_prtg_error("--database is required for this driver")
        return
    if args.driver == "cx_Oracle" and not (args.database or args.dsn):
        print_prtg_error("Provide --database or --dsn for cx_Oracle")
        return
    connector = CONNECTORS[args.driver]
    conn = connector(args)
    if conn is None:
        return

    try:
        cursor = conn.cursor()
    except Exception as exc:  # noqa: BLE001
        print_prtg_error(f"Unable to obtain cursor: {exc}")
        return

    try:
        start = time.perf_counter()
        cursor.execute(args.query)
        duration_ms = (time.perf_counter() - start) * 1000
        rowcount = cursor.rowcount if getattr(cursor, "rowcount", -1) not in (-1, None) else 0
    except Exception as exc:  # noqa: BLE001
        print_prtg_error(f"Query failed: {exc}")
        return
    finally:
        try:
            cursor.close()
            conn.close()
        except Exception:  # noqa: BLE001
            pass

    results = [
        build_channel("Query Duration", round(duration_ms, 2), "TimeResponse"),
        build_channel("Rows Affected", rowcount, "Count"),
    ]
    print_prtg_results(results)


if __name__ == "__main__":
    main()
