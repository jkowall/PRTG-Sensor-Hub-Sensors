from __future__ import annotations

import argparse
import sys
from datetime import date, timedelta
from pathlib import Path

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError as exc:  # pragma: no cover - dependency optional
    boto3 = None  # type: ignore[assignment]
    BotoCoreError = ClientError = Exception  # type: ignore[assignment]
    _BOTO_IMPORT_ERROR = exc
else:
    _BOTO_IMPORT_ERROR = None

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent))
    from prtg_helpers import build_channel, print_prtg_error, print_prtg_results
else:
    from .prtg_helpers import build_channel, print_prtg_error, print_prtg_results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Report estimated cloud spend for PRTG (AWS Cost Explorer).")
    parser.add_argument("--timeframe", choices=["today", "yesterday", "month-to-date", "last-month"], default="month-to-date")
    parser.add_argument("--metric", default="UnblendedCost", help="AWS Cost Explorer metric (default: UnblendedCost).")
    parser.add_argument("--granularity", choices=["DAILY", "MONTHLY"], default="DAILY", help="Cost Explorer granularity.")
    parser.add_argument("--profile", help="AWS profile name to use.")
    parser.add_argument("--region", default="us-east-1", help="Region for Cost Explorer endpoint.")
    return parser.parse_args()


def calculate_period(timeframe: str) -> tuple[str, str]:
    today = date.today()
    if timeframe == "today":
        start = today
        end = today + timedelta(days=1)
    elif timeframe == "yesterday":
        start = today - timedelta(days=1)
        end = today
    elif timeframe == "last-month":
        first_current = today.replace(day=1)
        last_month_end = first_current - timedelta(days=1)
        start = last_month_end.replace(day=1)
        end = first_current
    else:  # month-to-date
        start = today.replace(day=1)
        end = today + timedelta(days=1)
    return start.isoformat(), end.isoformat()


def main() -> None:
    args = parse_args()
    if boto3 is None:
        print_prtg_error(f"boto3 is required: {_BOTO_IMPORT_ERROR}")
        return
    start, end = calculate_period(args.timeframe)

    session_kwargs = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    session = boto3.Session(**session_kwargs)
    client = session.client("ce", region_name=args.region)

    try:
        response = client.get_cost_and_usage(
            TimePeriod={"Start": start, "End": end},
            Granularity=args.granularity,
            Metrics=[args.metric],
        )
    except (BotoCoreError, ClientError) as exc:
        print_prtg_error(f"Cost Explorer call failed: {exc}")
        return

    results = response.get("ResultsByTime", [])
    if not results:
        print_prtg_error("Cost Explorer returned no data")
        return

    total_cost = 0.0
    for item in results:
        total = item.get("Total", {}).get(args.metric)
        if total and "Amount" in total:
            total_cost += float(total["Amount"])

    period_days = max(len(results), 1)
    average_daily = total_cost / period_days

    payload = [
        build_channel(
            f"{args.timeframe.title()} Cost",
            round(total_cost, 2),
            "Custom",
            CustomUnit="USD",
        ),
        build_channel("Average Daily Cost", round(average_daily, 2), "Custom", CustomUnit="USD"),
    ]
    print_prtg_results(payload)


if __name__ == "__main__":
    main()
