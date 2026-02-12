from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent))
    from prtg_helpers import build_channel, print_prtg_error, print_prtg_results
else:
    from .prtg_helpers import build_channel, print_prtg_error, print_prtg_results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan log files for critical errors since last run.")
    parser.add_argument("--log-path", required=True, help="Target log file.")
    parser.add_argument("--pattern", action="append", metavar="REGEX", required=True, help="Regex to count (repeatable).")
    parser.add_argument("--state-file", help="JSON file storing last read offset (default: <log>.state.json).")
    parser.add_argument("--encoding", default="utf-8", help="Log file encoding (default: utf-8).")
    return parser.parse_args()


def load_state(state_file: Path) -> Dict[str, int]:
    if not state_file.exists():
        return {"offset": 0, "inode": 0}
    try:
        return json.loads(state_file.read_text())
    except (json.JSONDecodeError, OSError):
        return {"offset": 0, "inode": 0}


def save_state(state_file: Path, offset: int, inode: int) -> None:
    state = {"offset": offset, "inode": inode}
    state_file.write_text(json.dumps(state))


def main() -> None:
    args = parse_args()
    log_path = Path(args.log_path)
    if not log_path.is_file():
        print_prtg_error(f"Log file not found: {log_path}")
        return

    state_file = Path(args.state_file) if args.state_file else log_path.with_suffix(log_path.suffix + ".state.json")
    state = load_state(state_file)

    try:
        stat = log_path.stat()
    except OSError as exc:
        print_prtg_error(f"Unable to stat log: {exc}")
        return

    current_inode = int(stat.st_ino)
    offset = int(state.get("offset", 0)) if state.get("inode") == current_inode and state.get("offset", 0) <= stat.st_size else 0

    try:
        with log_path.open("r", encoding=args.encoding, errors="ignore") as handle:
            handle.seek(offset)
            data = handle.read()
            offset = handle.tell()
    except OSError as exc:
        print_prtg_error(f"Failed to read log: {exc}")
        return

    compiled: List[tuple[str, re.Pattern[str]]] = []
    for pattern in args.pattern:
        try:
            compiled.append((pattern, re.compile(pattern)))
        except re.error as exc:
            print_prtg_error(f"Invalid regex '{pattern}': {exc}")
            return

    counts: Dict[str, int] = {}
    for name, regex in compiled:
        counts[name] = len(regex.findall(data))

    total = sum(counts.values())
    results = [build_channel("Total Error Matches", total, "Count")]
    for name, count in counts.items():
        results.append(build_channel(f"Matches: {name}", count, "Count"))

    try:
        save_state(state_file, offset, current_inode)
    except OSError:
        pass

    print_prtg_results(results)


if __name__ == "__main__":
    main()
