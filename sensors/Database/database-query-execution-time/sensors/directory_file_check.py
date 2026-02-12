from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent))
    from prtg_helpers import build_channel, print_prtg_error, print_prtg_results
else:
    from .prtg_helpers import build_channel, print_prtg_error, print_prtg_results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inspect directory/file counts and ages for PRTG.")
    parser.add_argument("--path", required=True, help="Directory to inspect.")
    parser.add_argument("--pattern", default="*", help="Glob pattern (default: *).")
    parser.add_argument("--recursive", action="store_true", help="Use recursive globbing.")
    parser.add_argument("--follow-links", action="store_true", help="Follow symlinks while traversing.")
    return parser.parse_args()


def list_files(root: Path, pattern: str, recursive: bool, follow_links: bool) -> Iterable[Path]:
    iterator = root.rglob(pattern) if recursive else root.glob(pattern)
    for path in iterator:
        if path.is_symlink() and not follow_links:
            continue
        yield path


def main() -> None:
    args = parse_args()
    root = Path(args.path)
    if not root.exists():
        print_prtg_error(f"Path does not exist: {root}")
        return

    now = datetime.now(timezone.utc)
    files: List[Path] = []
    try:
        for path in list_files(root, args.pattern, args.recursive, args.follow_links):
            if path.is_file() or (args.follow_links and path.is_symlink()):
                files.append(path)
    except OSError as exc:
        print_prtg_error(f"Failed to enumerate files: {exc}")
        return

    if not files:
        results = [build_channel("File Count", 0, "Count"), build_channel("Oldest File Age", 0, "TimeSeconds"), build_channel("Newest File Age", 0, "TimeSeconds")]
        print_prtg_results(results)
        return

    ages_seconds: List[float] = []
    for path in files:
        try:
            stat = path.stat()
        except OSError:
            continue
        mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
        ages_seconds.append((now - mtime).total_seconds())

    if not ages_seconds:
        print_prtg_error("Unable to read file metadata")
        return

    ages_seconds.sort()
    oldest = ages_seconds[-1]
    newest = ages_seconds[0]
    avg_age = sum(ages_seconds) / len(ages_seconds)

    results = [
        build_channel("File Count", len(files), "Count"),
        build_channel("Oldest File Age", round(oldest), "TimeSeconds"),
        build_channel("Newest File Age", round(newest), "TimeSeconds"),
        build_channel("Average File Age", round(avg_age), "TimeSeconds"),
    ]
    print_prtg_results(results)


if __name__ == "__main__":
    main()
