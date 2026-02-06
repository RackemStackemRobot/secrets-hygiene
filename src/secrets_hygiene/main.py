from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone

from secrets_hygiene.scanner import find_pattern_matches, find_risky_files, walk_files


def main() -> None:
    parser = argparse.ArgumentParser(description="Defensive secrets hygiene scanner")
    parser.add_argument("path", nargs="?", default=".", help="Path to scan (default: current directory)")
    args = parser.parse_args()

    paths = walk_files(args.path)
    findings = []
    findings.extend(find_risky_files(paths))
    findings.extend(find_pattern_matches(paths))


    report = {
        "meta": {
            "tool": "secrets-hygiene",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
        "targets": [args.path],
        "findings": findings,
    }

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
