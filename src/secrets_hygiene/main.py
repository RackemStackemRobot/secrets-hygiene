from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone

from secrets_hygiene.reporting import to_markdown
from secrets_hygiene.scanner import find_pattern_matches, find_risky_files, walk_files


def build_report(target: str) -> dict:
    paths = walk_files(target)

    findings: list[dict] = []
    findings.extend(find_risky_files(paths) or [])
    findings.extend(find_pattern_matches(paths) or [])

    return {
        "meta": {
            "tool": "secrets-hygiene",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
        "targets": [target],
        "findings": findings,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Defensive secrets hygiene scanner")
    parser.add_argument("path", nargs="?", default=".", help="Path to scan (default: current directory)")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args()

    report = build_report(args.path)

    if args.format == "md":
        print(to_markdown(report))
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
