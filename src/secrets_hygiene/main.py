from __future__ import annotations

import json
from datetime import datetime, timezone


def main() -> None:
    report = {
        "meta": {
            "tool": "secrets-hygiene",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
        "targets": [],
        "findings": [],
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
