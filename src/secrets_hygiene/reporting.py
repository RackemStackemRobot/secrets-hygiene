from __future__ import annotations


def to_markdown(report: dict) -> str:
    meta = report.get("meta", {})
    targets = report.get("targets", [])
    findings = report.get("findings", [])

    lines: list[str] = []
    lines.append("# Secrets Hygiene Report")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Timestamp (UTC): {meta.get('timestamp_utc', 'unknown')}")
    lines.append(f"- Target(s): {', '.join(targets) if targets else 'n/a'}")
    lines.append(f"- Findings: {len(findings)}")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    lines.append("| Type | Severity | Rule | Path | Evidence |")
    lines.append("|---|---|---|---|---|")

    for f in findings:
        ftype = f.get("type", "")
        sev = f.get("severity", "")
        rule = f.get("rule_id", "")
        path = f.get("path", "")
        ev = f.get("evidence", {})
        ev_str = str(ev.get("match_masked") or ev.get("filename") or "")
        lines.append(f"| {ftype} | {sev} | {rule} | {path} | `{ev_str}` |")

    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("This report masks matched values to avoid leaking sensitive data in output.")
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"
