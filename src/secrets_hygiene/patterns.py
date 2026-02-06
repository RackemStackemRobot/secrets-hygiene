from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PatternRule:
    id: str
    title: str
    severity: str
    regex: re.Pattern


RULES: list[PatternRule] = [
    PatternRule(
        id="AWS-ACCESS-KEY",
        title="Possible AWS Access Key ID",
        severity="high",
        regex=re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    PatternRule(
        id="GITHUB-TOKEN",
        title="Possible GitHub token",
        severity="high",
        regex=re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
    ),
    PatternRule(
        id="SLACK-TOKEN",
        title="Possible Slack token",
        severity="high",
        regex=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    PatternRule(
        id="GENERIC-API-KEY",
        title="Suspicious API key assignment",
        severity="medium",
        regex=re.compile(r"(?i)\b(api[_-]?key|secret|token)\b\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}[\"']?"),
    ),
]


def mask_match(s: str) -> str:
    """
    Masks a matched secret-like value to avoid leaking sensitive content in reports.
    Keeps a small prefix/suffix for debugging context.
    """
    s = s.strip()
    if len(s) <= 8:
        return "*" * len(s)
    return f"{s[:4]}***{s[-4:]}"
