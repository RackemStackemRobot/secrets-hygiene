from __future__ import annotations

import os
from pathlib import Path
from secrets_hygiene.patterns import RULES, mask_match


DEFAULT_IGNORE_DIRS = {
    ".git",
    ".svn",
    ".hg",
    "__pycache__",
    "node_modules",
    "venv",
    ".venv",
    "dist",
    "build",
}

RISKY_FILENAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "credentials",
    "config.json",
}

RISKY_EXTENSIONS = {
    ".pem",
    ".p12",
    ".pfx",
    ".key",
    ".kdbx",
}


def _should_ignore_dir(dirname: str) -> bool:
    return dirname in DEFAULT_IGNORE_DIRS


def walk_files(root: str) -> list[Path]:
    root_path = Path(root).resolve()
    results: list[Path] = []

    for dirpath, dirnames, filenames in os.walk(root_path):
        # prune ignored dirs
        dirnames[:] = [d for d in dirnames if not _should_ignore_dir(d)]

        for fn in filenames:
            p = Path(dirpath) / fn
            results.append(p)

    return results


def find_risky_files(paths: list[Path]) -> list[dict]:
    findings: list[dict] = []

    for p in paths:
        name = p.name
        ext = p.suffix.lower()

        if name in RISKY_FILENAMES or ext in RISKY_EXTENSIONS:
            findings.append(
                {
                    "type": "risky_file",
                    "path": str(p),
                    "severity": "medium",
                    "evidence": {"filename": name, "extension": ext},
                    "recommendation": "Move secrets to a secure vault and ensure secret files are not committed to source control.",
                }
            )
TEXT_EXT_ALLOWLIST = {
    ".txt", ".md", ".py", ".ps1", ".psm1", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env"
}


def _is_probably_text(path: Path) -> bool:
    ext = path.suffix.lower()
    return ext in TEXT_EXT_ALLOWLIST or path.name.startswith(".env")


def scan_file_for_patterns(path: Path, max_bytes: int = 200_000) -> list[dict]:
    findings: list[dict] = []

    if not _is_probably_text(path):
        return findings

    try:
        # Read a capped amount to avoid huge files
        data = path.read_bytes()[:max_bytes]
        text = data.decode(errors="ignore")
    except Exception:
        return findings

    for rule in RULES:
        for m in rule.regex.finditer(text):
            raw = m.group(0)
            findings.append(
                {
                    "type": "pattern_match",
                    "rule_id": rule.id,
                    "title": rule.title,
                    "severity": rule.severity,
                    "path": str(path),
                    "evidence": {"match_masked": mask_match(raw)},
                    "recommendation": "Rotate the exposed secret, remove it from code, and store it in a secret manager or vault.",
                }
            )

    return findings


def find_pattern_matches(paths: list[Path]) -> list[dict]:
    all_findings: list[dict] = []
    for p in paths:
        all_findings.extend(scan_file_for_patterns(p))
    return all_findings

    return findings
