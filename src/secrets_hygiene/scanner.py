from __future__ import annotations

import os
from pathlib import Path


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

    return findings
