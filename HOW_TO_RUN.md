# How to Run secrets-hygiene

## Requirements
- Python 3.10+
- Windows/macOS/Linux (works anywhere, CI uses Windows)

## Install
From source:

    pip install -e .

## Run
Scan current directory (JSON):

    secrets-hygiene .

Scan current directory (Markdown):

    secrets-hygiene . --format md

Scan a specific folder:

    secrets-hygiene C:\path\to\project --format md

## Output behavior
- Matched values are masked. The tool does not print full tokens or keys.
- Findings include the file path, rule type, and masked evidence to help you locate the issue.

## Recommended workflow
- Run before committing code.
- Rotate any exposed secrets immediately.
- Move secrets to a proper secret manager or vault.
