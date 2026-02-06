# secrets-hygiene

Defensive scanner for accidental secrets and risky files. Outputs JSON or Markdown reports.

This tool is designed to be safe by default:
- It does not upload data anywhere.
- It masks matched values in output (no full secret values printed).
- It is intended for developer hygiene and defensive review.

## What it detects (current)
### Risky files
- `.env` and common env variants
- private key names like `id_rsa`
- certificate/key formats: `.pem`, `.p12`, `.pfx`, `.key`
- password vault file types: `.kdbx`
- common credential filenames like `credentials`

### Pattern matches (masked)
- Possible AWS Access Key IDs
- Possible GitHub tokens
- Possible Slack tokens
- Generic suspicious `api_key=...` / `token: ...` style assignments

## Ignore rules
The scanner skips common bulky folders by default:
- `.git/`, `node_modules/`, `venv/`, `.venv/`, `dist/`, `build/`, `__pycache__/`

## Run
- JSON:
  - `secrets-hygiene .`
- Markdown:
  - `secrets-hygiene . --format md`

## Safety note
This is not an offensive tool. It flags likely secret exposure and hygiene risks so you can remediate them.
