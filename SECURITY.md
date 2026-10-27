# Security policy

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting instead:
**Security → Report a vulnerability** on this repository. You'll get a response within a few days.

Examples of in-scope issues: hardn leaking a secret value into `FIX_PROMPT.md` / `report.json` / SARIF,
`hardn fix` acting outside the git repository, or code execution triggered by scanning a malicious repo.

## Supported versions

Only the latest release receives fixes.

## Design notes

- Scans never use the network. Only `hardn update` downloads data (OSV.dev, CISA KEV, optional Semgrep rules).
- Secret values are redacted before they reach any output file or prompt.
- `hardn fix` refuses to run outside git or on a dirty tree, works on a new branch, and never commits.
