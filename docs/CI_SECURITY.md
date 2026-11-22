# Continuous Integration and Security Checks

MIJHAR uses the existing pytest suite and separate GitHub Actions quality/security jobs on pull requests to `main`.

## Checks

| Check | Purpose | Expected evidence |
| --- | --- | --- |
| pytest (Python 3.9 / 3.12) | Regression and compatibility testing | Two successful matrix jobs |
| Ruff (E4, E7, E9, F) | Syntax and core lint correctness | Successful quality job |
| `python -m build` | sdist/wheel creation | Successful build step; packaging contents still need inspection |
| `python -m pip check` | Installed dependency consistency | Successful check step |
| Bandit (`-ll`) | Medium/high-severity security patterns in Python source | Successful security step or reviewed finding |
| pip-audit | Known vulnerable packages in the installed Python environment | Successful audit or reviewed advisory |

## Operating safeguards

- Token permission: `contents: read`; no secrets or third-party upload configured.
- CI cannot prove deployment readiness, detect every vulnerability, or validate all compliance mappings.
- `pip-audit` depends on network and vulnerability-advisory availability; false positives and environment-specific dependency findings require review, not automatic suppression.
- Pinned major GitHub Actions releases should be evaluated for SHA pinning in a later supply-chain hardening change.
- Keep a separate human approval gate for merging and publishing.
- Required status checks and branch protection are **repository settings** and need independent verification; adding workflows alone does not enforce them.

## Typical local commands

After cloning, creating a virtual environment, and installing `.[dev]` plus the audit tools:

```bash
python -m pytest
ruff check src tests --select E4,E7,E9,F
bandit -r src -ll -q
python -m pip_audit
python -m build
python -m pip check
```

Use exact CI logs for verified results. Do not claim a command passed merely because it is documented here.
