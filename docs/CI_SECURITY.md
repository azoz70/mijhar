# Continuous Integration and Security Checks

MIJHAR uses the existing pytest suite and separate GitHub Actions quality/security jobs on pull requests to `main`.

## Checks

| Check | Purpose | Expected evidence |
| --- | --- | --- |
| pytest (Python 3.9 / 3.12) | Regression and compatibility testing | Two successful matrix jobs |
| Ruff (E4, E7, E9, all F rules) | Syntax and core lint correctness | Successful quality job |
| `python -m build` | sdist/wheel creation | Successful build step; packaging contents still need inspection |
| `python -m pip check` | Installed dependency consistency | Successful check step |
| Bandit (`-ll`) | Medium/high-severity security patterns in Python source | Successful security step or reviewed finding |
| pip-audit | Known vulnerable packages in the installed Python environment | Successful audit or reviewed advisory |

## Operating safeguards

- Token permission: `contents: read`; no secrets or third-party upload configured.
- The initial Ruff baseline found 12 F401/F841 issues. These were addressed on PR #5; the blocking CI now checks all F rules plus E4/E7/E9. Confirm with current PR checks before treating the cleanup as validated.
- CI cannot prove deployment readiness, detect every vulnerability, or validate all compliance mappings.
- `pip-audit` depends on network and vulnerability-advisory availability; false positives and environment-specific dependency findings require review, not automatic suppression.
- Pinned major GitHub Actions releases should be evaluated for SHA pinning in a later supply-chain hardening change.
- Keep a separate human approval gate for merging and publishing.
- Required status checks and branch protection are **repository settings** and need independent verification; adding workflows alone does not enforce them.

## Recommended branch protection (requires repository administrator)

The connected GitHub integration returned HTTP 403 for `GET /branches/main/protection` and an empty list from `GET /rulesets` during this review. No branch protection was applied. A repository administrator should:

1. Open GitHub > Settings > Rules > Rulesets (or Branches, depending on the UI).
2. Add a rule targeting `main` and require a pull request before merging.
3. Require passing checks corresponding to `pytest (Python 3.9)`, `pytest (Python 3.12)`, `Ruff and package build`, and `Bandit and dependency audit` **only after those jobs have actually passed and GitHub exposes them as selectable checks**.
4. Block force pushes and branch deletion. Keep enforcement enabled for administrators if supported and suitable.
5. Prefer at least one independent human reviewer where practical; never count the PR author's own review as independent.
6. Test enforcement with a harmless draft PR; record observed results.

Do not rely on `AGENTS.md` or CI YAML alone to prevent bypassing merge controls.

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


The separate [platform smoke workflow](../.github/workflows/platform-smoke.yml) tests installed wheels and local read-only scans on hosted Linux/macOS runners.