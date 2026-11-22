# MIJHAR — Release Readiness Checklist

This checklist describes a **review gate**, not authorization to publish. A version is not production-ready merely because GitHub Actions passes.

## Before proposing an official release

- [ ] Confirm the latest `main` commit, intended semantic version, change scope, and an approved release owner.
- [ ] Review [AGENTS.md](../AGENTS.md), [STATUS.md](STATUS.md), [DECISIONS.md](DECISIONS.md), [ROADMAP.md](ROADMAP.md), and [SECURITY.md](../SECURITY.md).
- [ ] Ensure Python 3.9 and 3.12 pytest jobs pass on the **release candidate commit**; capture links to runs.
- [ ] Check Ruff, Bandit, and pip-audit findings; document and triage exceptions with evidence and expiration dates.
- [ ] Confirm wheel/sdist build and dependency consistency checks pass; verify bundled YAML catalogs and rules are included in the built package.
- [ ] Review framework-control IDs, sources, verified flags, and interpretive mappings; no automated scan is proof of organization-wide compliance.
- [ ] Test macOS and Linux user paths where equipment is available; record exact environments and results. Unavailable platform testing must be reported explicitly.
- [ ] Validate CLI help, exit codes, local scans, remote SSH safety, evidence redaction, and JSON/CSV/HTML export in an authorized test environment.
- [ ] Review documentation, installation commands, upgrade guidance, security disclosure instructions, licensing, and the changelog.
- [ ] Verify no API keys, credentials, customer data, assessment evidence, or sensitive paths are included in artifacts or git history.
- [ ] Obtain explicit human approval for merge, release/tag creation, and package publication as distinct actions.

## Evidence record template

| Item | Result (pass/fail/not run) | Environment | Evidence (commit, PR, run, report) | Reviewer |
| --- | --- | --- | --- | --- |
| pytest 3.9 | not run | — | — | — |
| pytest 3.12 | not run | — | — | — |
| Ruff | not run | — | — | — |
| Bandit | not run | — | — | — |
| pip-audit | not run | — | — | — |
| Package smoke test | not run | — | — | — |

**No automatic publishing or deployment is configured by this checklist.**
