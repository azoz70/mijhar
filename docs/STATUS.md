# MIJHAR — Project Status / AI Handoff

**Last documentation review:** 2026-11-22 (UTC+03:00)  
**Repository:** [azoz70/mijhar](https://github.com/azoz70/mijhar)  
**Baseline reviewed:** `main` commit [`ceb0cadf6b2de4a1c64f0edcd93f1f9fec69172f`](https://github.com/azoz70/mijhar/commit/ceb0cadf6b2de4a1c64f0edcd93f1f9fec69172f) (2026-11-21).  
**Documented version:** `0.2.0` in [src/mijhar/__init__.py](../src/mijhar/__init__.py); this is **not** a verified public release version.  
**Development status:** Alpha in [pyproject.toml](../pyproject.toml).  
**Scope of this handoff:** Documentation-only inventory; no local checkout or runtime test execution.

## Verified from repository contents

- [README.md](../README.md) describes an interactive CLI, modular Linux/macOS collectors, remote Linux over SSH, YAML rules, applicability checks, evidence, risk, compliance mapping, SQLite, and JSON/CSV/HTML reports.
- [Architecture](architecture.md) documents the data flow and separation of responsibilities; [CLI reference](CLI.md) documents supported commands.
- [Roadmap](ROADMAP.md) marks the v0.2 platform-aware implementation complete and lists Windows, cloud, devices, deeper mappings, optional intel fetching, PDF, and AI among future work. These are **documentation claims**, not independently executed validation results.
- [Compliance notes](COMPLIANCE.md) explicitly mark rule-to-framework mappings as interpretive / requiring reviewer verification, including SAMA considerations.
- `tests/test_scanner.py` and `tests/test_applicability.py` were read directly. A broader pytest suite is described in [CONTRIBUTING.md](../CONTRIBUTING.md).
- The latest baseline commit above merged PR #1, titled *Fix audit accuracy, evidence redaction, and catalog packaging*; this establishes commit history, not confirmed runtime behavior.

## Validation status

| Check | Result | Evidence / limitation |
| --- | --- | --- |
| Repository access and core documentation read | Verified | GitHub connector read of README, architecture, roadmap, compliance, CLI, contributing, security, pyproject |
| Source / test examples inspected | Partial | `src/mijhar/__init__.py`, `tests/test_scanner.py`, `tests/test_applicability.py` |
| `pytest` | **Not run** | No locally executable checkout obtained in this review |
| CI / GitHub Actions | **Not verified** | No combined commit statuses or PR-triggered workflow runs returned for baseline; absence of results does not prove CI is absent |
| Full source/rule audit | **Not performed** | Documentation scope only |
| Deployed release / package usability | **Not verified** | Not installed or executed |

## Open work and next actions

1. Review the documentation-only PR diff and verify all relative Markdown links.
2. Run Markdown/link checks in a checked-out environment; record exact commands and results in the PR.
3. If changing application logic later, run `.venv/bin/pytest` and appropriate security and package checks, documenting outcomes.
4. Validate rule-to-control mappings against official framework material with a qualified reviewer; retain `verified: false` until supported.
5. Keep future features and long-range milestones in [ROADMAP.md](ROADMAP.md), not this file.
6. After merging an approved change, refresh this file with the actual main-branch commit and latest verified test evidence.

## Handoff rule

For a future AI session: read this file, [AGENTS.md](../AGENTS.md), [DECISIONS.md](DECISIONS.md), and the relevant source. **Re-check GitHub for the latest state rather than treating this snapshot as current indefinitely.** Never report unexecuted tests as passing.
