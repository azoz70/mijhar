# AI Contributor Instructions — MIJHAR

This file guides AI coding assistants. It supplements, rather than replaces, [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and the documentation under `docs/`.

## Before making changes

1. Read [README.md](README.md), [architecture](docs/architecture.md), [roadmap](docs/ROADMAP.md), [compliance notes](docs/COMPLIANCE.md), and the relevant source files.
2. Check [project status](docs/STATUS.md) and [decision log](docs/DECISIONS.md). Treat them as documentation, **not** proof that the current repository or tests match their entries.
3. Confirm the current branch/commit, scope, requirements, and relevant tests. Never infer a successful test from a checkbox or past commit message.
4. Explain the planned minimal change, risks, and acceptance criteria before implementing.

## Safety and change control

- **Read-only assessment by default**: collectors observe; they do not change assessed hosts. Do not introduce destructive commands, exploitation, credentials storage, or unsanctioned network actions.
- Keep facts collection, rule applicability, rule evaluation, risk scoring, evidence, compliance mapping, and reporting separate.
- Apply only platform-eligible checks. Record explicit reasons for excluded rules. Do not equate an unassessed control with a pass.
- Preserve evidence redaction and integrity guarantees. Never publish credentials, secrets, or sensitive scan results.
- Work on a dedicated branch and submit changes as a Pull Request. **Do not push to `main`, merge, release, or run impactful security tests without explicit user approval.**
- Make the smallest relevant change; avoid unrelated refactors.

## Compliance-specific rules

- Use official framework texts and their exact applicable versions. Never invent controls or sub-control identifiers.
- Follow [docs/COMPLIANCE.md](docs/COMPLIANCE.md); mappings must identify source, verification status, and whether they are `direct`, `partial`, or `supporting_evidence`.
- Distinguish technical validation from full compliance assessment and operational effectiveness. Flag uncertain links for qualified human review.

## Validation and reporting

- The development test command documented in [CONTRIBUTING.md](CONTRIBUTING.md) is `.venv/bin/pytest` after installing `.[dev]`; only report it as passed if actually executed.
- For docs-only changes, inspect links, references, Markdown structure, and the final diff; record any checks not run.
- Summarize changed files, actual validation evidence, unverified items, and next actions. Update `docs/STATUS.md` only with evidence-backed state; log consequential approved architectural decisions in `docs/DECISIONS.md`.

## Documentation map

- User introduction and installation: [README.md](README.md)
- Architecture and data flow: [docs/architecture.md](docs/architecture.md)
- CLI usage: [docs/CLI.md](docs/CLI.md)
- Compliance mapping sources and caveats: [docs/COMPLIANCE.md](docs/COMPLIANCE.md)
- Longer-term plans: [docs/ROADMAP.md](docs/ROADMAP.md)
- Contribution conventions: [CONTRIBUTING.md](CONTRIBUTING.md)
- Security reporting: [SECURITY.md](SECURITY.md)
- Decision records: [docs/DECISIONS.md](docs/DECISIONS.md)
- Verified project handoff: [docs/STATUS.md](docs/STATUS.md)
