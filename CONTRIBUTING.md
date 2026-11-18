# Contributing to MIJHAR

Thanks for your interest in contributing! MIJHAR is a read-only technical
security assessment framework. Please keep changes **read-only by default** and
never introduce destructive actions or store credentials.

## Getting started

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Running the tests

```bash
.venv/bin/pytest
```

Tests use mocked command/file runners and need no administrator privileges.

## Project layout

```
src/mijhar/
  cli/            Typer commands, single-theme console, wordmark, main menu
  core/           config, models, engine, scanner
  applicability/  platform-aware applicability engine (rule selection + exclusions)
  collectors/     base, linux, macos, ssh (read-only fact collection)
  rules/          YAML loader + evaluator
  risk/           scoring
  compliance/     registry, mapper, platform-aware assessment
  evidence/       redaction + SHA-256 integrity
  database/       SQLite persistence
  reports/        terminal, JSON, CSV, HTML
rules/            bundled YAML rules (linux/, macos/, common/)
frameworks/       cis/, nca_ecc/, sama_csf/, iso27001/
tests/            pytest suite
```

## Adding a security rule

Add a YAML file under `rules/<platform>/` (or `rules/common/` for
cross-platform checks). A rule carries applicability metadata that the engine
uses to decide eligibility *before* execution:

```yaml
- id: EXAMPLE-001
  title: Short description of the check
  description: What this check verifies.
  severity: high            # critical | high | medium | low | informational
  platforms: [linux]        # linux | macos | windows | any
  required_components: []   # optional: e.g. [ssh] or [firewall]
  assessment_type: configuration
  technical_assessability: assessable   # assessable | not_assessable | unsupported
  prerequisites: []         # optional
  rule_version: "1.0"
  enabled: true
  technical_impact: What an attacker gains if this fails.
  security_impact: Business impact of the failure.
  remediation: How to fix it.
  references:              # framework id -> control/sub-control ids
    cis: ["5.2.8"]
  check:
    fact: ssh.permit_root_login
    operator: not_in        # see VALID_OPERATORS in rules/loader.py
    value: ["yes", "without-password"]
    fail_status: fail       # fail | warning
```

Every rule **must** map its `fact` to a fact actually produced by a collector.

## Adding a collector

Subclass `BaseCollector` in `collectors/`, implement `collect()` to return a
`CollectionResult` of `Fact` objects, and register it in `scanner.make_collector`.
Collectors only *observe* — they never mutate the target and never decide
PASS/FAIL themselves.

## Adding a framework

Add a YAML file under `frameworks/<id>/` following the schema in
`compliance/registry.py`. Preserve official control/sub-control IDs and record
`source`/`verified` on every mapping. Never invent control IDs; mark unverified
links as `verified: false`.

## Mapping rules to frameworks

Rule→control links use three classes:
`direct` (verifies the requirement), `partial` (verifies part), and
`supporting_evidence` (evidence only). A single technical check is never proof
of full framework compliance.

## Conventions

- Python 3.9+ compatible.
- Read-only by default; no automatic configuration changes.
- No hardcoded credentials, keys, or secrets.
- Keep applicability decisions in `applicability/`, separate from check
  execution in `rules/`.
- Add or update tests for new behavior.

## Reporting security issues

Do **not** open a public issue for vulnerabilities — see
[SECURITY.md](SECURITY.md).
