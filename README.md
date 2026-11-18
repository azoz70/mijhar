# MIJHAR

**MIJHAR — See What Others Miss.**

A modular Technical Security Assessment Framework. MIJHAR inspects system
configurations, identifies security weaknesses, collects technical evidence,
and maps findings to recognized cybersecurity frameworks such as NCA ECC,
SAMA CSF, CIS Benchmarks, and ISO/IEC 27001.

> MIJHAR is **not** a penetration testing tool. It does not exploit
> vulnerabilities, and it is **read-only by default**.

## Demo

![MIJHAR terminal demo](demo.gif)

*Interactive main menu → supported platforms → a real macOS assessment with
platform-aware checks, colored PASS/FAIL results, and the "excluded checks"
scope-transparency table.*

## Highlights

- **Intelligent, platform-aware assessment.** The selected platform determines
  *which* technical checks are eligible *before* anything runs. A macOS scan
  loads macOS checks only; Linux and Windows checks are excluded with a
  recorded reason — never executed and never silently dropped.
- **Separate framework catalog and executable checks.** Framework controls are
  kept as a complete, versioned catalog; only the technical rules that are
  relevant to the selected platform are loaded into a scan.
- **Centralized applicability engine** with explicit rule metadata
  (platforms, required components, prerequisites, assessability, mappings).
- **Optional component detection** — e.g. SSH checks only load when an SSH
  configuration is actually detected on the target.
- **Single, calm "Cool Arctic Cyan" terminal identity** with a large MIJHAR
  wordmark, developer attribution, and an interactive main menu.
- **Linux & macOS auditors** (read-only; remote Linux over SSH).
- **YAML rules engine** with PASS / FAIL / WARNING / NOT SUPPORTED statuses.
- **Risk scoring** (transparent, configurable, severity ≠ compliance).
- **Evidence engine** with sensitive-data redaction and SHA-256 integrity.
- **GRC engine** mapping findings to four frameworks:
  - NCA Essential Cybersecurity Controls (`nca-ecc`)
  - SAMA Cyber Security Framework (`sama-csf`)
  - CIS Benchmarks (`cis`)
  - ISO/IEC 27001:2022 (`iso27001`)
- **SQLite** persistence and **JSON / CSV / HTML** reporting with a dedicated
  "excluded checks" (scope transparency) section.

## Installation (development)

Requires Python 3.9+.

```bash
git clone <repo> && cd MIJHAR
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Quick start

Run `mijhar` with no arguments to open the interactive main menu, or use the
CLI directly:

```bash
.venv/bin/mijhar                      # interactive main menu
.venv/bin/mijhar --help               # full command reference
.venv/bin/mijhar system-info
.venv/bin/mijhar scan --target local --platform macos
.venv/bin/mijhar scan --target local --platform linux
.venv/bin/mijhar scan --target remote --platform linux --host 10.0.0.5 --user audit
.venv/bin/mijhar results
.venv/bin/mijhar compliance --framework cis
.venv/bin/mijhar report --format html --output report.html
```

### Runtime data location

By default, MIJHAR stores its SQLite database and reports under the
platform data directory (`~/Library/Application Support/mijhar` on macOS,
`~/.local/share/mijhar` on Linux). Override with `MIJHAR_HOME`:

```bash
MIJHAR_HOME=/tmp/mijhar .venv/bin/mijhar scan --target local --platform macos
```

## How platform-aware assessment works

1. You select a target (macOS, Linux local, or Linux over SSH) and choose which
   framework(s) to assess (`--frameworks`, or interactively in the menu).
2. MIJHAR detects the platform and any optional components (e.g. SSH, a
   firewall) from collected facts.
3. The **applicability engine** decides, before execution, which rules are
   eligible and records an explicit reason for every excluded rule.
4. Only eligible rules execute; the report shows findings plus a dedicated
   "excluded checks" section so nothing is silently discarded.

```bash
# Assess against CIS only
mijhar scan --target local --platform macos --frameworks cis

# Assess against CIS and ISO 27001
mijhar scan --target local --platform linux --frameworks cis,iso27001
```

Result statuses: **PASS**, **FAIL**, **WARNING**, **NOT SUPPORTED**.
Exclusion reasons: `platform_incompatible`, `not_applicable`,
`not_assessable`, `missing_prerequisite`, `outside_scope`, `unsupported`,
`disabled`.

## Compliance caveats (important)

- A single automated technical check is **never** treated as proof of full
  framework compliance.
- Non-compliant / partial results are always flagged for human review.
- A control is **never** marked compliant when it could not be checked; an
  unassessable or excluded control is reported as such, not as a pass.
- **NCA ECC-2:2024** — fully enumerated (4 domains, 28 subdomains, 108 main
  controls + 91 sub-controls, extracted from the official document); rule links
  are interpretive/unverified and require reviewer validation.
- **SAMA CSF** — the 4 domains and 32 subdomains are verified from the SAMA
  Rulebook; rule links are interpretive/unverified.
- CIS/ISO control identities are sourced from public summaries/standards; rule
  links are interpretive and must be reviewed by a qualified assessor.

See [docs/COMPLIANCE.md](docs/COMPLIANCE.md) for full sourcing and status.

## Documentation

- [CLI reference](docs/CLI.md)
- [Architecture](docs/architecture.md)
- [Compliance mapping notes](docs/COMPLIANCE.md)
- [Roadmap](docs/ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Testing

```bash
.venv/bin/pytest
```

Tests use mocked command/file runners and require no administrator privileges.

## Project layout

```
src/mijhar/
  cli/            Typer commands, single-theme console, wordmark, main menu
  core/           config, models, engine, scanner
  applicability/  centralized platform-aware applicability engine
  collectors/     base, linux, macos, ssh
  rules/          YAML loader + evaluator
  risk/           scoring
  compliance/     registry, mapper, assessment (platform-aware)
  evidence/       storage (redaction + integrity)
  database/       SQLite models
  reports/        terminal, JSON, CSV, HTML
rules/            bundled YAML security rules (linux/, macos/, common/)
frameworks/       cis/, nca_ecc/, sama_csf/, iso27001/
tests/            pytest suite
docs/             documentation
```

## Author

**Created by Abdulaziz.**

- LinkedIn: https://www.linkedin.com/in/abdulaziz-alshehri/

## License

MIT License — see [LICENSE](LICENSE).
