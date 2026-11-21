# MIJHAR Architecture

MIJHAR is a modular, read-only Technical Security Assessment Framework.

## Design principles

- **Read-only by default.** Collectors never modify the target.
- **Separation of concerns.** Collection, applicability, evaluation, risk,
  compliance, and reporting are independent engines.
- **Platform determines scope.** The selected platform decides which checks are
  eligible *before* execution; unrelated checks are excluded with a reason.
- **Framework catalog ≠ executable checks.** Framework controls are a complete,
  versioned catalog; only relevant technical rules load into a platform scan.
- **Severity != compliance.** Technical severity and compliance status are
  computed separately and never conflated.
- **No invented compliance content.** Framework mappings record their source,
  version, and verification status; unverified mappings are marked pending.

## Component overview

```
collectors/     -> facts (raw system state)
applicability/  -> platform-aware rule selection + exclusions (BEFORE execution)
rules/          -> rules (YAML) + evaluation -> findings
risk/           -> severity/impact scoring -> risk assessments
evidence/       -> redaction + SHA-256 integrity
compliance/     -> framework registry + mapping + platform-aware control assessment
reports/        -> terminal, JSON, CSV, HTML (incl. scope transparency)
database/       -> SQLite persistence (assets, scans, findings, exclusions, ...)
core/           -> config, models, scanner orchestration, engine facade
cli/            -> Typer commands + single-theme terminal identity + main menu
```

## Data flow

```
Target -> Collector -> Facts
                         |
                         v
ApplicabilityEngine (platform + components) -> included rules + exclusions
                         |
                         v
Rules (YAML) -> RuleEvaluator -> Findings (severity + status + evidence)
                         |
        +----------------+----------------+
        v                                 v
RiskScorer                          ControlAssessor (platform-aware)
(risk score, priority)              (framework -> control status, gaps)
        \                                 /
         \                               /
          +------------> Persistence (SQLite)
                                  |
                                  v
                           Reporting (terminal/JSON/CSV/HTML)
```

## Applicability vs. assessability vs. execution

MIJHAR keeps three concepts separate:

- **Applicability** — is the rule/control relevant to the selected platform?
  Decided from structured platform metadata, never keyword matching.
- **Assessability** — can the requirement be verified from this endpoint? An
  organizational control may be relevant yet not assessable from one host.
- **Execution** — only eligible rules run; every other rule is recorded as an
  exclusion with a reason (`platform_incompatible`, `not_applicable`,
  `not_assessable`, `missing_prerequisite`, `outside_scope`, `unsupported`,
  `disabled`).

Framework catalogs remain complete and separate from executable checks: a
control is only marked applicable in a platform scan when at least one of its
mapped rules is selected for that platform.

## Key models

- **Fact** — a single collected system value (key, value, raw, source, error).
- **Rule** — a technical check plus applicability metadata (platforms, required
  components, prerequisites, assessability, framework mappings).
- **Finding** — a rule evaluated against facts (severity, status, evidence,
  remediation, framework references).
- **RiskAssessment** — severity weight × impact multiplier → 0–100 score.
- **Framework / Control / ControlMapping** — compliance structure with
  `direct` / `partial` / `supporting_evidence` mapping types and verification
  flags.
- **EvidenceRecord** — redacted evidence with a SHA-256 digest.
- **Exclusion** — a rule/control left out of a scan, with a reason.

## Status semantics

| Status | Meaning |
| ------ | ------- |
| `pass` | The check condition holds. |
| `fail` | The check condition does not hold. |
| `warning` | Below-policy but not a hard failure (configurable per rule). |
| `not_supported` | MIJHAR cannot assess this on the target. |
| `not_applicable` | The fact was not collected or is not comparable. |
| `error` | Collection failed (missing tool, insufficient privilege, parse error). |

## Risk model

`score = severity_weight * business_impact_multiplier`, capped at 100. Defaults
are defined in `risk/scoring.py` and are fully configurable via `RiskConfig`.
Score bands map back to a risk level (critical/high/medium/low/informational).

## Extensibility

- **New collectors:** subclass `BaseCollector` and register it in
  `Engine.register_collector`.
- **New rules:** add a YAML file under `src/mijhar/rules/data/<platform>/` with applicability
  metadata (platforms, `required_components`, `prerequisites`,
  `technical_assessability`, `framework_mappings`).
- **New frameworks:** add a YAML file under `src/mijhar/compliance/data/<id>/` following the
  schema in `compliance/registry.py`.
