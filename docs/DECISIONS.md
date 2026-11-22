# MIJHAR — Decision Log

This log records **documented design decisions**, not a reconstructed history of meetings or approvals. Dates reflect the documentation review unless an original decision date is independently evidenced. New consequential decisions should record their approving party, alternatives, rationale, and source (PR/issue/commit).

| ID | Decision | Rationale / trade-off | Evidence | Historical decision date | Status |
| --- | --- | --- | --- | --- | --- |
| ADR-001 | Read-only assessment by default; not a penetration testing product | Avoid changing targets and keep assessment within an explicit security boundary | [README](../README.md), [architecture](architecture.md), [security policy](../SECURITY.md) | Not established | Documented in repository |
| ADR-002 | Determine rule applicability from platform and components **before** execution, and record exclusions | Prevent cross-platform false findings and invisible scope omissions | [architecture](architecture.md), [roadmap](ROADMAP.md) | Not established | Documented in repository |
| ADR-003 | Keep framework catalogs separate from executable YAML technical rules | A complete catalog does not imply all controls are technically assessed | [architecture](architecture.md), [compliance notes](COMPLIANCE.md) | Not established | Documented in repository |
| ADR-004 | Preserve `direct`, `partial`, and `supporting_evidence` mapping classes and explicit verification flags | A technical finding does not automatically prove framework compliance | [compliance notes](COMPLIANCE.md), [contributing](../CONTRIBUTING.md) | Not established | Documented in repository |
| ADR-005 | Separate severity/risk scoring from compliance status | Risk prioritization and compliance are distinct interpretations | [architecture](architecture.md), [README](../README.md) | Not established | Documented in repository |
| ADR-006 | Use a Python Typer/Rich CLI and modular collectors; defer AI integration | Maintain a focused auditable CLI before expanding scope | [pyproject](../pyproject.toml), [roadmap](ROADMAP.md) | Not established | Documented in repository |

## Recording future decisions

Copy this template for decisions approved after this log's creation:

```markdown
### ADR-XXX — Short title
- Date: YYYY-MM-DD
- Status: Proposed | Approved | Superseded
- Decision maker / approval: <reference or "not established">
- Context:
- Options considered:
- Decision and rationale:
- Security / compliance implications:
- Source: <issue / PR / commit / document>
- Supersedes: <ADR ID or none>
```

Do not claim an entry was formally approved unless an approval record exists. Keep the roadmap in [ROADMAP.md](ROADMAP.md), and current verification state in [STATUS.md](STATUS.md).
