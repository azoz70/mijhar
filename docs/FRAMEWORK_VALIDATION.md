# NCA ECC and SAMA CSF — Mapping Validation Record

**Review date:** 2026-11-22. **Scope:** catalog integrity and source provenance, not a formal compliance assessment.

## Official source references

- NCA ECC-2:2024: https://nca.gov.sa/en/regulatory-documents/controls-list/ecc/
- NCA official English ECC PDF: https://cdn.nca.gov.sa/api/files/public/upload/86e09090-44e4-481f-bc28-355673607654_ECC--2024-EN.pdf
- SAMA Cyber Security Framework: https://rulebook.sama.gov.sa/en/cyber-security-framework-2

These sources were checked for provenance and framework identity. A complete control-by-control comparison, including each technical mapping and control consideration, **was not performed**.

## What automated validation covers

`tests/test_catalog_integrity.py` checks:
1. Presence of both framework catalogs and absence of duplicate IDs within each catalog.
2. Each recorded rule-to-control mapping references an executable rule currently bundled with MIJHAR.
3. Interpretive NCA/SAMA links remain `verified: false`, rather than being described as regulatory assurance.
4. The catalog includes controls without technical mappings and controls excluded from technical assessment.

Those are **structural tests**. Passing cannot establish regulatory accuracy, applicability, operational effectiveness, or compliance.

## Known uncertainties and required human review

| Item | Current basis | Remaining validation |
| --- | --- | --- |
| NCA ECC-2:2024 | Repository catalog cites the official framework; structure tested in CI | Independently reconcile each ID, full control text, and current applicability with the official PDF |
| NCA display titles | Some catalog `title` values end with `...` (abbreviated) although the repository previously described titles as verbatim | Review and reconcile title/description accuracy before certifying transcription |
| SAMA CSF | Official Rulebook identifies framework hierarchy and considerations | Validate reconstructed consideration IDs and the precise wording against source |
| Mapping technical checks | All NCA/SAMA rule links are intentionally `verified: false` | Reviewer must check specific requirement, evidence, applicability and `direct`/`partial`/`supporting_evidence` class |
| CIS and ISO | Not part of this NCA/SAMA audit | Independent benchmark/version/license verification required |

**Review gate:** Never change an interpretive mapping to `verified: true` solely because its structural test passes. Record the official section, evidence, reviewer, and verification date before approval.

## Confirmed SAMA catalog defect and scoped correction

The initial structural test detected duplicate IDs `3.3.17.1`, `3.3.17.2`, and `3.3.17.3`. Inspection found four vendor-management considerations incorrectly nested under `3.3.17 Vulnerability Management`. SAMA's official [3.4.1 Contract and Vendor Management](https://rulebook.sama.gov.sa/en/341-contract-and-vendor-management-0) clearly identifies considerations 1 through 4 as belonging to `3.4.1`.

The four misplaced records were moved to `3.4.1.1` through `3.4.1.4`, with their source-grounded titles and third-party classification. This corrects only those four records. The remaining reconstructed SAMA IDs, subcontrols, and mappings have **not** received a full authoritative audit.

## Platform validation

`.github/workflows/platform-smoke.yml` builds a fresh wheel, installs it into a clean virtual environment on GitHub-hosted `ubuntu-24.04` and `macos-15`, runs a **local read-only** scan with CIS-only mapping, and verifies that JSON, CSV, and HTML reports can be produced. Data remains temporary on the runner and is deleted in cleanup.

This validates those hosted runner environments only. It does not demonstrate equivalence to an organization's endpoints, verify remote SSH operation, prove all facts are accurate, or certify macOS version compatibility beyond the tested runner.
