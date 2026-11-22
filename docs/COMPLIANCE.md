# MIJHAR Compliance Mapping Notes

MIJHAR connects technical findings to compliance frameworks through a
centralized mapping engine. This document records the sources and the
verification status of every mapping, in line with the MIJHAR mapping rules.

## Mapping rules (enforced by design)

1. Control identifiers and descriptions are never invented.
2. Official framework documents and verified sources are recorded.
3. Framework name and version are always recorded.
4. Direct vs. partial vs. supporting-evidence mappings are distinguished.
5. One finding may support many controls; one control may be supported by many
   findings.
6. A control is **never** automatically marked non-compliant from a single
   technical finding — non-compliant/partial results are flagged for human
   review (`needs_review`).
7. Unmapped findings are identifiable (see `ComplianceMapper.unmapped_rules`).
8. Licensed content is respected: only public summaries are reproduced, never
   full licensed benchmark text.

## Framework sources and status

| Framework | Identifier | Version | Status |
| --------- | ---------- | ------- | ------ |
| CIS Benchmarks | `cis` | Representative subset | Linux section numbers/titles from public summaries; macOS sections and all rule links require verification against the licensed benchmark. |
| ISO/IEC 27001:2022 | `iso27001` | 2022 Annex A | Control IDs/titles from the published standard; rule links are interpretive (partial/supporting_evidence). |
| NCA ECC | `nca-ecc` | ECC-2:2024 | **Fully enumerated**: 4 domains, 28 subdomains, 108 main controls + 91 sub-controls extracted from the official document; rule→control links are interpretive/unverified. |
| SAMA CSF | `sama-csf` | CSF (SAMA Rulebook, Circular 381000091275) | **4 domains + 32 subdomains + 220 control considerations** (extracted from the Rulebook); consideration IDs are best-effort reconstructions and rule links are unverified. |

## Official sources

- **NCA ECC-2:2024** — National Cybersecurity Authority, *Essential Cybersecurity Controls*:
  [official English PDF](https://istitlaa.ncc.gov.sa/en/security/nca/ecc22024/Documents/ECC%202-2024%20EN%2019092024.pdf).
  Control and sub-control IDs/descriptions are attributed to this document; some display titles are abbreviated and require line-by-line validation
  (TLP:White / Public). The front-matter summary states "110 controls / 90
  subcontrols" while the document body contains 108 main controls and 91
  sub-controls; MIJHAR records the body as extracted.
- **SAMA CSF** — Saudi Central Bank, published in the [SAMA Rulebook](https://www.rulebook.sama.gov.sa/):
  [Cyber Risk Control chapter](https://www.rulebook.sama.gov.sa/en/entiresection/3869).

## Important caveats

- An automated technical check is **supporting evidence**, not proof of full
  framework compliance.
- MIJHAR never claims complete framework compliance based on a limited number
  of automated checks.
- The NCA catalog is based on the official ECC-2:2024 document, but some displayed titles are abbreviated; the catalog transcription and rule-to-control links require independent reviewer validation.
- SAMA CSF names and hierarchy are based on the official Rulebook. Consideration IDs are reconstructed; their accuracy, wording, and technical rule links require independent review.

## Verification fields

Every control carries `verified` and `pending_verification`; every mapping
carries `mapping_type` (direct/partial/supporting_evidence), `source`, and `verified`.
The report and CLI surface `pending_verification` counts so reviewers can see
exactly what has not yet been validated against an official source.

## Technical assessment scope

Controls are classified as **technical** (assessable via configuration review,
system inspection, or verifiable technical evidence) or **excluded** (outside
technical scope). Every excluded control records an `excluded_reason` and is
never reported as PASS — it is marked `not_applicable` in assessments.

Excluded categories (per framework):

- **NCA ECC-2:2024** — Cybersecurity Governance (domain 1), Cybersecurity
  Resilience/BCM (domain 3), Physical Security (2-14), Third-Party (4-1).
  Cybersecurity Defense (domain 2) and Cloud Computing (4-2) remain technical.
- **SAMA CSF** — Leadership & Governance (3.1), Risk Management & Compliance
  (3.2), Human Resources (3.3.1), Physical Security (3.3.2), Third Party (3.4).
- **ISO/IEC 27001:2022** — A.5.24 (incident management planning) is excluded.
- **CIS** — the bundled subset is entirely technical.

## Mapping classification

Rule→control links use three classes: `direct` (the check verifies the
requirement), `partial` (verifies part), and `supporting_evidence` (supporting
evidence only, cannot establish compliance alone). A single technical check
never establishes full framework compliance.


See [NCA/SAMA mapping validation record](FRAMEWORK_VALIDATION.md) for evidence and outstanding verification.