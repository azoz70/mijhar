# MIJHAR Roadmap

## v0.2 — platform-aware redesign (current)

- [x] Python package + `mijhar` console script (Typer + Rich).
- [x] Single "Cool Arctic Cyan" terminal identity: pyfiglet MIJHAR wordmark,
      slogan, developer attribution with LinkedIn, product
      description, and a compact information panel. Microscope artwork removed.
- [x] Interactive main menu (8 options) shown at launch; a scan is never
      started automatically.
- [x] Centralized **applicability engine**: platform-aware rule selection with
      explicit structured metadata and recorded exclusion reasons.
- [x] Separate framework catalogs from executable technical checks.
- [x] Optional component detection (e.g. SSH, firewall) before dependent checks
      load.
- [x] Platform-aware compliance: controls mapping only to other-platform checks
      are marked not-applicable, never silently "not assessed" or compliant.
- [x] `NOT SUPPORTED` result status; scope-transparency "excluded checks"
      section in reports.
- [x] macOS and Linux local collectors + remote Linux (SSH).
- [x] YAML rules engine (PASS/FAIL/WARNING/NOT SUPPORTED/NOT_APPLICABLE/ERROR).
- [x] Risk scoring + prioritization.
- [x] Evidence collection with redaction + SHA-256 integrity + export.
- [x] GRC engine: NCA ECC-2:2024, SAMA CSF, CIS, ISO 27001:2022.
- [x] Mapping classification: `direct` / `partial` / `supporting_evidence`.
- [x] SQLite persistence (assets, scans, findings, exclusions, evidence,
      frameworks, controls, mappings, remediations, reviews, risk records).
- [x] Terminal / JSON / CSV / HTML reporting.
- [x] Reviewer workflow + remediation tracking + risk records + intel management.
- [x] `Created by Abdulaziz` attribution + LinkedIn.
- [x] Automated pytest suite (applicability + UI + engine).

## Next (planned)

- **More collectors:** Windows Server, Windows 10/11 endpoints, Cisco/Fortinet/
  Palo Alto network devices, AWS/Azure/GCP cloud APIs, Docker/Kubernetes,
  Web/API, databases, email/M365.
- **Framework depth:** verify SAMA control-consideration IDs against the
  official Rulebook; expand CIS/ISO coverage.
- **Intel fetchers:** optional safe HTTPS fetchers for NVD/CISA KEV/OSV.
- **Remediation workflow** beyond status/owner/due (reassessment evidence).
- **PDF reporting.**
- **AI integration** (explicitly deferred).

## Non-goals

- MIJHAR is **not** a penetration testing tool.
- It does **not** exploit vulnerabilities or modify configurations.
- It never stores plaintext credentials.
