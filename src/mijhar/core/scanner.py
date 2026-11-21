"""Scan orchestration: collector -> rules -> findings -> risk -> evidence -> compliance.

The :class:`Scanner` wires the independent MIJHAR engines together and
persists the result to SQLite. It is read-only against the target.
"""

from __future__ import annotations

import socket
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from mijhar.collectors.base import BaseCollector, CollectionResult, Fact
from mijhar.collectors.linux import LinuxCollector
from mijhar.collectors.macos import MacOSCollector
from mijhar.applicability.engine import ApplicabilityEngine, Exclusion, detect_capabilities
from mijhar.compliance.assessment import ComplianceSummary, ControlAssessor, ControlAssessment
from mijhar.compliance.registry import Framework, FrameworkRegistry
from mijhar.core.config import Config, Platform, Status, get_config
from mijhar.core.models import Finding
from mijhar.database.models import Database, _loads
from mijhar.evidence.storage import EvidenceRecord, EvidenceStore, redact_finding_evidence, redact_value
from mijhar.risk.scoring import RiskAssessment, RiskScorer
from mijhar.rules.evaluator import RuleEvaluator
from mijhar.rules.loader import Rule, RuleLoader


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _severity_distribution(findings: List[Finding]) -> Dict[str, int]:
    dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for finding in findings:
        key = finding.severity.value
        if key in dist:
            dist[key] += 1
    return dist


def _remediation_summary(db: Database, scan_id: str) -> Dict[str, int]:
    summary = {"open": 0, "in_progress": 0, "pending_validation": 0, "resolved": 0, "accepted_risk": 0}
    for item in db.list_remediations(scan_id=scan_id):
        status = item["status"]
        if status in summary:
            summary[status] += 1
    return summary


def _detect_os_info(facts: List[Fact], platform: Platform) -> Dict[str, str]:
    """Derive the detected OS name/version from collected facts."""
    fm = {f.key: f for f in facts}
    info = {"name": platform.value}
    if platform is Platform.MACOS:
        version = fm.get("os.version")
        if version and version.value:
            info["version"] = str(version.value)
    elif platform is Platform.LINUX:
        release = fm.get("os.release")
        if release and isinstance(release.value, dict):
            name = release.value.get("PRETTY_NAME") or release.value.get("NAME")
            version = release.value.get("VERSION_ID") or release.value.get("VERSION")
            if name:
                info["name"] = str(name)
            if version:
                info["version"] = str(version)
    return info


@dataclass
class ScanResult:
    """Everything produced by one scan, held in memory for reporting."""

    scan_id: str
    asset_id: str
    platform: Platform
    started_at: str
    ended_at: str
    facts: List[Fact] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    rules_applied: int = 0
    risk_assessments: List[RiskAssessment] = field(default_factory=list)
    compliance: Dict[str, ComplianceSummary] = field(default_factory=dict)
    evidence: List[EvidenceRecord] = field(default_factory=list)
    exclusions: List[Exclusion] = field(default_factory=list)
    capabilities: set = field(default_factory=set)
    os_info: Dict[str, str] = field(default_factory=dict)

    @property
    def counts(self) -> Dict[str, int]:
        return {
            "total": len(self.findings),
            "passed": sum(1 for f in self.findings if f.status is Status.PASS),
            "failed": sum(1 for f in self.findings if f.status is Status.FAIL),
            "warnings": sum(1 for f in self.findings if f.status is Status.WARNING),
            "not_supported": sum(1 for f in self.findings if f.status is Status.NOT_SUPPORTED),
            "errors": sum(1 for f in self.findings if f.status is Status.ERROR),
            "excluded": len(self.exclusions),
        }

    def as_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "asset_id": self.asset_id,
            "platform": self.platform.value,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "os_info": self.os_info,
            "counts": self.counts,
            "findings": [f.as_dict() for f in self.findings],
            "exclusions": [self._exclusion_dict(e) for e in self.exclusions],
            "compliance": {k: v.as_dict() for k, v in self.compliance.items()},
        }

    @staticmethod
    def _exclusion_dict(exclusion: Exclusion) -> dict:
        return {
            "rule_id": exclusion.rule_id,
            "title": exclusion.title,
            "reason": exclusion.reason.value,
            "detail": exclusion.detail,
        }

    def exclusion_dicts(self) -> List[dict]:
        return [self._exclusion_dict(e) for e in self.exclusions]


class Scanner:
    """Run a configuration security scan and persist the result."""

    def __init__(
        self,
        config: Optional[Config] = None,
        rules_dir: Optional[Path] = None,
        frameworks_dir: Optional[Path] = None,
        db_path: Optional[Path] = None,
    ) -> None:
        self.config = config or get_config()
        self.rules_dir = rules_dir or self.config.rules_dir
        self.frameworks_dir = frameworks_dir or self.config.frameworks_dir
        self.db_path = db_path or self.config.db_path

    def make_collector(
        self,
        platform: Platform,
        target: str = "local",
        **kwargs,
    ) -> BaseCollector:
        if target == "remote":
            # Remote collection adapter (Phase 9).
            from mijhar.collectors.ssh import SSHCollector  # local import

            return SSHCollector(**kwargs)
        if platform is Platform.MACOS:
            return MacOSCollector()
        if platform is Platform.LINUX:
            return LinuxCollector()
        raise ValueError(f"unsupported platform for local scan: {platform.value}")

    def run(
        self,
        platform: Platform,
        target: str = "local",
        asset_id: Optional[str] = None,
        collector_kwargs: Optional[dict] = None,
        framework_ids: Optional[List[str]] = None,
    ) -> ScanResult:
        collector_kwargs = collector_kwargs or {}
        started = _now()
        asset_id = asset_id or socket.gethostname()

        collector = self.make_collector(platform, target, **collector_kwargs)
        collection: CollectionResult = collector.collect()

        rules: List[Rule] = RuleLoader(self.rules_dir).load()

        # -- platform-aware applicability, decided BEFORE any check executes --
        capabilities = detect_capabilities(collection.facts, platform)
        applicability = ApplicabilityEngine(
            platform, rules, capabilities=capabilities
        ).evaluate()
        included_rule_ids = set(applicability.included_ids)

        findings = RuleEvaluator().evaluate_all(
            applicability.included, collection.facts, asset_id=asset_id, platform=platform
        )

        risk = RiskScorer().assess_all(findings)

        evidence_store = EvidenceStore()
        evidence = [evidence_store.add_for_finding(f, asset_id) for f in findings]
        findings = [
            replace(
                finding,
                observed_value=redact_value(finding.observed_value, key=finding.fact_key),
                evidence=redact_finding_evidence(finding.evidence, finding.fact_key),
            )
            for finding in findings
        ]

        compliance = self.assess_compliance(
            findings, platform=platform, included_rule_ids=included_rule_ids,
            framework_ids=framework_ids,
        )

        result = ScanResult(
            scan_id=f"S-{uuid.uuid4().hex[:10]}",
            asset_id=asset_id,
            platform=platform,
            started_at=started,
            ended_at=_now(),
            facts=collection.facts,
            findings=findings,
            rules_applied=len(applicability.included),
            risk_assessments=risk,
            compliance=compliance,
            evidence=evidence,
            exclusions=applicability.excluded,
            capabilities=capabilities,
            os_info=_detect_os_info(collection.facts, platform),
        )

        self._persist(result, framework_ids=framework_ids)
        return result

    # -- persistence --------------------------------------------------------

    def _persist(self, result: ScanResult, framework_ids: Optional[List[str]] = None) -> None:
        with Database(self.db_path) as db:
            db.upsert_asset(
                asset_id=result.asset_id,
                name=result.asset_id,
                platform=result.platform.value,
                created_at=result.started_at,
            )
            db.create_scan(result.scan_id, result.asset_id, platform=result.platform.value, started_at=result.started_at)
            for rule in RuleLoader(self.rules_dir).load():
                db.insert_rule(
                    rule.id,
                    rule.title,
                    rule.severity.value,
                    [p.value for p in rule.platforms],
                    rule.check.fact,
                    rule.check.operator,
                    rule.check.value,
                )
            for finding in result.findings:
                db.insert_finding(finding)
                db.set_finding_scan(finding.id, result.scan_id)
                if finding.status in (Status.FAIL, Status.WARNING):
                    db.insert_remediation(
                        remediation_id=f"R-{finding.id}",
                        finding_id=finding.id,
                        recommendation=finding.remediation or "No remediation guidance recorded.",
                        status="open",
                        created_at=result.ended_at,
                    )
            for record in result.evidence:
                db.insert_evidence(record)
            for exclusion in result.exclusions:
                db.insert_exclusion(
                    result.scan_id, exclusion.rule_id, exclusion.title,
                    exclusion.reason.value, exclusion.detail,
                )
            registry = FrameworkRegistry(self.frameworks_dir)
            registry.load()
            for framework in registry.list():
                db.save_framework(framework)
            db.set_scan_frameworks(result.scan_id, framework_ids)
            db.finalize_scan(
                result.scan_id,
                result.ended_at,
                "completed",
                result.counts,
            )

    def assess_compliance(
        self,
        findings: List[Finding],
        platform: Optional[Platform] = None,
        included_rule_ids: Optional[set] = None,
        framework_ids: Optional[List[str]] = None,
    ) -> Dict[str, ComplianceSummary]:
        """Assess frameworks against a set of findings.

        ``framework_ids`` restricts assessment to the selected frameworks
        (``None``/empty = all). When ``platform``/``included_rule_ids`` are
        supplied, controls whose mappings point *only* to rules for other
        platforms are recorded as not applicable to this platform rather than
        being silently assessed as "not assessed".
        """
        registry = FrameworkRegistry(self.frameworks_dir)
        registry.load()
        selected = set(framework_ids) if framework_ids else None
        assessor = ControlAssessor()
        compliance: Dict[str, ComplianceSummary] = {}
        for framework in registry.list():
            if selected is not None and framework.id not in selected:
                continue
            assessments = assessor.assess(
                framework, findings, platform=platform, included_rule_ids=included_rule_ids
            )
            compliance[framework.id] = assessor.summary(framework, assessments)
        return compliance

    def assess_framework(
        self,
        findings: List[Finding],
        framework_id: str,
        platform: Optional[Platform] = None,
        included_rule_ids: Optional[set] = None,
    ) -> tuple[Framework, List[ControlAssessment], ComplianceSummary]:
        """Assess a single framework, returning the full per-control detail."""
        registry = FrameworkRegistry(self.frameworks_dir)
        registry.load()
        framework = registry.get(framework_id)
        if framework is None:
            raise ValueError(f"unknown framework: {framework_id}")
        assessor = ControlAssessor()
        assessments = assessor.assess(
            framework, findings, platform=platform, included_rule_ids=included_rule_ids
        )
        return framework, assessments, assessor.summary(framework, assessments)

    # -- query helpers for the CLI -----------------------------------------

    def latest_scan_id(self) -> Optional[str]:
        with Database(self.db_path) as db:
            scans = db.list_scans(limit=1)
            return scans[0]["id"] if scans else None

    def list_scans(self, limit: int = 20) -> List[dict]:
        with Database(self.db_path) as db:
            return db.list_scans(limit=limit)

    def findings_for_scan(self, scan_id: str) -> List[dict]:
        with Database(self.db_path) as db:
            return db.findings_for_scan(scan_id)

    def findings_objects_for_scan(self, scan_id: str) -> List[Finding]:
        return [Finding.from_dict(f) for f in self.findings_for_scan(scan_id)]

    def build_report_data(self, scan_id: str) -> dict:
        """Assemble a full serializable report for a stored scan."""
        with Database(self.db_path) as db:
            scan = db.get_scan(scan_id)
            if scan is None:
                raise ValueError(f"unknown scan id: {scan_id}")
            finding_dicts = db.findings_for_scan(scan_id)
            exclusions = db.exclusions_for_scan(scan_id)
            finding_reviews = {r["finding_id"] for r in db.list_finding_reviews()}
            remediation_counts = _remediation_summary(db, scan_id)
        findings = [Finding.from_dict(f) for f in finding_dicts]
        platform = Platform(scan["platform"]) if scan["platform"] else Platform.UNKNOWN
        included_rule_ids = {f.rule_id for f in findings}
        framework_ids = _loads(scan.get("frameworks"))
        if framework_ids and not isinstance(framework_ids, list):
            framework_ids = None
        compliance = self.assess_compliance(
            findings, platform=platform, included_rule_ids=included_rule_ids,
            framework_ids=framework_ids,
        )
        counts = {
            "total": scan["checks_total"],
            "passed": scan["passed"],
            "failed": scan["failed"],
            "warnings": scan["warnings"],
            "not_supported": sum(1 for f in findings if f.status is Status.NOT_SUPPORTED),
            "errors": scan["errors"],
            "excluded": len(exclusions),
        }
        severity_distribution = _severity_distribution(findings)
        reviewed = sum(1 for f in finding_dicts if f["id"] in finding_reviews)
        return {
            "scan_id": scan_id,
            "asset_id": scan["asset_id"],
            "platform": scan["platform"],
            "frameworks": framework_ids,
            "started_at": scan["started_at"],
            "ended_at": scan["ended_at"],
            "counts": counts,
            "severity_distribution": severity_distribution,
            "review": {"reviewed": reviewed, "total": len(finding_dicts)},
            "remediation": remediation_counts,
            "findings": finding_dicts,
            "exclusions": exclusions,
            "compliance": {k: v.as_dict() for k, v in compliance.items()},
        }
