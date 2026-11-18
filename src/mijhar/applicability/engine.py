"""Platform-aware applicability engine.

The engine's job is narrow and explicit: given a selected platform, a target,
detected optional components, and the full set of technical rules, it decides
which rules are eligible to run and *why* every other rule is excluded.

It never evaluates a check and never mutates a target. The decisions it
produces feed the scanner, which executes only the *included* rules, and the
report, which shows the exclusion reasons for full scope transparency.

Terminology (kept deliberately distinct):

- **Included**      — eligible: applicable platform, assessable, supported, and
                      all prerequisites/components are satisfied. Will execute.
- **Not applicable**— the rule genuinely does not apply to this platform/target.
- **Not assessable**— relevant to the organization but not verifiable by
                      inspecting this single endpoint/target.
- **Unsupported**   — MIJHAR does not currently implement the capability.
- **Missing prerequisite** — the rule applies, but a required component or
                      permission is absent on this target.
- **Outside scope** — excluded by the selected assessment profile.
- **Disabled**      — the rule is present but marked ``enabled: false``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Optional, Set

from mijhar.collectors.base import Fact
from mijhar.core.config import Platform
from mijhar.rules.loader import Rule


class ExclusionReason(str, Enum):
    """Why a rule was excluded from a platform-specific scan."""

    PLATFORM_INCOMPATIBLE = "platform_incompatible"
    NOT_APPLICABLE = "not_applicable"
    NOT_ASSESSABLE = "not_assessable"
    MISSING_PREREQUISITE = "missing_prerequisite"
    OUTSIDE_SCOPE = "outside_scope"
    UNSUPPORTED = "unsupported"
    DISABLED = "disabled"


@dataclass(frozen=True)
class Exclusion:
    """One excluded rule with the reason and a human-readable explanation."""

    rule_id: str
    title: str
    reason: ExclusionReason
    detail: str = ""


@dataclass
class ApplicabilityResult:
    """The outcome of an applicability decision pass."""

    included: List[Rule] = field(default_factory=list)
    excluded: List[Exclusion] = field(default_factory=list)
    capabilities: Set[str] = field(default_factory=set)
    platform: Optional[Platform] = None

    @property
    def included_ids(self) -> List[str]:
        return [r.id for r in self.included]

    def excluded_count(self, reason: ExclusionReason) -> int:
        return sum(1 for e in self.excluded if e.reason is reason)


# ---------------------------------------------------------------------------
# Optional component detection.
#
# A component is "detected" when the collected facts provide positive evidence
# that the product/service is present and (where relevant) active. Detection is
# deliberately conservative: a missing or unobservable component is reported as
# absent, never treated as evidence of compliance.
# ---------------------------------------------------------------------------

def _fact_map(facts: Iterable[Fact]) -> Dict[str, Fact]:
    return {f.key: f for f in facts}


def detect_capabilities(facts: Iterable[Fact], platform: Optional[Platform] = None) -> Set[str]:
    """Return the set of optional components detected from collected facts.

    This is the *single* place that translates raw facts into capability
    names, so rule ``required_components`` stay platform-neutral.

    Detection is conservative: a component is only reported when there is
    positive evidence it is present (a readable config, an observable state).
    """
    fm = _fact_map(facts)
    caps: Set[str] = set()

    def _value(key: str) -> bool:
        f = fm.get(key)
        return f is not None and f.value is not None and f.error is None

    # SSH server/daemon configuration present on the target (a real, parsed
    # config or an observed directive — not merely a probe that ran).
    ssh_cfg = fm.get("ssh.config")
    ssh_present = (
        ssh_cfg is not None
        and ssh_cfg.error is None
        and bool(ssh_cfg.value)
    ) or any(
        _value(k)
        for k in ("ssh.permit_root_login", "ssh.password_authentication",
                  "ssh.permit_empty_passwords", "ssh.x11_forwarding")
    )
    if ssh_present or (platform is Platform.MACOS and "remote_login.enabled" in fm):
        caps.add("ssh")

    # A host firewall is observable (active or configured).
    if any(_value(k) for k in (
        "firewall.any_active", "firewall.enabled", "firewall.globalstate",
        "firewall.ufw_active", "firewall.firewalld_running",
    )):
        caps.add("firewall")

    # Disk encryption surface.
    if _value("filevault.enabled"):
        caps.add("disk-encryption")

    # Mandatory access control (SELinux/AppArmor) observable on Linux.
    if any(_value(k) for k in ("selinux.status", "apparmor.status")):
        caps.add("mac")

    return caps


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class ApplicabilityEngine:
    """Decide, before execution, which rules are eligible for a scan."""

    def __init__(
        self,
        platform: Platform,
        rules: Iterable[Rule],
        capabilities: Optional[Set[str]] = None,
        scope: Optional[Set[str]] = None,
    ) -> None:
        self.platform = platform
        self.rules = list(rules)
        self.capabilities = set(capabilities or ())
        # ``scope`` restricts by assessment_type (e.g. {"configuration"}).
        self.scope = scope

    def evaluate(self) -> ApplicabilityResult:
        result = ApplicabilityResult(platform=self.platform, capabilities=set(self.capabilities))
        for rule in self.rules:
            decision = self._decide(rule)
            if decision is None:
                result.included.append(rule)
            else:
                result.excluded.append(decision)
        return result

    def _decide(self, rule: Rule) -> Optional[Exclusion]:
        """Return an :class:`Exclusion` if the rule must not run, else ``None``."""
        if not rule.enabled:
            return Exclusion(rule.id, rule.title, ExclusionReason.DISABLED,
                             "Rule is present but disabled in its metadata.")

        # Platform applicability is decided from structured platform metadata,
        # not keyword matching.
        if not rule.applies_to(self.platform):
            others = ", ".join(p.value for p in rule.platforms if p is not Platform.UNKNOWN) or "cross-platform"
            return Exclusion(rule.id, rule.title, ExclusionReason.PLATFORM_INCOMPATIBLE,
                             f"Rule targets {others}; not part of a {self.platform.value} scan.")

        # A rule may be relevant to an organization but not assessable from a
        # single endpoint (e.g. enterprise-wide policy). Such rules are never
        # silently dropped — they are recorded as not-assessable.
        if rule.technical_assessability == "not_assessable":
            return Exclusion(rule.id, rule.title, ExclusionReason.NOT_ASSESSABLE,
                             "Relevant to the organization but cannot be verified from this target.")

        if rule.technical_assessability == "unsupported":
            return Exclusion(rule.id, rule.title, ExclusionReason.UNSUPPORTED,
                             "MIJHAR does not currently implement this assessment capability.")

        # Optional component prerequisites.
        for component in rule.required_components:
            if component not in self.capabilities:
                return Exclusion(rule.id, rule.title, ExclusionReason.MISSING_PREREQUISITE,
                                 f"Required component '{component}' was not detected on the target.")

        # Explicit declared prerequisites (permissions, products, evidence).
        if rule.prerequisites:
            missing = [p for p in rule.prerequisites if p not in self.capabilities]
            if missing:
                return Exclusion(rule.id, rule.title, ExclusionReason.MISSING_PREREQUISITE,
                                 f"Prerequisite not satisfied: {', '.join(missing)}.")

        # Assessment-profile scope restriction.
        if self.scope is not None and rule.assessment_type not in self.scope:
            return Exclusion(rule.id, rule.title, ExclusionReason.OUTSIDE_SCOPE,
                             f"Assessment type '{rule.assessment_type}' is outside the selected scope.")

        return None
