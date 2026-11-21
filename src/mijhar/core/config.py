"""Central configuration, shared constants, and enums for MIJHAR.

This module is the single source of truth for severity levels, finding
statuses, platform identifiers, and runtime paths. It keeps no secrets and
contains no credentials.
"""

from __future__ import annotations

import os
import platform as _platform
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict

APP_NAME = "MIJHAR"
TAGLINE = "See What Others Miss."
VERSION = "0.2.0"

# Preferred environment variable used to relocate all MIJHAR runtime data.
# This is honoured first so tests and CI can use an isolated directory.
ENV_HOME = "MIJHAR_HOME"


class Severity(str, Enum):
    """Finding severity levels.

    Severity is a *technical risk* classification and is intentionally kept
    distinct from *compliance status*. A single failed technical check must
    never be treated as proof that a framework control is non-compliant.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


SEVERITY_RANK: Dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFORMATIONAL: 1,
}


class Status(str, Enum):
    """Result status of a single configuration check."""

    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    NOT_SUPPORTED = "not_supported"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class Platform(str, Enum):
    """Supported target platforms.

    Only platforms with a working collector are listed as *implemented*;
    ``WINDOWS`` is recognized for detection purposes but has no collector yet.
    """

    LINUX = "linux"
    MACOS = "macos"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PlatformModule:
    """A declared assessment platform/module and its implementation status.

    This registry is the single source of truth the terminal information panel
    and the "supported platforms" screen read from, so the displayed counts
    always reflect what is actually implemented rather than an invented list.
    """

    id: str
    name: str
    platforms: tuple = ()
    targets: tuple = ("local",)
    implemented: bool = True
    description: str = ""


# Assessment modules that ship a working collector today.
IMPLEMENTED_MODULES: tuple = (
    PlatformModule(
        id="macos",
        name="macOS",
        platforms=(Platform.MACOS,),
        targets=("local",),
        implemented=True,
        description="FileVault, firewall, Gatekeeper, SIP, updates, screen lock, admin accounts, remote login.",
    ),
    PlatformModule(
        id="linux",
        name="Linux",
        platforms=(Platform.LINUX,),
        targets=("local", "remote"),
        implemented=True,
        description="SSH config, firewall, users/groups, password policy, file permissions, services, audit logging, updates.",
    ),
    PlatformModule(
        id="linux-ssh",
        name="Linux (remote over SSH)",
        platforms=(Platform.LINUX,),
        targets=("remote",),
        implemented=True,
        description="Same Linux checks over a key-based, read-only SSH connection.",
    ),
)

# Declared but not yet implemented modules (shown as "planned" in the UI).
PLANNED_MODULES: tuple = (
    PlatformModule(id="windows", name="Windows", implemented=False,
                   description="Microsoft Defender, BitLocker, firewall, updates, accounts, PowerShell, audit."),
    PlatformModule(id="network", name="Network Devices", implemented=False,
                   description="Management access, SSH/SNMP, firewall rules, firmware, hardening."),
    PlatformModule(id="aws", name="AWS", implemented=False,
                   description="IAM, MFA, S3 exposure, security groups, CloudTrail, encryption, logging."),
    PlatformModule(id="azure", name="Microsoft Azure", implemented=False,
                   description="Entra ID, MFA, NSG, storage, activity log, encryption."),
    PlatformModule(id="gcp", name="Google Cloud Platform", implemented=False,
                   description="IAM, MFA, storage exposure, VPC, logging, encryption."),
    PlatformModule(id="docker", name="Docker / Containers", implemented=False,
                   description="Image config, daemon hardening, secrets, runtime."),
    PlatformModule(id="kubernetes", name="Kubernetes", implemented=False,
                   description="RBAC, pod security, network policies, secrets, audit."),
)

# Platforms with at least one implemented module.
IMPLEMENTED_PLATFORMS: tuple = (Platform.MACOS, Platform.LINUX)


def implemented_module_count() -> int:
    """Number of assessment modules that are actually implemented."""
    return len(IMPLEMENTED_MODULES)


def implemented_platform_count() -> int:
    """Number of platforms with at least one implemented module."""
    return len(IMPLEMENTED_PLATFORMS)


def detect_platform(system: str | None = None) -> Platform:
    """Map an OS name (or the current host when omitted) to a Platform."""
    name = (system or _platform.system()).strip().lower()
    if name == "darwin":
        return Platform.MACOS
    if name == "linux":
        return Platform.LINUX
    if name in ("windows", "win32"):
        return Platform.WINDOWS
    return Platform.UNKNOWN


def _data_dir_platform_component() -> Path:
    """Return the per-user data base directory for the current OS."""
    system = _platform.system()
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support"
    if system == "Windows":
        appdata = os.environ.get("APPDATA")
        return Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
    xdg = os.environ.get("XDG_DATA_HOME")
    return Path(xdg) if xdg else Path.home() / ".local" / "share"


def get_data_dir() -> Path:
    """Return the MIJHAR data directory (overridable via ``MIJHAR_HOME``)."""
    override = os.environ.get(ENV_HOME)
    if override:
        return Path(override).expanduser()
    return _data_dir_platform_component() / "mijhar"


_PACKAGE_DIR = Path(__file__).resolve().parents[1]


@dataclass
class Config:
    """Runtime configuration resolved from defaults and environment."""

    app_name: str = APP_NAME
    version: str = VERSION
    data_dir: Path = field(default_factory=get_data_dir)
    db_path: Path | None = None
    rules_dir: Path | None = None
    frameworks_dir: Path | None = None
    reports_dir: Path | None = None

    def __post_init__(self) -> None:
        if self.db_path is None:
            self.db_path = self.data_dir / "mijhar.db"
        if self.rules_dir is None:
            self.rules_dir = _PACKAGE_DIR / "rules" / "data"
        if self.frameworks_dir is None:
            self.frameworks_dir = _PACKAGE_DIR / "compliance" / "data"
        if self.reports_dir is None:
            self.reports_dir = self.data_dir / "reports"

    def ensure_dirs(self) -> None:
        """Create runtime directories that MIJHAR may write to."""
        for directory in (self.data_dir, self.reports_dir):
            directory.mkdir(parents=True, exist_ok=True)


def get_config() -> Config:
    """Return a freshly-resolved :class:`Config`."""
    return Config()


def severity_rank(severity: Severity | str) -> int:
    """Return the numeric rank of a severity (higher is more severe)."""
    return SEVERITY_RANK[Severity(severity)]
