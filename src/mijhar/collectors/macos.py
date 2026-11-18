"""macOS local collector.

Gathers read-only security configuration facts using standard system tools
(``fdesetup``, ``spctl``, ``csrutil``, ``defaults``, ``dscl``, ``sw_vers``).
Privileged probes degrade gracefully to an ``error`` fact instead of failing
the whole collection.
"""

from __future__ import annotations

from typing import List, Optional

from mijhar.collectors.base import BaseCollector, CollectionResult, Fact
from mijhar.core.config import Platform

_FIREWALL_SOCKETFILTERFW = (
    "/usr/libexec/ApplicationFirewall/socketfilterfw"
)


def parse_filevault(output: str) -> Optional[bool]:
    text = output.lower()
    if "filevault is on" in text:
        return True
    if "filevault is off" in text:
        return False
    return None


def parse_on_off(output: str) -> Optional[bool]:
    text = output.lower()
    if " on" in text or text.startswith("on") or "enabled" in text:
        return True
    if " off" in text or text.startswith("off") or "disabled" in text:
        return False
    return None


def parse_bool_int(output: str) -> Optional[bool]:
    value = output.strip()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    return None


def parse_int(output: str) -> Optional[int]:
    try:
        return int(output.strip())
    except ValueError:
        return None


def parse_group_membership(output: str) -> List[str]:
    """Parse ``GroupMembership: a b c`` into a list of account names."""
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("GroupMembership:"):
            return line.split(":", 1)[1].split()
    return []


def parse_sip(output: str) -> Optional[bool]:
    text = output.lower()
    if "status: enabled" in text:
        return True
    if "status: disabled" in text:
        return False
    return None


class MacOSCollector(BaseCollector):
    """Collect macOS security configuration facts."""

    platform = Platform.MACOS
    name = "macos"

    def collect(self) -> CollectionResult:
        facts: List[Fact] = []
        facts.append(self._os_version())
        facts.append(self._architecture())
        facts.append(self._filevault())
        facts.append(self._firewall_state())
        facts.append(self._firewall_enabled())
        facts.append(self._gatekeeper())
        facts.append(self._sip())
        facts.append(self._automatic_update("autoupdate.check_enabled", "AutomaticCheckEnabled"))
        facts.append(self._automatic_update("autoupdate.download_enabled", "AutomaticDownload"))
        facts.append(self._automatic_update("autoupdate.install_config_data", "ConfigDataInstall"))
        facts.append(self._automatic_update("autoupdate.install_critical", "CriticalUpdateInstall"))
        facts.append(self._screen_lock_password())
        facts.append(self._screen_lock_delay())
        facts.append(self._admin_accounts())
        facts.append(self._remote_login())
        return CollectionResult(collector=self.name, platform=self.platform, facts=facts)

    # -- probes ------------------------------------------------------------

    def _os_version(self) -> Fact:
        result = self.run(["sw_vers", "-productVersion"])
        return self._fact("os.version", result, parse=lambda o: o.strip() or None)

    def _architecture(self) -> Fact:
        result = self.run(["uname", "-m"])
        return self._fact("os.architecture", result, parse=lambda o: o.strip() or None)

    def _filevault(self) -> Fact:
        result = self.run(["fdesetup", "status"])
        return self._fact("filevault.enabled", result, parse=parse_filevault)

    def _firewall_state(self) -> Fact:
        result = self.run(
            ["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"]
        )
        return self._fact("firewall.globalstate", result, parse=parse_int)

    def _firewall_enabled(self) -> Fact:
        result = self.run([_FIREWALL_SOCKETFILTERFW, "--getglobalstate"])
        return self._fact("firewall.enabled", result, parse=parse_on_off)

    def _gatekeeper(self) -> Fact:
        result = self.run(["spctl", "--status"])
        return self._fact("gatekeeper.enabled", result, parse=parse_on_off)

    def _sip(self) -> Fact:
        result = self.run(["csrutil", "status"])
        return self._fact("sip.enabled", result, parse=parse_sip)

    def _automatic_update(self, key: str, pref: str) -> Fact:
        result = self.run(
            ["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", pref]
        )
        return self._fact(key, result, parse=parse_bool_int)

    def _screen_lock_password(self) -> Fact:
        result = self.run(
            ["defaults", "-currentHost", "read", "com.apple.screensaver", "askForPassword"]
        )
        return self._fact("screenlock.require_password", result, parse=parse_bool_int)

    def _screen_lock_delay(self) -> Fact:
        result = self.run(
            ["defaults", "-currentHost", "read", "com.apple.screensaver", "askForPasswordDelay"]
        )
        return self._fact("screenlock.delay_seconds", result, parse=parse_int)

    def _admin_accounts(self) -> Fact:
        result = self.run(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"])
        return self._fact("admin.accounts", result, parse=parse_group_membership)

    def _remote_login(self) -> Fact:
        result = self.run(["systemsetup", "-getremotelogin"])
        return self._fact("remote_login.enabled", result, parse=parse_on_off)
