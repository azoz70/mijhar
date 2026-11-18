"""Tests for the macOS collector using a mocked command runner."""

from __future__ import annotations

from mijhar.collectors.macos import (
    MacOSCollector,
    parse_filevault,
    parse_group_membership,
    parse_on_off,
    parse_sip,
)
from tests.conftest import FakeRunner, result


def _happy_runner() -> FakeRunner:
    return FakeRunner(
        {
            ("sw_vers", "-productVersion"): result(0, "14.5"),
            ("uname", "-m"): result(0, "arm64"),
            ("fdesetup", "status"): result(0, "FileVault is On."),
            ("defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"): result(0, "1"),
            ("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"): result(
                0, "Firewall is enabled."
            ),
            ("spctl", "--status"): result(0, "assessments enabled"),
            ("csrutil", "status"): result(0, "System Integrity Protection status: enabled."),
            ("defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"): result(0, "1"),
            ("defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload"): result(0, "1"),
            ("defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall"): result(0, "1"),
            ("defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall"): result(0, "1"),
            ("defaults", "-currentHost", "read", "com.apple.screensaver", "askForPassword"): result(0, "1"),
            ("defaults", "-currentHost", "read", "com.apple.screensaver", "askForPasswordDelay"): result(0, "300"),
            ("dscl", ".", "-read", "/Groups/admin", "GroupMembership"): result(
                0, "GroupMembership: root admin alice"
            ),
            ("systemsetup", "-getremotelogin"): result(0, "Remote Login: Off"),
        }
    )


def test_collects_expected_keys():
    collector = MacOSCollector(_happy_runner())
    collection = collector.collect()
    keys = {f.key for f in collection.facts}
    expected = {
        "os.version",
        "os.architecture",
        "filevault.enabled",
        "firewall.globalstate",
        "firewall.enabled",
        "gatekeeper.enabled",
        "sip.enabled",
        "autoupdate.check_enabled",
        "autoupdate.download_enabled",
        "autoupdate.install_config_data",
        "autoupdate.install_critical",
        "screenlock.require_password",
        "screenlock.delay_seconds",
        "admin.accounts",
        "remote_login.enabled",
    }
    assert expected <= keys


def test_fact_values_happy_path():
    collector = MacOSCollector(_happy_runner())
    facts = {f.key: f for f in collector.collect().facts}
    assert facts["filevault.enabled"].value is True
    assert facts["firewall.globalstate"].value == 1
    assert facts["firewall.enabled"].value is True
    assert facts["gatekeeper.enabled"].value is True
    assert facts["sip.enabled"].value is True
    assert facts["autoupdate.check_enabled"].value is True
    assert facts["screenlock.require_password"].value is True
    assert facts["screenlock.delay_seconds"].value == 300
    assert facts["admin.accounts"].value == ["root", "admin", "alice"]
    assert facts["remote_login.enabled"].value is False
    assert facts["os.version"].value == "14.5"
    # No collection errors on the happy path.
    assert not [f for f in facts.values() if f.error]


def test_privileged_probe_degrades_to_error_fact():
    # csrutil requires root; simulate the permission denial.
    runner = FakeRunner(
        {
            ("csrutil", "status"): result(1, stderr="This tool must be run as root."),
        }
    )
    collector = MacOSCollector(runner)
    facts = {f.key: f for f in collector.collect().facts}
    sip = facts["sip.enabled"]
    assert sip.value is None
    assert sip.error and "root" in sip.error


def test_missing_binary_is_captured_not_raised():
    collector = MacOSCollector(FakeRunner({}))
    collection = collector.collect()
    assert collection.facts  # still collected something
    assert len(collection.errors) == len(collection.facts)


# -- parser unit tests -------------------------------------------------------


def test_parse_filevault():
    assert parse_filevault("FileVault is On.") is True
    assert parse_filevault("FileVault is Off.") is False
    assert parse_filevault("unexpected") is None


def test_parse_on_off():
    assert parse_on_off("Firewall is enabled.") is True
    assert parse_on_off("Firewall is disabled.") is False
    assert parse_on_off("Remote Login: On") is True
    assert parse_on_off("Remote Login: Off") is False


def test_parse_sip():
    assert parse_sip("System Integrity Protection status: enabled.") is True
    assert parse_sip("System Integrity Protection status: disabled.") is False


def test_parse_group_membership():
    assert parse_group_membership("GroupMembership: root admin alice") == [
        "root",
        "admin",
        "alice",
    ]
    assert parse_group_membership("no membership here") == []
