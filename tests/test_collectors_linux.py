"""Tests for the Linux collector using mocked command and file readers."""

from __future__ import annotations

from mijhar.collectors.linux import (
    LinuxCollector,
    mode_permission_bits,
    parse_login_defs,
    parse_uid_zero_accounts,
)
from tests.conftest import FakeFileReader, FakeRunner, result

_SSHD_EFFECTIVE = """\
permitrootlogin no
passwordauthentication no
permitemptypasswords no
x11forwarding no
"""

_LOGIN_DEFS = """\
PASS_MAX_DAYS 90
PASS_MIN_DAYS 1
PASS_WARN_AGE 7
"""

_PASSWD = """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
admin:x:0:1000:admin:/home/admin:/bin/bash
alice:x:1000:1000:alice:/home/alice:/bin/bash
"""


def _happy_files() -> FakeFileReader:
    return FakeFileReader(
        texts={
            "/etc/os-release": 'ID=ubuntu\nVERSION_ID="22.04"\n',
            "/etc/login.defs": _LOGIN_DEFS,
            "/etc/pam.d/common-password": "password requisite pam_pwquality.so retry=3 minlen=12 remember=5\n",
            "/etc/passwd": _PASSWD,
            "/var/run/reboot-required": "*** System restart required ***\n",
        },
        modes={
            "/etc/shadow": 0o100600,
            "/etc/sudoers": 0o100440,
            "/etc/ssh/ssh_host_rsa_key": 0o100600,
        },
    )


def _happy_runner() -> FakeRunner:
    return FakeRunner(
        {
            ("/usr/sbin/sshd", "-T"): result(0, _SSHD_EFFECTIVE),
            ("ufw", "status"): result(0, "Status: active"),
            ("firewall-cmd", "--state"): result(0, "not running"),
            ("systemctl", "is-enabled", "auditd"): result(0, "enabled"),
            ("systemctl", "is-active", "auditd"): result(0, "active"),
            ("systemctl", "is-active", "rsyslog"): result(0, "active"),
            ("systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager"): result(
                0, "sshd.service loaded active running OpenSSH\ncron.service loaded active running cron\n"
            ),
            ("systemctl", "is-enabled", "unattended-upgrades"): result(0, "enabled"),
        }
    )


def test_collects_expected_facts():
    collector = LinuxCollector(_happy_runner(), _happy_files())
    facts = {f.key: f for f in collector.collect().facts}
    assert facts["os.release"].value["ID"] == "ubuntu"
    assert facts["ssh.permit_root_login"].value == "no"
    assert facts["ssh.password_authentication"].value == "no"
    assert facts["ssh.permit_empty_passwords"].value == "no"
    assert facts["password.max_days"].value == 90
    assert facts["password.min_days"].value == 1
    assert facts["password.warn_age"].value == 7
    assert facts["password.pam"].value["minlen"] == "12"
    assert facts["accounts.uid_zero"].value == ["root", "admin"]
    assert facts["firewall.ufw_active"].value is True
    assert facts["firewall.firewalld_running"].value is False
    assert facts["auditd.status"].value == {"enabled": "enabled", "active": "active"}
    assert facts["file.shadow_mode"].value == 0o600
    assert facts["file.sudoers_mode"].value == 0o440
    assert facts["file.ssh_host_rsa_key_mode"].value == 0o600
    assert facts["services.running"].value == ["sshd.service", "cron.service"]
    assert facts["updates.unattended_enabled"].value == "enabled"
    assert facts["updates.reboot_required"].value is True


def test_missing_files_degrade_gracefully():
    collector = LinuxCollector(FakeRunner({}), FakeFileReader({}))
    facts = {f.key: f for f in collector.collect().facts}
    assert facts["ssh.config"].error
    assert facts["file.shadow_mode"].error
    assert facts["updates.reboot_required"].value is False  # missing file => no reboot
    assert facts["updates.reboot_required"].error is None


def test_uid_zero_accounts_requires_zero_uid_only():
    assert parse_uid_zero_accounts("root:x:0:0:root:/root:/bin/bash") == ["root"]


# -- parser unit tests -------------------------------------------------------


def test_failed_effective_ssh_probe_does_not_use_file_values():
    runner = FakeRunner({("/usr/sbin/sshd", "-T"): result(1, stderr="host keys unavailable")})
    files = FakeFileReader(
        texts={"/etc/ssh/sshd_config": "PermitRootLogin no"},
        modes={"/etc/ssh/sshd_config": 0o644},
    )
    facts = {f.key: f for f in LinuxCollector(runner, files).collect().facts}

    assert facts["ssh.config"].value is True
    assert facts["ssh.permit_root_login"].value is None
    assert facts["ssh.permit_root_login"].error == "host keys unavailable"
    assert "/etc/ssh/sshd_config" not in files.reads


def test_parse_login_defs():
    assert parse_login_defs(_LOGIN_DEFS)["PASS_MAX_DAYS"] == "90"


def test_mode_permission_bits():
    assert mode_permission_bits(0o100600) == 0o600
    assert mode_permission_bits(0o100644) == 0o644
