"""Tests for the remote SSH collection adapter."""

from __future__ import annotations

from mijhar.collectors.ssh import SSHCollector, SSHRunner
from tests.conftest import FakeRunner, result


def test_ssh_runner_builds_secure_args():
    runner = SSHRunner(host="server1", user="audit", port=2222, ssh_bin="ssh")
    args = runner.build_args(["ufw", "status"])
    assert args == [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=10",
        "-p", "2222",
        "audit@server1",
        "ufw",
        "status",
    ]


def test_ssh_collector_delegates_over_transport():
    runner = FakeRunner(
        {
            ("cat", "/etc/os-release"): result(0, 'ID=ubuntu\nVERSION_ID="22.04"\n'),
            ("/usr/sbin/sshd", "-T"): result(0, "permitrootlogin no\npasswordauthentication no\n"),
            ("cat", "/etc/login.defs"): result(0, "PASS_MAX_DAYS 90\n"),
            ("cat", "/etc/passwd"): result(0, "root:x:0:0:root:/root:/bin/bash\n"),
            ("ufw", "status"): result(0, "Status: active"),
            ("firewall-cmd", "--state"): result(0, "not running"),
            ("stat", "-c", "%a", "/etc/shadow"): result(0, "600"),
            ("stat", "-c", "%a", "/etc/sudoers"): result(0, "440"),
            ("stat", "-c", "%a", "/etc/ssh/ssh_host_rsa_key"): result(0, "600"),
        }
    )
    collector = SSHCollector(host="server1", user="audit", runner=runner)
    facts = {f.key: f for f in collector.collect().facts}

    assert facts["os.release"].value["ID"] == "ubuntu"
    assert facts["ssh.permit_root_login"].value == "no"
    assert facts["password.max_days"].value == 90
    assert facts["accounts.uid_zero"].value == ["root"]
    assert facts["firewall.ufw_active"].value is True
    assert facts["file.shadow_mode"].value == 0o600
    assert facts["file.sudoers_mode"].value == 0o440


def test_ssh_stat_parses_octal_mode():
    from mijhar.collectors.ssh import SSHFileReader

    runner = FakeRunner({("stat", "-c", "%a", "/etc/shadow"): result(0, "640")})
    reader = SSHFileReader(runner)
    file_result = reader.stat_mode("/etc/shadow")
    assert file_result.mode == 0o640
