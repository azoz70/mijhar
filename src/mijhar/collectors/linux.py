"""Linux local collector.

Gathers read-only security configuration facts from common Linux files
(``/etc/ssh/sshd_config``, ``/etc/login.defs``, PAM, ``/etc/passwd``) and
system tools (``ufw``, ``firewall-cmd``, ``systemctl``). Missing files and
privileged paths degrade to ``error`` facts instead of failing collection.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from mijhar.collectors.base import BaseCollector, CollectionResult, Fact
from mijhar.core.config import Platform

_SSHD = "/etc/ssh/sshd_config"
_LOGIN_DEFS = "/etc/login.defs"
_PASSWD = "/etc/passwd"
_COMMON_PASSWORD = "/etc/pam.d/common-password"
_PWQUALITY = "/etc/security/pwquality.conf"
_SHADOW = "/etc/shadow"
_SUDOERS = "/etc/sudoers"
_SSH_HOST_RSA = "/etc/ssh/ssh_host_rsa_key"
_REBOOT_REQUIRED = "/var/run/reboot-required"


def parse_key_value_file(content: str) -> Dict[str, str]:
    """Parse a simple ``KEY=VALUE`` file such as ``/etc/os-release``."""
    result: Dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        result[key.strip()] = value.strip().strip('"').strip("'")
    return result


def parse_login_defs(content: str) -> Dict[str, str]:
    """Parse ``/etc/login.defs`` ``KEY VALUE`` entries."""
    result: Dict[str, str] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            result[parts[0]] = parts[1].strip('"').strip("'")
    return result


def parse_uid_zero_accounts(content: str) -> List[str]:
    """Return account names whose numeric UID is 0 from ``/etc/passwd``."""
    accounts: List[str] = []
    for line in content.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) >= 3 and fields[2] == "0":
            accounts.append(fields[0])
    return accounts


def parse_pam_arguments(content: str) -> Dict[str, str]:
    """Extract ``key=value`` arguments from PAM ``pam_pwquality``/``pam_unix`` lines."""
    result: Dict[str, str] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "pam_pwquality" in stripped or "pam_unix" in stripped or "password" in stripped:
            for token in stripped.split():
                if "=" in token:
                    key, _, value = token.partition("=")
                    result[key] = value
    return result


def parse_status_word(output: str) -> Optional[str]:
    """Return the first word of a status command's output, lowercased."""
    parts = output.strip().split()
    return parts[0].lower() if parts else None


def mode_permission_bits(mode: int) -> int:
    """Return just the permission bits (owner/group/other + special) of ``st_mode``."""
    return mode & 0o7777


class LinuxCollector(BaseCollector):
    """Collect Linux security configuration facts."""

    platform = Platform.LINUX
    name = "linux"

    def collect(self) -> CollectionResult:
        facts: List[Fact] = [self._os_release()]
        facts.extend(self._ssh_settings())
        facts.extend(self._password_policy())
        facts.append(self._pam_password_policy())
        facts.append(self._uid_zero_accounts())
        facts.append(self._ufw_status())
        facts.append(self._firewalld_state())
        facts.append(self._auditd())
        facts.append(self._rsyslog())
        facts.append(self._running_services())
        facts.append(self._shadow_mode())
        facts.append(self._sudoers_mode())
        facts.append(self._ssh_host_key_mode())
        facts.append(self._unattended_upgrades())
        facts.append(self._reboot_required())
        facts.append(self._firewall_any_active(facts))
        return CollectionResult(collector=self.name, platform=self.platform, facts=facts)

    # -- probes ------------------------------------------------------------

    def _os_release(self) -> Fact:
        result = self.files.read_text("/etc/os-release")
        return self._file_fact("os.release", result, parse=parse_key_value_file)

    def _ssh_settings(self) -> List[Fact]:
        # OpenSSH resolves defaults, duplicate directives and included files.
        # Without -C it reports the global policy. Match policies need a
        # connection context and are outside the scope of this collection.
        source = "cmd:/usr/sbin/sshd -T (global policy)"
        result = self.runner.run(["/usr/sbin/sshd", "-T"])
        directives = {
            "permitrootlogin": "ssh.permit_root_login",
            "passwordauthentication": "ssh.password_authentication",
            "permitemptypasswords": "ssh.permit_empty_passwords",
            "x11forwarding": "ssh.x11_forwarding",
        }
        if not result.ok:
            config_present = self.files.stat_mode(_SSHD).ok
            error = result.error or f"exit {result.returncode}"
            return [
                Fact(key="ssh.config", value=True if config_present else None,
                     source=f"file:{_SSHD}", error=None if config_present else error),
                *(Fact(key=key, source=source, error=error) for key in directives.values()),
            ]

        settings = {}
        for line in result.output.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0] in directives:
                settings[parts[0]] = parts[1].lower()

        facts = [Fact(key="ssh.config", value=True, source=source)]
        for directive, key in directives.items():
            value = settings.get(directive)
            facts.append(Fact(
                key=key, value=value, source=source,
                raw=f"{directive} {value}" if value is not None else None,
                error=None if value is not None else "setting missing from sshd -T output",
            ))
        return facts

    def _password_policy(self) -> List[Fact]:
        result = self.files.read_text(_LOGIN_DEFS)
        cfg = parse_login_defs(result.content or "") if result.ok else {}
        facts = [self._file_fact("password.policy", result, value=cfg)]
        for key, fact_key in (
            ("PASS_MAX_DAYS", "password.max_days"),
            ("PASS_MIN_DAYS", "password.min_days"),
            ("PASS_WARN_AGE", "password.warn_age"),
        ):
            if key in cfg:
                facts.append(
                    Fact(
                        key=fact_key,
                        value=self._to_int(cfg[key]),
                        source=f"file:{_LOGIN_DEFS}",
                        raw=f"{key} {cfg[key]}",
                    )
                )
        return facts

    @staticmethod
    def _to_int(value: str) -> Optional[int]:
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    def _pam_password_policy(self) -> Fact:
        content = ""
        for path in (_COMMON_PASSWORD, _PWQUALITY):
            res = self.files.read_text(path)
            if res.ok and res.content:
                content += res.content + "\n"
        if not content:
            return Fact(key="password.pam", value={}, source=f"file:{_COMMON_PASSWORD}", error="no pam password policy file found")
        parsed = parse_pam_arguments(content)
        # Handle pwquality.conf `minlen = 12` form too.
        parsed.update(parse_key_value_file(content))
        return Fact(key="password.pam", value=parsed, source=f"file:{_COMMON_PASSWORD}", raw=content.rstrip())

    def _uid_zero_accounts(self) -> Fact:
        result = self.files.read_text(_PASSWD)
        return self._file_fact("accounts.uid_zero", result, parse=parse_uid_zero_accounts)

    def _ufw_status(self) -> Fact:
        result = self.run(["ufw", "status"])
        def parse(out: str) -> Optional[bool]:
            text = out.lower()
            if "status: active" in text:
                return True
            if "status: inactive" in text:
                return False
            return None
        return self._fact("firewall.ufw_active", result, parse=parse)

    def _firewalld_state(self) -> Fact:
        result = self.run(["firewall-cmd", "--state"])
        def parse(out: str) -> Optional[bool]:
            return {"running": True, "not running": False}.get(out.strip().lower())
        return self._fact("firewall.firewalld_running", result, parse=parse)

    def _auditd(self) -> Fact:
        enabled = self.run(["systemctl", "is-enabled", "auditd"])
        active = self.run(["systemctl", "is-active", "auditd"])
        value = {
            "enabled": parse_status_word(enabled.output),
            "active": parse_status_word(active.output),
        }
        error = None
        if parse_status_word(enabled.output) is None and not enabled.ok:
            error = enabled.error or f"exit {enabled.returncode}"
        return Fact(
            key="auditd.status",
            value=value,
            source="systemctl auditd",
            raw=f"is-enabled: {enabled.output}\nis-active: {active.output}".strip(),
            error=error,
        )

    def _rsyslog(self) -> Fact:
        result = self.run(["systemctl", "is-active", "rsyslog"])
        return self._status_fact("logging.rsyslog_active", result)

    def _running_services(self) -> Fact:
        result = self.run(
            ["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager"]
        )
        def parse(out: str) -> List[str]:
            return [line.split()[0] for line in out.splitlines() if line.split()]
        return self._fact("services.running", result, parse=parse)

    def _shadow_mode(self) -> Fact:
        result = self.files.stat_mode(_SHADOW)
        return self._mode_fact("file.shadow_mode", result)

    def _sudoers_mode(self) -> Fact:
        result = self.files.stat_mode(_SUDOERS)
        return self._mode_fact("file.sudoers_mode", result)

    def _ssh_host_key_mode(self) -> Fact:
        result = self.files.stat_mode(_SSH_HOST_RSA)
        return self._mode_fact("file.ssh_host_rsa_key_mode", result)

    def _unattended_upgrades(self) -> Fact:
        result = self.run(["systemctl", "is-enabled", "unattended-upgrades"])
        return self._status_fact("updates.unattended_enabled", result)

    def _reboot_required(self) -> Fact:
        result = self.files.read_text(_REBOOT_REQUIRED)
        fact = self._file_fact("updates.reboot_required", result, parse=lambda c: True)
        if result.error:
            # A missing file simply means no reboot is required (not an error).
            fact.value = False
            fact.error = None
        return fact

    # -- fact builders -----------------------------------------------------

    def _status_fact(self, key: str, result) -> Fact:
        word = parse_status_word(result.output)
        error = None
        if word is None:
            error = result.error or f"exit code {result.returncode}"
        return Fact(
            key=key,
            value=word,
            source=" ".join(result.args),
            raw=result.stdout.rstrip() if result.stdout else None,
            error=error,
        )

    def _mode_fact(self, key: str, result) -> Fact:
        if not result.ok or result.mode is None:
            return Fact(key=key, value=None, source=f"file:{result.path}", error=result.error)
        return Fact(
            key=key,
            value=mode_permission_bits(result.mode),
            source=f"file:{result.path}",
            raw=f"{mode_permission_bits(result.mode):04o}",
        )

    def _firewall_any_active(self, facts: List[Fact]) -> Fact:
        """Aggregate ufw/firewalld facts into a single 'is a firewall active' fact."""
        by_key = {f.key: f for f in facts}
        ufw = by_key.get("firewall.ufw_active")
        fwd = by_key.get("firewall.firewalld_running")
        active: Optional[bool] = None
        if (ufw and ufw.value is True) or (fwd and fwd.value is True):
            active = True
        elif ufw and ufw.value is False and fwd and fwd.value is False:
            active = False
        return Fact(
            key="firewall.any_active",
            value=active,
            source="aggregate(ufw, firewalld)",
            raw=f"ufw={ufw.value if ufw else None}; firewalld={fwd.value if fwd else None}",
        )
