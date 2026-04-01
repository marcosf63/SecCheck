"""Testes para os novos scanners: sshd_config, firewall, fail2ban, docker, auth_logs."""
import pytest
from unittest.mock import MagicMock

from app.models.scan_result import ScanResult
from app.scanners.sshd_config import SshdConfigScanner
from app.scanners.firewall import FirewallScanner
from app.scanners.fail2ban import Fail2BanScanner
from app.scanners.docker import DockerScanner
from app.scanners.auth_logs import AuthLogsScanner


def _executor(outputs: dict[str, str]) -> MagicMock:
    """Cria executor mock onde run_safe retorna stdout conforme o comando."""
    executor = MagicMock()

    def run_safe_side_effect(cmd):
        for key, out in outputs.items():
            if key in cmd:
                r = MagicMock()
                r.stdout = out
                return r
        r = MagicMock()
        r.stdout = ""
        return r

    executor.run_safe.side_effect = run_safe_side_effect
    return executor


# ── SshdConfigScanner ─────────────────────────────────────────────────────────

class TestSshdConfigScanner:
    def test_parses_key_value_params(self):
        output = (
            "PasswordAuthentication no\n"
            "PermitRootLogin prohibit-password\n"
            "PubkeyAuthentication yes\n"
            "Port 2222\n"
        )
        executor = _executor({"grep": output})
        result = SshdConfigScanner().run(executor)
        assert result.success
        assert result.parsed_data["PasswordAuthentication"] == "no"
        assert result.parsed_data["PermitRootLogin"] == "prohibit-password"
        assert result.parsed_data["Port"] == "2222"

    def test_ignores_comment_lines(self):
        output = "# PasswordAuthentication yes\nPasswordAuthentication no\n"
        executor = _executor({"grep": output})
        result = SshdConfigScanner().run(executor)
        assert result.parsed_data["PasswordAuthentication"] == "no"

    def test_empty_output_returns_empty_dict(self):
        executor = _executor({})
        result = SshdConfigScanner().run(executor)
        assert result.success
        assert result.parsed_data == {}


# ── FirewallScanner ───────────────────────────────────────────────────────────

class TestFirewallScanner:
    def test_ufw_available(self):
        outputs = {
            "which ufw": "/usr/sbin/ufw",
            "ufw status": "Status: active\nTo                         Action      From\n22/tcp                     ALLOW       Anywhere",
            "which iptables": "",
        }
        executor = _executor(outputs)
        result = FirewallScanner().run(executor)
        assert result.success
        assert result.parsed_data["ufw"]["available"] is True
        assert "Status: active" in result.parsed_data["ufw"]["output"]

    def test_ufw_not_installed(self):
        executor = _executor({})
        result = FirewallScanner().run(executor)
        assert result.parsed_data["ufw"]["available"] is False

    def test_iptables_collected_when_present(self):
        outputs = {
            "which ufw": "",
            "which iptables": "/sbin/iptables",
            "iptables -L": "Chain INPUT (policy ACCEPT)",
        }
        executor = _executor(outputs)
        result = FirewallScanner().run(executor)
        assert result.parsed_data["iptables"]["available"] is True


# ── Fail2BanScanner ───────────────────────────────────────────────────────────

class TestFail2BanScanner:
    def test_not_installed(self):
        executor = _executor({})
        result = Fail2BanScanner().run(executor)
        assert result.parsed_data["available"] is False

    def test_parses_jail_list(self):
        outputs = {
            "which fail2ban-client": "/usr/bin/fail2ban-client",
            "fail2ban-client status": (
                "Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, nginx-http-auth"
            ),
            "fail2ban-client status sshd": "Status for the jail: sshd\n|- Filter\n|- Actions",
            "fail2ban-client status nginx-http-auth": "Status for the jail: nginx-http-auth",
        }
        executor = _executor(outputs)
        result = Fail2BanScanner().run(executor)
        assert result.parsed_data["available"] is True
        assert "sshd" in result.parsed_data["jail_list"]
        assert "nginx-http-auth" in result.parsed_data["jail_list"]


# ── DockerScanner ─────────────────────────────────────────────────────────────

class TestDockerScanner:
    def test_not_installed(self):
        executor = _executor({})
        result = DockerScanner().run(executor)
        assert result.parsed_data["available"] is False

    def test_parses_containers(self):
        container_line = "abc123\tnginx:latest\tUp 2 hours\t0.0.0.0:80->80/tcp\tweb"
        outputs = {
            "which docker": "/usr/bin/docker",
            "docker ps -a": container_line,
            "docker volume ls": "",
            "docker network ls": "",
            "docker inspect": "",
        }
        executor = _executor(outputs)
        result = DockerScanner().run(executor)
        assert result.parsed_data["available"] is True
        containers = result.parsed_data["containers"]
        assert len(containers) == 1
        assert containers[0]["image"] == "nginx:latest"
        assert containers[0]["name"] == "web"


# ── AuthLogsScanner ───────────────────────────────────────────────────────────

class TestAuthLogsScanner:
    def test_collects_successful_logins(self):
        accepted_line = "Apr  1 20:44:01 server sshd[123]: Accepted publickey for deploy"
        outputs = {
            "Accepted": accepted_line,
            "journalctl -u ssh -u sshd": accepted_line,
            "last": "deploy   pts/0  177.37.186.244  Wed Apr  1 20:44",
            "lastlog": "deploy          pts/0    177.37.186.244   Wed Apr  1 20:44",
        }
        executor = _executor(outputs)
        result = AuthLogsScanner().run(executor)
        assert result.success
        assert isinstance(result.parsed_data["login_history"], list)

    def test_collects_failed_attempts(self):
        failed_line = "Apr  1 20:10:01 server sshd[99]: Failed password for root"
        outputs = {
            "Failed": failed_line,
            "journalctl -u ssh -u sshd": failed_line,
            "last": "",
            "lastlog": "",
        }
        executor = _executor(outputs)
        result = AuthLogsScanner().run(executor)
        assert result.success
        assert isinstance(result.parsed_data["failed_attempts"], list)

    def test_no_data_returns_empty_lists(self):
        executor = _executor({})
        result = AuthLogsScanner().run(executor)
        assert result.success
        assert result.parsed_data["successful_logins"] == []
        assert result.parsed_data["failed_attempts"] == []
        assert result.parsed_data["sudo_usage"] == []
        assert result.parsed_data["login_history"] == []
