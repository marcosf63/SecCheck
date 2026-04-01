"""
Scanner: logs de autenticação — logins bem-sucedidos, falhas, uso de sudo.
Coleta os registros sem emitir julgamentos.
"""
from app.models.scan_result import ScanResult
from app.scanners.base import BaseScanner
from app.ssh.executor import RemoteExecutor

# Janela de análise padrão (horas para trás)
_HOURS = 48


class AuthLogsScanner(BaseScanner):
    name = "auth_logs"

    def _run(self, executor: RemoteExecutor) -> ScanResult:
        parts: list[str] = []
        data: dict = {}

        # Logins aceitos (journalctl — mais confiável no systemd)
        accepted = executor.run_safe(
            f"sudo journalctl -u ssh -u sshd --since '{_HOURS} hours ago' "
            r"--no-pager -q 2>/dev/null | grep -i 'Accepted\|session opened\|Disconnected' | tail -50"
        )
        data["successful_logins"] = accepted.stdout.strip().splitlines()
        parts.append(f"=== LOGINS ACEITOS (últimas {_HOURS}h) ===\n{accepted.stdout.strip()}")

        # Falhas de autenticação
        failed = executor.run_safe(
            f"sudo journalctl -u ssh -u sshd --since '{_HOURS} hours ago' "
            r"--no-pager -q 2>/dev/null | grep -i 'Failed\|Invalid\|error' | tail -50"
        )
        data["failed_attempts"] = failed.stdout.strip().splitlines()
        parts.append(f"=== FALHAS DE AUTENTICAÇÃO (últimas {_HOURS}h) ===\n{failed.stdout.strip()}")

        # Fallback: /var/log/auth.log
        auth_log = executor.run_safe(
            f"sudo grep -i 'Accepted\\|Failed\\|Invalid\\|session opened\\|sudo' "
            f"/var/log/auth.log 2>/dev/null | tail -100"
        )
        if auth_log.stdout.strip():
            data["auth_log_tail"] = auth_log.stdout.strip().splitlines()
            parts.append(f"=== /var/log/auth.log (últimas 100 linhas relevantes) ===\n{auth_log.stdout.strip()}")

        # Uso de sudo
        sudo_usage = executor.run_safe(
            f"sudo journalctl --since '{_HOURS} hours ago' --no-pager -q 2>/dev/null "
            r"| grep -i 'sudo\|COMMAND=' | tail -50"
        )
        data["sudo_usage"] = sudo_usage.stdout.strip().splitlines()
        parts.append(f"=== USO DE SUDO (últimas {_HOURS}h) ===\n{sudo_usage.stdout.strip()}")

        # Histórico de logins (last)
        last = executor.run_safe("last -n 20 2>/dev/null")
        data["login_history"] = last.stdout.strip().splitlines()
        parts.append(f"=== HISTÓRICO DE LOGINS (last -n 20) ===\n{last.stdout.strip()}")

        # Último login por usuário (lastlog)
        lastlog = executor.run_safe("lastlog 2>/dev/null | grep -v 'Never logged in' | head -30")
        data["lastlog"] = lastlog.stdout.strip().splitlines()
        parts.append(f"=== LASTLOG ===\n{lastlog.stdout.strip()}")

        return ScanResult(
            scanner_name=self.name,
            raw_output="\n\n".join(parts),
            parsed_data=data,
        )
