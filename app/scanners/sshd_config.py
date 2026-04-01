"""
Scanner: configuração do servidor SSH (sshd_config).
Coleta os parâmetros de segurança relevantes sem emitir julgamentos.
"""
from app.models.scan_result import ScanResult
from app.scanners.base import BaseScanner
from app.ssh.executor import RemoteExecutor

_PARAMS = [
    "PasswordAuthentication",
    "PermitRootLogin",
    "PubkeyAuthentication",
    "PermitEmptyPasswords",
    "ChallengeResponseAuthentication",
    "UsePAM",
    "AllowUsers",
    "AllowGroups",
    "DenyUsers",
    "DenyGroups",
    "Port",
    "ListenAddress",
    "MaxAuthTries",
    "LoginGraceTime",
    "X11Forwarding",
    "AuthorizedKeysFile",
]


class SshdConfigScanner(BaseScanner):
    name = "sshd_config"

    def _run(self, executor: RemoteExecutor) -> ScanResult:
        # Extrai apenas linhas ativas (sem comentário) dos arquivos principais
        cmd = (
            r"sudo grep -Eih '^("
            + "|".join(_PARAMS)
            + r")\s+'  /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null"
        )
        result = executor.run_safe(cmd)
        raw = result.stdout.strip()

        params: dict[str, str] = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                key, val = parts
                # Última ocorrência vence (comportamento do sshd)
                params[key] = val

        return ScanResult(
            scanner_name=self.name,
            raw_output=raw,
            parsed_data=params,
        )
