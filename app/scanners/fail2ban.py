"""
Scanner: status do Fail2Ban.
"""
from app.models.scan_result import ScanResult
from app.scanners.base import BaseScanner
from app.ssh.executor import RemoteExecutor


class Fail2BanScanner(BaseScanner):
    name = "fail2ban"

    def _run(self, executor: RemoteExecutor) -> ScanResult:
        check = executor.run_safe("which fail2ban-client 2>/dev/null")
        if not check.stdout.strip():
            return ScanResult(
                scanner_name=self.name,
                raw_output="fail2ban não instalado",
                parsed_data={"available": False},
            )

        parts: list[str] = []
        data: dict = {"available": True, "jails": {}}

        # Status geral
        general = executor.run_safe("sudo fail2ban-client status 2>/dev/null")
        data["status"] = general.stdout.strip()
        parts.append(f"=== STATUS GERAL ===\n{general.stdout.strip()}")

        # Extrai lista de jails do status geral
        jails: list[str] = []
        for line in general.stdout.splitlines():
            if "Jail list:" in line:
                raw_jails = line.split(":", 1)[1].strip()
                jails = [j.strip() for j in raw_jails.split(",") if j.strip()]
                break

        data["jail_list"] = jails

        # Status de cada jail
        for jail in jails:
            jail_status = executor.run_safe(f"sudo fail2ban-client status {jail} 2>/dev/null")
            data["jails"][jail] = jail_status.stdout.strip()
            parts.append(f"=== JAIL: {jail} ===\n{jail_status.stdout.strip()}")

        return ScanResult(
            scanner_name=self.name,
            raw_output="\n\n".join(parts),
            parsed_data=data,
        )
