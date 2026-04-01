"""
Scanner: regras de firewall (UFW e iptables).
"""
from app.models.scan_result import ScanResult
from app.scanners.base import BaseScanner
from app.ssh.executor import RemoteExecutor


class FirewallScanner(BaseScanner):
    name = "firewall"

    def _run(self, executor: RemoteExecutor) -> ScanResult:
        data: dict = {}
        parts: list[str] = []

        # UFW
        ufw_check = executor.run_safe("which ufw 2>/dev/null")
        if ufw_check.stdout.strip():
            ufw_status = executor.run_safe("sudo ufw status verbose 2>/dev/null")
            data["ufw"] = {
                "available": True,
                "output": ufw_status.stdout.strip(),
            }
            parts.append(f"=== UFW STATUS ===\n{ufw_status.stdout.strip()}")
        else:
            data["ufw"] = {"available": False}

        # iptables (fallback / complementar)
        ipt_check = executor.run_safe("which iptables 2>/dev/null")
        if ipt_check.stdout.strip():
            ipt = executor.run_safe("sudo iptables -L -n --line-numbers 2>/dev/null")
            data["iptables"] = {
                "available": True,
                "output": ipt.stdout.strip(),
            }
            parts.append(f"=== IPTABLES ===\n{ipt.stdout.strip()}")
        else:
            data["iptables"] = {"available": False}

        return ScanResult(
            scanner_name=self.name,
            raw_output="\n\n".join(parts),
            parsed_data=data,
        )
