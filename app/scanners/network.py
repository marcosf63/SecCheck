from app.models.scan_result import ScanResult
from app.scanners.base import BaseScanner
from app.ssh.executor import RemoteExecutor


class NetworkScanner(BaseScanner):
    name = "network"

    def _run(self, executor: RemoteExecutor) -> ScanResult:
        result = executor.run_safe("ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null")
        ports = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Netid") or line.startswith("Proto"):
                continue
            parts = line.split()
            if len(parts) >= 5:
                ports.append({
                    "proto": parts[0],
                    "state": parts[1] if len(parts) > 5 else "",
                    "local_address": parts[4] if len(parts) > 5 else parts[3],
                    "process": parts[-1] if "pid=" in parts[-1] or "/" in parts[-1] else "",
                })

        connections_result = executor.run_safe("ss -tnp state established 2>/dev/null")
        connections = []
        for line in connections_result.stdout.splitlines():
            if not line or line.startswith("Recv"):
                continue
            parts = line.split()
            if len(parts) >= 5:
                connections.append({
                    "local": parts[3],
                    "remote": parts[4],
                    "process": parts[5] if len(parts) > 5 else "",
                })

        return ScanResult(
            scanner_name=self.name,
            raw_output=result.stdout,
            parsed_data={"ports": ports, "connections": connections},
        )
