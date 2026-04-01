from app.models.scan_result import ScanResult
from app.scanners.base import BaseScanner
from app.ssh.executor import RemoteExecutor


class ServicesScanner(BaseScanner):
    name = "services"

    def _run(self, executor: RemoteExecutor) -> ScanResult:
        result = executor.run_safe(
            "systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null"
        )
        services = []
        for line in result.stdout.splitlines():
            parts = line.split(None, 4)
            if len(parts) >= 4:
                services.append({
                    "unit": parts[0],
                    "load": parts[1],
                    "active": parts[2],
                    "sub": parts[3],
                    "description": parts[4] if len(parts) > 4 else "",
                })
        return ScanResult(
            scanner_name=self.name,
            raw_output=result.stdout,
            parsed_data=services,
        )
