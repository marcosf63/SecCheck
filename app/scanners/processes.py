from app.models.scan_result import ScanResult
from app.scanners.base import BaseScanner
from app.ssh.executor import RemoteExecutor


class ProcessScanner(BaseScanner):
    name = "processes"

    def _run(self, executor: RemoteExecutor) -> ScanResult:
        result = executor.run_safe("ps aux --no-headers")
        processes = []
        for line in result.stdout.splitlines():
            parts = line.split(None, 10)
            if len(parts) >= 11:
                processes.append({
                    "user": parts[0],
                    "pid": parts[1],
                    "cpu": parts[2],
                    "mem": parts[3],
                    "command": parts[10],
                })
        return ScanResult(
            scanner_name=self.name,
            raw_output=result.stdout,
            parsed_data=processes,
        )
