from app.models.scan_result import ScanResult
from app.scanners.base import BaseScanner
from app.ssh.executor import RemoteExecutor


class SSHKeysScanner(BaseScanner):
    name = "ssh_keys"

    _KEY_PATHS = [
        "/root/.ssh/authorized_keys",
        "/home/*/.ssh/authorized_keys",
    ]

    def _run(self, executor: RemoteExecutor) -> ScanResult:
        results = []
        raw_parts = []

        for path_pattern in self._KEY_PATHS:
            result = executor.run_safe(f"cat {path_pattern} 2>/dev/null")
            if result.stdout:
                raw_parts.append(f"=== {path_pattern} ===\n{result.stdout}")
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        results.append({
                            "path": path_pattern,
                            "key_type": parts[0] if parts else "",
                            "key": parts[1][:20] + "..." if len(parts) > 1 else "",
                            "comment": parts[2] if len(parts) > 2 else "",
                            "full_line": line,
                        })

        return ScanResult(
            scanner_name=self.name,
            raw_output="\n\n".join(raw_parts),
            parsed_data=results,
        )
