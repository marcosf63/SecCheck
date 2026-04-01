from app.models.scan_result import ScanResult
from app.scanners.base import BaseScanner
from app.ssh.executor import RemoteExecutor


class FilesScanner(BaseScanner):
    name = "files"

    _SUSPICIOUS_DIRS = ["/tmp", "/dev/shm", "/var/tmp"]

    def _run(self, executor: RemoteExecutor) -> ScanResult:
        dirs = " ".join(self._SUSPICIOUS_DIRS)
        suspicious = executor.run_safe(f"find {dirs} -type f 2>/dev/null")
        executables = executor.run_safe(f"find {dirs} -type f -executable 2>/dev/null")
        recent = executor.run_safe(
            "find /etc /bin /sbin /usr/bin /usr/sbin -newer /etc/passwd -type f 2>/dev/null | head -30"
        )
        suid = executor.run_safe("find / -perm /4000 -type f 2>/dev/null | head -20")

        raw = (
            f"=== SUSPICIOUS DIRS ===\n{suspicious.stdout}\n\n"
            f"=== EXECUTABLES IN SUSPICIOUS DIRS ===\n{executables.stdout}\n\n"
            f"=== RECENTLY MODIFIED SYSTEM FILES ===\n{recent.stdout}\n\n"
            f"=== SUID FILES ===\n{suid.stdout}"
        )
        return ScanResult(
            scanner_name=self.name,
            raw_output=raw,
            parsed_data={
                "suspicious_files": suspicious.stdout.splitlines(),
                "executables_in_tmp": executables.stdout.splitlines(),
                "recent_system_files": recent.stdout.splitlines(),
                "suid_files": suid.stdout.splitlines(),
            },
        )
