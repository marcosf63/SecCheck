from app.models.scan_result import ScanResult
from app.scanners.base import BaseScanner
from app.ssh.executor import RemoteExecutor


class UsersScanner(BaseScanner):
    name = "users"

    def _run(self, executor: RemoteExecutor) -> ScanResult:
        logged = executor.run_safe("who")
        last = executor.run_safe("last -n 20 2>/dev/null")
        passwd = executor.run_safe("getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 {print}'")

        users_logged = []
        for line in logged.stdout.splitlines():
            parts = line.split()
            if parts:
                users_logged.append({"user": parts[0], "tty": parts[1] if len(parts) > 1 else "", "from": parts[4] if len(parts) > 4 else ""})

        system_users = []
        for line in passwd.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 7:
                system_users.append({"user": parts[0], "uid": parts[2], "home": parts[5], "shell": parts[6]})

        raw = f"=== WHO ===\n{logged.stdout}\n\n=== LAST ===\n{last.stdout}\n\n=== PASSWD ===\n{passwd.stdout}"
        return ScanResult(
            scanner_name=self.name,
            raw_output=raw,
            parsed_data={"logged": users_logged, "system_users": system_users, "last": last.stdout},
        )
