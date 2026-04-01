from app.models.scan_result import ScanResult
from app.scanners.base import BaseScanner
from app.ssh.executor import RemoteExecutor


class SystemdScanner(BaseScanner):
    name = "systemd"

    def _run(self, executor: RemoteExecutor) -> ScanResult:
        timers = executor.run_safe("systemctl list-timers --no-pager --no-legend 2>/dev/null")
        enabled = executor.run_safe(
            "systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null"
        )
        user_units = executor.run_safe(
            "find /etc/systemd/system/ /lib/systemd/system/ -name '*.service' -newer /etc/passwd 2>/dev/null"
        )

        timer_list = []
        for line in timers.stdout.splitlines():
            parts = line.split(None, 7)
            if len(parts) >= 5:
                timer_list.append({"next": parts[0], "left": parts[1], "unit": parts[4] if len(parts) > 4 else ""})

        enabled_list = []
        for line in enabled.stdout.splitlines():
            parts = line.split()
            if parts:
                enabled_list.append({"unit": parts[0], "state": parts[1] if len(parts) > 1 else ""})

        raw = f"=== TIMERS ===\n{timers.stdout}\n\n=== ENABLED SERVICES ===\n{enabled.stdout}\n\n=== RECENT UNITS ===\n{user_units.stdout}"
        return ScanResult(
            scanner_name=self.name,
            raw_output=raw,
            parsed_data={"timers": timer_list, "enabled": enabled_list, "recent_units": user_units.stdout.splitlines()},
        )
