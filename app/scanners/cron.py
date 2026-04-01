from app.models.scan_result import ScanResult
from app.scanners.base import BaseScanner
from app.ssh.executor import RemoteExecutor


class CronScanner(BaseScanner):
    name = "cron"

    def _run(self, executor: RemoteExecutor) -> ScanResult:
        crontab = executor.run_safe("crontab -l 2>/dev/null")
        system_cron = executor.run_safe("cat /etc/crontab 2>/dev/null")
        cron_d = executor.run_safe("ls /etc/cron.d/ 2>/dev/null && cat /etc/cron.d/* 2>/dev/null")
        cron_hourly = executor.run_safe("ls /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null")

        entries = []
        all_raw = []

        for label, result in [
            ("crontab -l", crontab),
            ("/etc/crontab", system_cron),
            ("/etc/cron.d/*", cron_d),
            ("cron.*/", cron_hourly),
        ]:
            if result.stdout:
                all_raw.append(f"=== {label} ===\n{result.stdout}")
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        entries.append({"source": label, "entry": line})

        return ScanResult(
            scanner_name=self.name,
            raw_output="\n\n".join(all_raw),
            parsed_data=entries,
        )
