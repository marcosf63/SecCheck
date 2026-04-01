from app.models.scan_result import ScanResult
from app.scanners.base import BaseScanner
from app.ssh.executor import RemoteExecutor


class RootkitScanner(BaseScanner):
    name = "rootkits"

    def _run(self, executor: RemoteExecutor) -> ScanResult:
        results = {}
        raw_parts = []

        rkhunter = executor.run_safe("which rkhunter 2>/dev/null")
        if rkhunter.stdout:
            run = executor.run_safe("rkhunter --check --skip-keypress --quiet 2>/dev/null | tail -20")
            results["rkhunter"] = {"available": True, "output": run.stdout}
            raw_parts.append(f"=== RKHUNTER ===\n{run.stdout}")
        else:
            results["rkhunter"] = {"available": False}

        chkrootkit = executor.run_safe("which chkrootkit 2>/dev/null")
        if chkrootkit.stdout:
            run = executor.run_safe("chkrootkit 2>/dev/null | grep -i infected")
            results["chkrootkit"] = {"available": True, "output": run.stdout}
            raw_parts.append(f"=== CHKROOTKIT ===\n{run.stdout}")
        else:
            results["chkrootkit"] = {"available": False}

        if not results["rkhunter"]["available"] and not results["chkrootkit"]["available"]:
            raw_parts.append("Nenhuma ferramenta de rootkit disponível (rkhunter, chkrootkit).")

        return ScanResult(
            scanner_name=self.name,
            raw_output="\n\n".join(raw_parts),
            parsed_data=results,
        )
