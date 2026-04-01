from abc import ABC, abstractmethod

from app.models.scan_result import ScanResult
from app.ssh.executor import RemoteExecutor


class BaseScanner(ABC):
    name: str = ""

    def run(self, executor: RemoteExecutor) -> ScanResult:
        try:
            return self._run(executor)
        except Exception as exc:
            return ScanResult(scanner_name=self.name, error=str(exc))

    @abstractmethod
    def _run(self, executor: RemoteExecutor) -> ScanResult:
        ...
