from __future__ import annotations

from dataclasses import dataclass

from app.ssh.client import SSHClient
from app.ssh.errors import CommandExecutionError


@dataclass
class CommandResult:
    command: str
    stdout: str
    stderr: str
    exit_code: int

    @property
    def success(self) -> bool:
        return self.exit_code == 0


class RemoteExecutor:
    def __init__(self, client: SSHClient, command_timeout: int = 30) -> None:
        self._client = client
        self._timeout = command_timeout

    def run(self, command: str) -> CommandResult:
        try:
            _, stdout_obj, stderr_obj = self._client.raw.exec_command(
                command, timeout=self._timeout
            )
            stdout = stdout_obj.read().decode("utf-8", errors="replace").strip()
            stderr = stderr_obj.read().decode("utf-8", errors="replace").strip()
            exit_code = stdout_obj.channel.recv_exit_status()
        except Exception as exc:
            raise CommandExecutionError(f"Erro ao executar '{command}': {exc}") from exc

        return CommandResult(
            command=command,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
        )

    def run_safe(self, command: str) -> CommandResult:
        """Executa o comando sem lançar exceção em caso de falha."""
        try:
            return self.run(command)
        except CommandExecutionError:
            return CommandResult(command=command, stdout="", stderr="command failed", exit_code=1)
