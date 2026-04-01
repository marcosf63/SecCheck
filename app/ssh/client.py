from __future__ import annotations

import socket
from pathlib import Path

import paramiko

from app.models.connection import SSHConnection
from app.ssh.errors import AuthenticationError, SSHConnectionError


class SSHClient:
    def __init__(self, connection: SSHConnection) -> None:
        self._conn = connection
        self._client: paramiko.SSHClient | None = None

    def connect(self) -> None:
        identity = Path(self._conn.identity_file).expanduser()
        if not identity.exists():
            raise SSHConnectionError(f"Chave privada não encontrada: {identity}")

        client = paramiko.SSHClient()
        if self._conn.known_hosts:
            client.load_host_keys(self._conn.known_hosts)
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname=self._conn.host,
                port=self._conn.port,
                username=self._conn.user,
                key_filename=str(identity),
                timeout=self._conn.timeout,
                look_for_keys=False,
                allow_agent=False,
            )
        except paramiko.AuthenticationException as exc:
            raise AuthenticationError(f"Autenticação falhou para {self._conn.user}@{self._conn.host}") from exc
        except (paramiko.SSHException, socket.error) as exc:
            raise SSHConnectionError(f"Não foi possível conectar a {self._conn.host}:{self._conn.port} — {exc}") from exc

        self._client = client

    def disconnect(self) -> None:
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self) -> SSHClient:
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.disconnect()

    @property
    def raw(self) -> paramiko.SSHClient:
        if not self._client:
            raise SSHConnectionError("Não conectado. Chame connect() primeiro.")
        return self._client
