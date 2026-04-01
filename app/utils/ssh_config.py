"""Leitura de ~/.ssh/config via Paramiko."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import paramiko


@dataclass
class SSHConfigEntry:
    hostname: str | None = None   # HostName resolvido
    user: str | None = None
    port: int | None = None
    identity_file: str | None = None


def load_ssh_config(host: str, config_path: str = "~/.ssh/config") -> SSHConfigEntry:
    """Lê ~/.ssh/config e retorna as opções para o host especificado."""
    path = Path(config_path).expanduser()
    if not path.exists():
        return SSHConfigEntry()

    cfg = paramiko.SSHConfig()
    with open(path) as f:
        cfg.parse(f)

    options = cfg.lookup(host)

    port = None
    if "port" in options:
        try:
            port = int(options["port"])
        except ValueError:
            pass

    identity_file = None
    identity_files = options.get("identityfile", [])
    if identity_files:
        candidate = Path(identity_files[0]).expanduser()
        if candidate.exists():
            identity_file = str(candidate)

    return SSHConfigEntry(
        hostname=options.get("hostname"),
        user=options.get("user"),
        port=port,
        identity_file=identity_file,
    )
