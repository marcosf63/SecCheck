from app.scanners.base import BaseScanner
from app.scanners.processes import ProcessScanner
from app.scanners.network import NetworkScanner
from app.scanners.users import UsersScanner
from app.scanners.services import ServicesScanner
from app.scanners.ssh_keys import SSHKeysScanner
from app.scanners.cron import CronScanner
from app.scanners.systemd import SystemdScanner
from app.scanners.files import FilesScanner
from app.scanners.rootkits import RootkitScanner

QUICK_SCANNERS: list[BaseScanner] = [
    ProcessScanner(),
    NetworkScanner(),
    UsersScanner(),
    ServicesScanner(),
]

DEEP_SCANNERS: list[BaseScanner] = QUICK_SCANNERS + [
    SSHKeysScanner(),
    CronScanner(),
    SystemdScanner(),
    FilesScanner(),
    RootkitScanner(),
]

__all__ = [
    "BaseScanner",
    "ProcessScanner",
    "NetworkScanner",
    "UsersScanner",
    "ServicesScanner",
    "SSHKeysScanner",
    "CronScanner",
    "SystemdScanner",
    "FilesScanner",
    "RootkitScanner",
    "QUICK_SCANNERS",
    "DEEP_SCANNERS",
]
