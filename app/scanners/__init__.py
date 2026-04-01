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
from app.scanners.sshd_config import SshdConfigScanner
from app.scanners.firewall import FirewallScanner
from app.scanners.fail2ban import Fail2BanScanner
from app.scanners.docker import DockerScanner
from app.scanners.auth_logs import AuthLogsScanner

QUICK_SCANNERS: list[BaseScanner] = [
    ProcessScanner(),
    NetworkScanner(),
    UsersScanner(),
    ServicesScanner(),
]

DEEP_SCANNERS: list[BaseScanner] = QUICK_SCANNERS + [
    SSHKeysScanner(),
    SshdConfigScanner(),
    FirewallScanner(),
    Fail2BanScanner(),
    DockerScanner(),
    AuthLogsScanner(),
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
    "SshdConfigScanner",
    "FirewallScanner",
    "Fail2BanScanner",
    "DockerScanner",
    "AuthLogsScanner",
    "QUICK_SCANNERS",
    "DEEP_SCANNERS",
]
