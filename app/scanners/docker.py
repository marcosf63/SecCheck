"""
Scanner: containers Docker em execução e configuração de segurança.
"""
from app.models.scan_result import ScanResult
from app.scanners.base import BaseScanner
from app.ssh.executor import RemoteExecutor


class DockerScanner(BaseScanner):
    name = "docker"

    def _run(self, executor: RemoteExecutor) -> ScanResult:
        check = executor.run_safe("which docker 2>/dev/null")
        if not check.stdout.strip():
            return ScanResult(
                scanner_name=self.name,
                raw_output="Docker não instalado",
                parsed_data={"available": False},
            )

        parts: list[str] = []
        data: dict = {"available": True}

        # Containers (todos, inclusive parados)
        ps = executor.run_safe(
            "sudo docker ps -a --format "
            "'{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.Names}}' 2>/dev/null"
        )
        containers: list[dict] = []
        for line in ps.stdout.strip().splitlines():
            parts_line = line.split("\t")
            if len(parts_line) >= 5:
                containers.append({
                    "id":     parts_line[0],
                    "image":  parts_line[1],
                    "status": parts_line[2],
                    "ports":  parts_line[3],
                    "name":   parts_line[4],
                })
        data["containers"] = containers
        parts.append(f"=== CONTAINERS ===\n{ps.stdout.strip()}")

        # Volumes
        volumes = executor.run_safe("sudo docker volume ls 2>/dev/null")
        data["volumes"] = volumes.stdout.strip()
        parts.append(f"=== VOLUMES ===\n{volumes.stdout.strip()}")

        # Redes
        networks = executor.run_safe(
            "sudo docker network ls --format '{{.ID}}\t{{.Name}}\t{{.Driver}}\t{{.Scope}}' 2>/dev/null"
        )
        data["networks"] = networks.stdout.strip()
        parts.append(f"=== REDES ===\n{networks.stdout.strip()}")

        # Containers com --privileged
        privileged = executor.run_safe(
            "sudo docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}}' "
            "$(sudo docker ps -q 2>/dev/null) 2>/dev/null"
        )
        data["privileged_check"] = privileged.stdout.strip()
        parts.append(f"=== PRIVILEGED CHECK ===\n{privileged.stdout.strip()}")

        return ScanResult(
            scanner_name=self.name,
            raw_output="\n\n".join(parts),
            parsed_data=data,
        )
