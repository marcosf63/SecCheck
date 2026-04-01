from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from app.models.report import Report

console = Console()


def _table(title: str, rows: list[dict], columns: list[str]) -> Table:
    t = Table(title=title, box=box.SIMPLE_HEAD, show_lines=False)
    for col in columns:
        t.add_column(col, overflow="fold")
    for row in rows:
        t.add_row(*[str(row.get(c, "")) for c in columns])
    return t


def print_report(report: Report) -> None:
    console.print()
    console.print(Panel(
        f"[bold]SecCheck — Coleta de Dados[/bold]\n"
        f"Host: [cyan]{report.metadata.target.host}:{report.metadata.target.port}[/cyan] "
        f"| Usuário: [cyan]{report.metadata.target.user}[/cyan] "
        f"| Scan: [cyan]{report.metadata.scan_type}[/cyan]\n"
        f"Data: [dim]{report.metadata.timestamp}[/dim]",
        box=box.ROUNDED,
    ))

    sections = report.sections

    # Processos
    processes = sections.get("processes", [])
    if processes:
        console.print(_table(
            f"Processos ({len(processes)})",
            processes,
            ["user", "pid", "cpu", "mem", "command"],
        ))

    # Rede
    network = sections.get("network", {})
    ports = network.get("ports", []) if isinstance(network, dict) else []
    if ports:
        console.print(_table(
            f"Portas abertas ({len(ports)})",
            ports,
            ["proto", "state", "local_address", "process"],
        ))
    connections = network.get("connections", []) if isinstance(network, dict) else []
    if connections:
        console.print(_table(
            f"Conexões estabelecidas ({len(connections)})",
            connections,
            ["local", "remote", "process"],
        ))

    # Usuários
    users = sections.get("users", {})
    if isinstance(users, dict):
        logged = users.get("logged", [])
        if logged:
            console.print(_table("Usuários logados", logged, ["user", "tty", "from"]))
        system_users = users.get("system_users", [])
        if system_users:
            console.print(_table(
                f"Usuários do sistema ({len(system_users)})",
                system_users,
                ["user", "uid", "home", "shell"],
            ))

    # Serviços
    services = sections.get("services", [])
    if services:
        console.print(_table(
            f"Serviços ativos ({len(services)})",
            services,
            ["unit", "active", "sub", "description"],
        ))

    # Chaves SSH
    ssh_keys = sections.get("ssh_keys", [])
    if ssh_keys:
        console.print(_table(
            f"Chaves SSH autorizadas ({len(ssh_keys)})",
            ssh_keys,
            ["path", "key_type", "comment", "key"],
        ))

    # Cron
    cron = sections.get("cron", [])
    if cron:
        console.print(_table(
            f"Entradas de cron ({len(cron)})",
            cron,
            ["source", "entry"],
        ))

    # Systemd
    systemd = sections.get("systemd", {})
    if isinstance(systemd, dict):
        timers = systemd.get("timers", [])
        if timers:
            console.print(_table("Timers systemd", timers, ["next", "left", "unit"]))

    # Arquivos
    files = sections.get("files", {})
    if isinstance(files, dict):
        for key, label in [
            ("suspicious_files", "Arquivos em diretórios temporários"),
            ("executables_in_tmp", "Executáveis em /tmp, /dev/shm, /var/tmp"),
            ("recent_system_files", "Arquivos de sistema modificados recentemente"),
            ("suid_files", "Arquivos com SUID"),
        ]:
            items = files.get(key, [])
            if items:
                t = Table(title=f"{label} ({len(items)})", box=box.SIMPLE_HEAD)
                t.add_column("path", overflow="fold")
                for item in items:
                    t.add_row(item)
                console.print(t)

    # Rootkits
    rootkits = sections.get("rootkits", {})
    if isinstance(rootkits, dict):
        for tool, data in rootkits.items():
            if data.get("available"):
                output = data.get("output", "").strip()
                label = f"[green]disponível[/green]" if not output else f"[yellow]saída abaixo[/yellow]"
                console.print(f"  {tool}: {label}")
                if output:
                    console.print(f"[dim]{output}[/dim]")
            else:
                console.print(f"  [dim]{tool}: não instalado[/dim]")

    console.print()
