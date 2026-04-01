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

    # SSH config
    sshd = sections.get("sshd_config", {})
    if isinstance(sshd, dict) and sshd:
        t = Table(title="Configuração sshd", box=box.SIMPLE_HEAD)
        t.add_column("Parâmetro")
        t.add_column("Valor")
        for k, v in sshd.items():
            t.add_row(k, v)
        console.print(t)

    # Firewall
    firewall = sections.get("firewall", {})
    if isinstance(firewall, dict):
        ufw = firewall.get("ufw", {})
        if ufw.get("available"):
            console.print(Panel(ufw.get("output", ""), title="UFW", box=box.SIMPLE))
        ipt = firewall.get("iptables", {})
        if ipt.get("available") and not ufw.get("available"):
            console.print(Panel(ipt.get("output", ""), title="iptables", box=box.SIMPLE))

    # Fail2Ban
    f2b = sections.get("fail2ban", {})
    if isinstance(f2b, dict) and f2b.get("available"):
        jails = f2b.get("jail_list", [])
        t = Table(title=f"Fail2Ban — jails ({len(jails)})", box=box.SIMPLE_HEAD)
        t.add_column("Jail")
        t.add_column("Detalhes", overflow="fold")
        for jail in jails:
            t.add_row(jail, f2b.get("jails", {}).get(jail, ""))
        console.print(t)
    elif isinstance(f2b, dict) and not f2b.get("available"):
        console.print("  [dim]fail2ban: não instalado[/dim]")

    # Docker
    docker = sections.get("docker", {})
    if isinstance(docker, dict) and docker.get("available"):
        containers = docker.get("containers", [])
        if containers:
            console.print(_table(
                f"Containers Docker ({len(containers)})",
                containers,
                ["id", "name", "image", "status", "ports"],
            ))
        priv = docker.get("privileged_check", "")
        if priv:
            console.print(Panel(priv, title="Privileged check", box=box.SIMPLE))
    elif isinstance(docker, dict) and not docker.get("available"):
        console.print("  [dim]docker: não instalado[/dim]")

    # Auth Logs
    auth = sections.get("auth_logs", {})
    if isinstance(auth, dict):
        history = auth.get("login_history", [])
        if history:
            t = Table(title=f"Histórico de logins (last)", box=box.SIMPLE_HEAD)
            t.add_column("entrada", overflow="fold")
            for line in history[:20]:
                t.add_row(line)
            console.print(t)

        accepted = auth.get("successful_logins", [])
        if accepted:
            t = Table(title=f"Logins aceitos — últimas 48h ({len(accepted)})", box=box.SIMPLE_HEAD)
            t.add_column("entrada", overflow="fold")
            for line in accepted:
                t.add_row(line)
            console.print(t)

        failed = auth.get("failed_attempts", [])
        if failed:
            t = Table(title=f"Falhas de autenticação — últimas 48h ({len(failed)})", box=box.SIMPLE_HEAD)
            t.add_column("entrada", overflow="fold")
            for line in failed:
                t.add_row(line)
            console.print(t)

        sudo_usage = auth.get("sudo_usage", [])
        if sudo_usage:
            t = Table(title=f"Uso de sudo — últimas 48h ({len(sudo_usage)})", box=box.SIMPLE_HEAD)
            t.add_column("entrada", overflow="fold")
            for line in sudo_usage:
                t.add_row(line)
            console.print(t)

    # Rootkits
    rootkits = sections.get("rootkits", {})
    if isinstance(rootkits, dict):
        for tool, data in rootkits.items():
            if data.get("available"):
                output = data.get("output", "").strip()
                label = "[green]disponível[/green]" if not output else "[yellow]saída abaixo[/yellow]"
                console.print(f"  {tool}: {label}")
                if output:
                    console.print(f"[dim]{output}[/dim]")
            else:
                console.print(f"  [dim]{tool}: não instalado[/dim]")

    console.print()
