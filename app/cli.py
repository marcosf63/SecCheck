from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from app.models.connection import SSHConnection
from app.models.report import Report, ReportMetadata, TargetInfo
from app.ssh.client import SSHClient
from app.ssh.executor import RemoteExecutor
from app.ssh.errors import SSHConnectionError, AuthenticationError
from app.scanners import QUICK_SCANNERS, DEEP_SCANNERS
from app.analyzers import run_all_heuristics, calculate_score, get_recommended_actions
from app.reporters import print_report, to_json, save_json, to_llm_json, save_llm_json
from app.utils.ssh_config import load_ssh_config

app = typer.Typer(
    name="sec-check",
    help="Auditoria remota de segurança Linux via SSH.",
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True)

# ── Opções comuns ──────────────────────────────────────────────────────────────

HostOpt      = Annotated[str, typer.Option("--host", "-H", help="Host, IP ou alias do ~/.ssh/config.")]
UserOpt      = Annotated[str | None, typer.Option("--user", "-u", help="Usuário SSH (usa ~/.ssh/config se omitido).")]
IdentityOpt  = Annotated[str | None, typer.Option("--identity", "-i", help="Chave privada SSH (usa ~/.ssh/config se omitido).")]
PortOpt      = Annotated[int | None, typer.Option("--port", "-p", help="Porta SSH (usa ~/.ssh/config ou 22 se omitido).")]
TimeoutOpt   = Annotated[int, typer.Option("--timeout", help="Timeout da conexão em segundos.", show_default=True)]
FormatOpt    = Annotated[str, typer.Option("--format", "-f", help="Formato de saída: text | json | llm-json.", show_default=True)]
OutputOpt    = Annotated[str | None, typer.Option("--output", "-o", help="Arquivo de saída (opcional).")]


def _build_connection(
    host: str,
    user: str | None,
    identity: str | None,
    port: int | None,
    timeout: int,
) -> SSHConnection:
    """Resolve parâmetros de conexão mesclando CLI + ~/.ssh/config (CLI tem prioridade)."""
    cfg = load_ssh_config(host)

    resolved_host     = cfg.hostname or host
    resolved_user     = user     or cfg.user
    resolved_port     = port     or cfg.port or 22
    resolved_identity = identity or cfg.identity_file

    if not resolved_user:
        err_console.print(
            "[red]Erro:[/red] Usuário SSH não informado e não encontrado em ~/.ssh/config.\n"
            "Use [bold]--user[/bold] ou adicione uma entrada 'User' no ~/.ssh/config para este host."
        )
        raise typer.Exit(1)

    if not resolved_identity:
        err_console.print(
            "[red]Erro:[/red] Chave SSH não informada e não encontrada em ~/.ssh/config.\n"
            "Use [bold]--identity[/bold] ou adicione 'IdentityFile' no ~/.ssh/config para este host."
        )
        raise typer.Exit(1)

    identity_path = Path(resolved_identity).expanduser()
    if not identity_path.exists():
        err_console.print(f"[red]Erro:[/red] Chave privada não encontrada: {identity_path}")
        raise typer.Exit(1)

    if cfg.hostname and host != cfg.hostname:
        console.print(f"[dim]SSH config: {host} → {cfg.hostname}[/dim]")

    return SSHConnection(
        host=resolved_host,
        port=resolved_port,
        user=resolved_user,
        identity_file=str(identity_path),
        timeout=timeout,
    )


def _run_scan(connection: SSHConnection, scan_type: str, scanners: list) -> Report:
    results: dict = {}

    with SSHClient(connection) as client:
        executor = RemoteExecutor(client)
        console.print(f"[dim]Conectado a {connection.host}:{connection.port} como {connection.user}[/dim]")

        with console.status("[bold green]Executando scanners...") as status:
            for scanner in scanners:
                status.update(f"[bold green]Scanner: {scanner.name}...")
                result = scanner.run(executor)
                results[scanner.name] = result
                icon = "[green]✓[/green]" if result.success else "[yellow]![/yellow]"
                console.print(f"  {icon} {scanner.name}")

    findings = run_all_heuristics(results)
    summary = calculate_score(findings)
    actions = get_recommended_actions(summary.status)

    raw_sections = {
        name: (res.parsed_data if isinstance(res.parsed_data, list) else [])
        for name, res in results.items()
    }

    return Report(
        metadata=ReportMetadata(
            scan_type=scan_type,
            target=TargetInfo(host=connection.host, port=connection.port, user=connection.user),
        ),
        summary=summary,
        findings=findings,
        recommended_actions=actions,
        raw_sections=raw_sections,
    )


def _output_report(report: Report, fmt: str, output: str | None) -> None:
    if fmt == "text":
        print_report(report)
        if output:
            with open(output, "w") as f:
                from io import StringIO
                from rich.console import Console as RConsole
                buf = StringIO()
                c = RConsole(file=buf, highlight=False, markup=False)
                c.print(report.model_dump_json(indent=2))
                f.write(buf.getvalue())
    elif fmt == "json":
        content = to_json(report)
        if output:
            save_json(report, output)
            console.print(f"[green]Relatório salvo em:[/green] {output}")
        else:
            print(content)
    elif fmt == "llm-json":
        content = to_llm_json(report)
        if output:
            save_llm_json(report, output)
            console.print(f"[green]Relatório LLM-ready salvo em:[/green] {output}")
        else:
            print(content)
    else:
        err_console.print(f"[red]Formato desconhecido:[/red] {fmt}. Use text, json ou llm-json.")
        raise typer.Exit(1)


# ── Comandos ───────────────────────────────────────────────────────────────────

@app.command()
def quick(
    host: HostOpt,
    user: UserOpt = None,
    identity: IdentityOpt = None,
    port: PortOpt = None,
    timeout: TimeoutOpt = 30,
    fmt: FormatOpt = "text",
    output: OutputOpt = None,
) -> None:
    """Scan rápido: processos, rede, usuários e serviços."""
    connection = _build_connection(host, user, identity, port, timeout)
    try:
        report = _run_scan(connection, "quick", QUICK_SCANNERS)
    except AuthenticationError as e:
        err_console.print(f"[red]Autenticação falhou:[/red] {e}")
        raise typer.Exit(1)
    except SSHConnectionError as e:
        err_console.print(f"[red]Falha de conexão:[/red] {e}")
        raise typer.Exit(1)
    _output_report(report, fmt, output)


@app.command()
def deep(
    host: HostOpt,
    user: UserOpt = None,
    identity: IdentityOpt = None,
    port: PortOpt = None,
    timeout: TimeoutOpt = 30,
    fmt: FormatOpt = "text",
    output: OutputOpt = None,
) -> None:
    """Scan completo: todos os scanners incluindo SSH keys, cron, systemd, arquivos e rootkits."""
    connection = _build_connection(host, user, identity, port, timeout)
    try:
        report = _run_scan(connection, "deep", DEEP_SCANNERS)
    except AuthenticationError as e:
        err_console.print(f"[red]Autenticação falhou:[/red] {e}")
        raise typer.Exit(1)
    except SSHConnectionError as e:
        err_console.print(f"[red]Falha de conexão:[/red] {e}")
        raise typer.Exit(1)
    _output_report(report, fmt, output)


@app.command()
def doctor(
    host: HostOpt,
    user: UserOpt = None,
    identity: IdentityOpt = None,
    port: PortOpt = None,
    timeout: TimeoutOpt = 10,
) -> None:
    """Testa conectividade SSH e valida as credenciais."""
    connection = _build_connection(host, user, identity, port, timeout)
    console.print(f"[dim]Testando conexão com {connection.host}:{connection.port}...[/dim]")
    try:
        with SSHClient(connection) as client:
            executor = RemoteExecutor(client)
            result = executor.run("uname -a && whoami && uptime")
            console.print(f"[green]✓ Conexão OK[/green]")
            console.print(f"[dim]{result.stdout}[/dim]")
    except AuthenticationError as e:
        err_console.print(f"[red]✗ Autenticação falhou:[/red] {e}")
        raise typer.Exit(1)
    except SSHConnectionError as e:
        err_console.print(f"[red]✗ Falha de conexão:[/red] {e}")
        raise typer.Exit(1)
