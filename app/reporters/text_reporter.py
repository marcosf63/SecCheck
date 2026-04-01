from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.text import Text

from app.models.report import Report

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

STATUS_COLORS = {
    "SAFE": "bold green",
    "SUSPICIOUS": "bold yellow",
    "COMPROMISED": "bold red",
}


def print_report(report: Report) -> None:
    status_color = STATUS_COLORS.get(report.summary.status, "white")
    score = report.summary.risk_score

    console.print()
    console.print(Panel(
        f"[bold]SecCheck — Relatório de Auditoria[/bold]\n"
        f"Host: [cyan]{report.metadata.target.host}:{report.metadata.target.port}[/cyan] "
        f"| Usuário: [cyan]{report.metadata.target.user}[/cyan] "
        f"| Scan: [cyan]{report.metadata.scan_type}[/cyan]\n"
        f"Data: [dim]{report.metadata.timestamp}[/dim]",
        box=box.ROUNDED,
    ))

    console.print(Panel(
        f"Score de Risco: [{status_color}]{score}/100[/{status_color}]   "
        f"Status: [{status_color}]{report.summary.status}[/{status_color}]   "
        f"Confiança: [dim]{report.summary.confidence}[/dim]",
        title="[bold]Resumo[/bold]",
        box=box.ROUNDED,
    ))

    if report.findings:
        table = Table(title="Findings", box=box.SIMPLE_HEAD, show_lines=True)
        table.add_column("Severidade", style="bold", width=10)
        table.add_column("Categoria", width=10)
        table.add_column("Título", width=40)
        table.add_column("Evidência", width=50)
        table.add_column("+Score", justify="right", width=7)

        for f in sorted(report.findings, key=lambda x: ["critical","high","medium","low","info"].index(x.severity)):
            color = SEVERITY_COLORS.get(f.severity, "white")
            evidence_str = f.evidence.match or f.evidence.file or f.evidence.command or ""
            table.add_row(
                Text(f.severity.upper(), style=color),
                f.category,
                f.title,
                evidence_str[:60],
                f"+{f.score_contribution}",
            )
        console.print(table)
    else:
        console.print("[green]Nenhum finding detectado.[/green]")

    if report.recommended_actions:
        console.print(Panel(
            "\n".join(f"• {a}" for a in report.recommended_actions),
            title="[bold]Ações Recomendadas[/bold]",
            box=box.ROUNDED,
        ))

    console.print()
