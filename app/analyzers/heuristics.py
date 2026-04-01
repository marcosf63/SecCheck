from __future__ import annotations

import re
from app.models.finding import Finding, Evidence
from app.models.scan_result import ScanResult


SUSPICIOUS_DIRS = ["/tmp", "/dev/shm", "/var/tmp"]

COMMON_PORTS = {
    22, 80, 443, 25, 587, 465, 110, 143, 993, 995,
    3306, 5432, 6379, 27017, 8080, 8443,
}

SUSPICIOUS_SHELLS = ["/bin/sh", "/bin/bash", "/bin/dash", "/usr/bin/python", "/usr/bin/perl"]

SUSPICIOUS_CRON_PATTERNS = [
    r"curl\s+.*\|\s*(ba)?sh",
    r"wget\s+.*\|\s*(ba)?sh",
    r"chmod\s+\+x",
    r"/tmp/",
    r"/dev/shm/",
    r"base64\s+-d",
    r"python.*-c\s+['\"]",
]


def analyze_processes(result: ScanResult) -> list[Finding]:
    findings = []
    if not result.success:
        return findings

    processes = result.parsed_data if isinstance(result.parsed_data, list) else []
    for proc in processes:
        cmd = proc.get("command", "")
        for d in SUSPICIOUS_DIRS:
            if cmd.startswith(d) or f" {d}/" in cmd:
                findings.append(Finding(
                    id=f"proc_suspicious_dir_{proc.get('pid', 'unknown')}",
                    severity="high",
                    category="process",
                    title="Processo executando em diretório suspeito",
                    evidence=Evidence(command="ps aux", match=cmd[:120]),
                    reasoning=f"Processo rodando em {d} é forte indicador de atividade maliciosa.",
                    score_contribution=20,
                ))
                break

    return findings


def analyze_network(result: ScanResult) -> list[Finding]:
    findings = []
    if not result.success:
        return findings

    data = result.parsed_data if isinstance(result.parsed_data, dict) else {}
    ports = data.get("ports", [])

    for port_entry in ports:
        addr = port_entry.get("local_address", "")
        match = re.search(r":(\d+)$", addr)
        if not match:
            continue
        port = int(match.group(1))
        if port not in COMMON_PORTS and port < 32768:
            findings.append(Finding(
                id=f"net_unusual_port_{port}",
                severity="medium",
                category="network",
                title=f"Porta incomum ouvindo: {port}",
                evidence=Evidence(command="ss -tulnp", match=addr),
                reasoning=f"Porta {port} não é comum em servidores e pode indicar backdoor ou serviço não autorizado.",
                score_contribution=15,
            ))

    return findings


def analyze_ssh_keys(result: ScanResult) -> list[Finding]:
    findings = []
    if not result.success:
        return findings

    keys = result.parsed_data if isinstance(result.parsed_data, list) else []
    if keys:
        for key in keys:
            findings.append(Finding(
                id=f"ssh_key_{hash(key.get('key', '')) % 100000}",
                severity="high",
                category="ssh",
                title="Chave SSH autorizada encontrada",
                evidence=Evidence(file=key.get("path", ""), match=key.get("full_line", "")[:80]),
                reasoning="Cada chave SSH autorizada deve ser auditada — chaves desconhecidas indicam possível persistência.",
                score_contribution=10,
            ))

    return findings


def analyze_cron(result: ScanResult) -> list[Finding]:
    findings = []
    if not result.success:
        return findings

    entries = result.parsed_data if isinstance(result.parsed_data, list) else []
    for entry in entries:
        line = entry.get("entry", "")
        for pattern in SUSPICIOUS_CRON_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(Finding(
                    id=f"cron_suspicious_{hash(line) % 100000}",
                    severity="high",
                    category="cron",
                    title="Entrada de cron suspeita detectada",
                    evidence=Evidence(command="crontab -l / /etc/crontab", match=line[:120]),
                    reasoning=f"Padrão suspeito encontrado em cron: '{pattern}'. Pode indicar persistência maliciosa.",
                    score_contribution=20,
                ))
                break

    return findings


def analyze_files(result: ScanResult) -> list[Finding]:
    findings = []
    if not result.success:
        return findings

    data = result.parsed_data if isinstance(result.parsed_data, dict) else {}

    executables = data.get("executables_in_tmp", [])
    for f in executables:
        findings.append(Finding(
            id=f"file_exec_tmp_{hash(f) % 100000}",
            severity="high",
            category="files",
            title="Arquivo executável em diretório temporário",
            evidence=Evidence(command="find /tmp /dev/shm /var/tmp -executable", match=f),
            reasoning="Executáveis em /tmp ou /dev/shm são fortemente suspeitos de atividade maliciosa.",
            score_contribution=20,
        ))

    return findings


def analyze_rootkits(result: ScanResult) -> list[Finding]:
    findings = []
    if not result.success:
        return findings

    data = result.parsed_data if isinstance(result.parsed_data, dict) else {}

    for tool in ["rkhunter", "chkrootkit"]:
        tool_data = data.get(tool, {})
        if tool_data.get("available") and tool_data.get("output"):
            output = tool_data["output"]
            if re.search(r"(warning|infected|INFECTED|FOUND)", output, re.IGNORECASE):
                findings.append(Finding(
                    id=f"rootkit_{tool}_positive",
                    severity="critical",
                    category="rootkit",
                    title=f"{tool} reportou resultado positivo",
                    evidence=Evidence(command=tool, match=output[:200]),
                    reasoning=f"{tool} encontrou indicadores de rootkit ou malware na máquina.",
                    score_contribution=35,
                ))

    return findings


def run_all_heuristics(scan_results: dict[str, ScanResult]) -> list[Finding]:
    findings = []

    analyzers = {
        "processes": analyze_processes,
        "network": analyze_network,
        "ssh_keys": analyze_ssh_keys,
        "cron": analyze_cron,
        "files": analyze_files,
        "rootkits": analyze_rootkits,
    }

    for scanner_name, analyze_fn in analyzers.items():
        result = scan_results.get(scanner_name)
        if result:
            findings.extend(analyze_fn(result))

    return findings
