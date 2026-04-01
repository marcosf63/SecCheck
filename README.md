# SecCheck

CLI de auditoria remota de segurança Linux via SSH. Coleta sinais de comprometimento, gera score de risco e produz relatório estruturado — pronto para consumo por LLMs e agentes.

## Instalação

```bash
uv tool install .
# ou para desenvolvimento:
uv sync
```

## Uso

### Testar conectividade

```bash
sec-check doctor --host 192.168.1.10 --user ubuntu --identity ~/.ssh/id_ed25519
```

### Scan rápido

```bash
sec-check quick --host 192.168.1.10 --user ubuntu --identity ~/.ssh/id_ed25519
```

### Scan completo

```bash
sec-check deep --host servidor.exemplo.com --user deploy --identity ~/.ssh/producao.pem
```

### Gerar relatório LLM-ready

```bash
sec-check deep \
  --host servidor.exemplo.com \
  --user root \
  --identity ~/.ssh/id_ed25519 \
  --format llm-json \
  --output report.json
```

## Opções globais

| Opção | Padrão | Descrição |
|---|---|---|
| `--host` | — | Host ou IP do servidor remoto |
| `--user` | — | Usuário SSH |
| `--identity` | — | Caminho da chave privada SSH |
| `--port` | `22` | Porta SSH |
| `--timeout` | `30` | Timeout da conexão (segundos) |
| `--format` | `text` | Formato de saída: `text`, `json`, `llm-json` |
| `--output` | — | Arquivo de saída (opcional) |

## Score de risco

| Score | Status |
|---|---|
| 0–30 | SAFE |
| 31–70 | SUSPICIOUS |
| 71–100 | COMPROMISED |

## Scanners

### Quick scan
- Processos ativos
- Portas abertas e conexões de rede
- Usuários logados
- Serviços rodando

### Deep scan (inclui quick +)
- Chaves SSH autorizadas
- Crontabs e agendamentos
- Timers e serviços systemd
- Arquivos em diretórios suspeitos (`/tmp`, `/dev/shm`, `/var/tmp`)
- Rootkits via `rkhunter` / `chkrootkit` (se disponíveis)

## Testes

```bash
uv run pytest
```

## Estrutura do projeto

```
app/
├── cli.py            # Comandos Typer (quick, deep, doctor)
├── main.py           # Entry point
├── models/           # Pydantic: SSHConnection, Finding, ScanResult, Report
├── ssh/              # SSHClient, RemoteExecutor, erros
├── scanners/         # Módulos de coleta (1 por domínio)
├── analyzers/        # Heurísticas, scoring, normalizer
└── reporters/        # text, json, llm-json
tests/                # pytest
```
