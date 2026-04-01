# SecCheck

CLI de auditoria remota de segurança Linux via SSH. Coleta dados do servidor e produz relatório estruturado — pronto para consumo por LLMs e agentes.

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

### Usando ~/.ssh/config

`--user`, `--identity` e `--port` são opcionais quando o host está configurado em `~/.ssh/config`. Flags da CLI sempre têm prioridade sobre o config file.

```bash
# Se "meu-servidor" estiver no ~/.ssh/config com User e IdentityFile definidos:
sec-check quick --host meu-servidor
```

## Opções globais

| Opção | Padrão | Descrição |
|---|---|---|
| `--host` | — | Host, IP ou alias do `~/.ssh/config` |
| `--user` | — | Usuário SSH (usa `~/.ssh/config` se omitido) |
| `--identity` | — | Chave privada SSH (usa `~/.ssh/config` se omitido) |
| `--port` | `22` | Porta SSH (usa `~/.ssh/config` se omitido) |
| `--timeout` | `30` | Timeout da conexão (segundos) |
| `--format` | `text` | Formato de saída: `text`, `json`, `llm-json` |
| `--output` | — | Arquivo de saída (opcional) |

## Scanners

### Quick scan
- Processos ativos
- Portas abertas e conexões de rede
- Usuários logados
- Serviços rodando

### Deep scan (inclui quick +)
- Chaves SSH autorizadas
- Configuração do sshd (`/etc/ssh/sshd_config`)
- Status do firewall (UFW / iptables)
- Fail2ban: status e jails ativos
- Docker: containers, volumes, redes e containers privilegiados
- Logs de autenticação: logins aceitos, falhas e uso de sudo (janela de 48h)
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
├── models/           # Pydantic: SSHConnection, ScanResult, Report
├── ssh/              # SSHClient, RemoteExecutor, erros
├── scanners/         # Módulos de coleta (1 por domínio)
├── reporters/        # text, json, llm-json
└── utils/            # ssh_config: resolução de ~/.ssh/config
tests/                # pytest
```
