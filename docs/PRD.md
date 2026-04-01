# PRD — SecCheck (CLI + Skill de Auditoria Remota de Segurança Linux)

## 🎯 Objetivo

Criar uma ferramenta CLI + Skill para agentes capaz de:

* Conectar remotamente a um servidor Linux via SSH
* Coletar sinais de comprometimento
* Gerar um score de risco
* Produzir um relatório estruturado e **LLM-ready**
* Ser utilizável manualmente ou por agentes como Claude/OpenClaw

---

## 🧠 Problema

Administradores de VPS frequentemente:

* Não sabem se a máquina foi comprometida
* Não possuem uma rotina padronizada de auditoria
* Dependem de comandos soltos
* Precisam de uma saída pronta para análise por LLM

---

## 💡 Solução

Criar o **SecCheck**, uma CLI que:

1. Recebe credenciais SSH
2. Conecta na máquina remota
3. Executa scanners de coleta
4. Aplica heurísticas de risco
5. Gera relatório técnico e relatório **LLM-ready**

---

## 👤 Casos de uso

### 1. Scan remoto rápido

```bash
sec-check quick \
  --host 192.168.1.10 \
  --user ubuntu \
  --identity ~/.ssh/id_ed25519
```

### 2. Scan remoto completo

```bash
sec-check deep \
  --host servidor.exemplo.com \
  --user deploy \
  --identity ~/.ssh/producao.pem
```

### 3. Gerar relatório LLM-ready

```bash
sec-check deep \
  --host servidor.exemplo.com \
  --user root \
  --identity ~/.ssh/id_ed25519 \
  --format llm-json \
  --output report.json
```

---

## 🧩 Funcionalidades

### 1. Conexão SSH remota

A CLI deve aceitar:

* `--host`
* `--port` (default: 22)
* `--user`
* `--identity` (caminho da chave privada)
* `--known-hosts` opcional
* `--timeout`

A CLI **não deve exigir senha por padrão**. O foco inicial será autenticação por chave SSH.

---

### 2. Scan rápido

```bash
sec-check quick --host ... --user ... --identity ...
```

Inclui:

* Processos ativos
* Portas abertas
* Conexões de rede
* Usuários logados
* Serviços ativos mais relevantes

---

### 3. Scan completo

```bash
sec-check deep --host ... --user ... --identity ...
```

Inclui:

* Tudo do scan rápido
* SSH authorized_keys
* Crontabs
* Timers systemd
* Arquivos modificados recentemente
* Usuários e grupos suspeitos
* Verificação de diretórios sensíveis (`/tmp`, `/dev/shm`, `/var/tmp`)
* Rootkits conhecidos, se ferramentas existirem
* Persistência suspeita

---

### 4. Score de risco

| Score  | Status      |
| ------ | ----------- |
| 0-30   | SAFE        |
| 31-70  | SUSPICIOUS  |
| 71-100 | COMPROMISED |

---

### 5. Relatório LLM-ready

O sistema deve gerar uma saída limpa e estruturada, pronta para ser usada por outro agente.

#### Exemplo de saída JSON

```json
{
  "metadata": {
    "tool": "sec-check",
    "scan_type": "deep",
    "target": {
      "host": "servidor.exemplo.com",
      "port": 22,
      "user": "ubuntu"
    },
    "timestamp": "2026-04-01T10:30:00Z"
  },
  "summary": {
    "risk_score": 78,
    "status": "COMPROMISED",
    "confidence": "high"
  },
  "findings": [
    {
      "id": "proc_tmp_exec",
      "severity": "high",
      "category": "process",
      "title": "Processo executando em diretório suspeito",
      "evidence": {
        "command": "ps aux",
        "match": "/tmp/.x123/agent"
      },
      "reasoning": "Processos executando de /tmp são fortes indicadores de atividade maliciosa."
    },
    {
      "id": "ssh_unknown_key",
      "severity": "high",
      "category": "ssh",
      "title": "Chave SSH desconhecida detectada",
      "evidence": {
        "file": "/root/.ssh/authorized_keys",
        "match": "ssh-ed25519 AAAAC3..."
      },
      "reasoning": "A presença de chave não reconhecida sugere persistência via SSH."
    }
  ],
  "recommended_actions": [
    "Isolar a máquina da rede",
    "Revisar e remover chaves SSH desconhecidas",
    "Encerrar processos suspeitos",
    "Considerar rebuild da máquina"
  ],
  "raw_sections": {
    "processes": [],
    "network": [],
    "users": [],
    "ssh": [],
    "cron": []
  }
}
```

---

## ⚙️ Requisitos funcionais

### RF001 — Conexão remota

O sistema deve conectar via SSH usando usuário, host e chave privada.

### RF002 — Execução remota de comandos

O sistema deve executar comandos remotos de forma segura e capturar stdout, stderr e exit code.

### RF003 — Coleta estruturada

Cada scanner deve retornar dados em estrutura padronizada.

### RF004 — Análise heurística

O sistema deve transformar evidências em findings com severidade e score.

### RF005 — Relatório LLM-ready

O sistema deve gerar saída em formato altamente estruturado, sem ruído, fácil de consumir por LLM.

### RF006 — Exportação

O sistema deve permitir:

* `--format text`
* `--format json`
* `--format llm-json`
* `--output arquivo`

---

## ⚙️ Requisitos não funcionais

### RNF001 — Segurança

* Não registrar conteúdo sensível da chave privada
* Não imprimir a chave em logs
* Minimizar persistência local de segredos

### RNF002 — Robustez

* Tratar timeout e falhas de conexão
* Informar claramente quando um scanner não puder rodar

### RNF003 — Extensibilidade

* Cada scanner deve ser modular
* Novos scanners devem ser adicionados sem alterar o core

---

## 📂 Estrutura do projeto

```text
sec-check/
├── app/
│   ├── main.py
│   ├── cli.py
│   ├── config.py
│   ├── models/
│   │   ├── connection.py
│   │   ├── finding.py
│   │   ├── report.py
│   │   └── scan_result.py
│   ├── ssh/
│   │   ├── client.py
│   │   ├── executor.py
│   │   └── errors.py
│   ├── scanners/
│   │   ├── processes.py
│   │   ├── network.py
│   │   ├── users.py
│   │   ├── files.py
│   │   ├── ssh_keys.py
│   │   ├── cron.py
│   │   ├── systemd.py
│   │   └── rootkits.py
│   ├── analyzers/
│   │   ├── heuristics.py
│   │   ├── scoring.py
│   │   └── normalizer.py
│   ├── reporters/
│   │   ├── text_reporter.py
│   │   ├── json_reporter.py
│   │   └── llm_reporter.py
│   └── utils/
│       ├── logging.py
│       └── time.py
├── tests/
│   ├── test_scanners.py
│   ├── test_scoring.py
│   ├── test_llm_reporter.py
│   └── test_ssh_client.py
├── pyproject.toml
├── README.md
└── PRD.md
```

---

## 🧠 Lógica de análise

### Exemplos de regras

* Processo rodando em `/tmp` ou `/dev/shm` → +20
* Porta incomum escutando → +15
* Chave SSH desconhecida → +30
* Cron suspeito → +20
* Serviço persistente incomum → +20
* Ferramenta de rootkit acusando positivo → +35

---

## 🖥️ Comandos principais

### Scan rápido

```bash
sec-check quick --host HOST --user USER --identity KEY
```

### Scan profundo

```bash
sec-check deep --host HOST --user USER --identity KEY
```

### Testar conexão

```bash
sec-check doctor --host HOST --user USER --identity KEY
```

### Gerar relatório LLM-ready

```bash
sec-check deep \
  --host HOST \
  --user USER \
  --identity KEY \
  --format llm-json \
  --output report.json
```

---

## 🤖 Integração com agentes

O relatório LLM-ready deve ser consumível por:

* Claude Code
* OpenClaw
* agentes RAG
* pipelines de triagem automatizada

Uso esperado:

1. O CLI coleta
2. O relatório é salvo em JSON
3. O agente lê o arquivo e produz análise adicional ou plano de resposta

---

## 🚀 Roadmap

### MVP

* SSH remoto
* Scan quick
* JSON simples
* LLM-ready básico

### V1

* Scan deep
* scoring robusto
* reporter markdown + llm-json

### V2

* baseline por host
* comparação entre scans
* múltiplos hosts
* integração com API

---

## 🧾 Conclusão

O SecCheck será uma ferramenta de auditoria remota para Linux, focada em detecção inicial de comprometimento, com saída estruturada e pronta para consumo por LLMs e agentes operacionais.
