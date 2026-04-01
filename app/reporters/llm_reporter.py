"""
Reporter LLM-ready: JSON estruturado com os dados coletados, sem julgamentos.
Otimizado para consumo por agentes e LLMs.
"""
from __future__ import annotations

import json
from app.models.report import Report


def to_llm_json(report: Report, indent: int = 2) -> str:
    payload = {
        "metadata": {
            "tool": report.metadata.tool,
            "scan_type": report.metadata.scan_type,
            "target": report.metadata.target.model_dump(),
            "timestamp": report.metadata.timestamp,
        },
        "sections": report.sections,
    }
    return json.dumps(payload, ensure_ascii=False, indent=indent)


def save_llm_json(report: Report, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(to_llm_json(report))
