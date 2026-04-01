"""
Reporter LLM-ready: produz JSON limpo e estruturado, otimizado para consumo por LLMs e agentes.
Segue a spec do PRD.
"""
from __future__ import annotations

import json
from app.models.report import Report


def to_llm_json(report: Report, indent: int = 2) -> str:
    findings_out = []
    for f in report.findings:
        findings_out.append({
            "id": f.id,
            "severity": f.severity,
            "category": f.category,
            "title": f.title,
            "evidence": {k: v for k, v in f.evidence.model_dump().items() if v is not None},
            "reasoning": f.reasoning,
        })

    payload = {
        "metadata": {
            "tool": report.metadata.tool,
            "scan_type": report.metadata.scan_type,
            "target": report.metadata.target.model_dump(),
            "timestamp": report.metadata.timestamp,
        },
        "summary": {
            "risk_score": report.summary.risk_score,
            "status": report.summary.status,
            "confidence": report.summary.confidence,
        },
        "findings": findings_out,
        "recommended_actions": report.recommended_actions,
        "raw_sections": report.raw_sections,
    }

    return json.dumps(payload, ensure_ascii=False, indent=indent)


def save_llm_json(report: Report, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(to_llm_json(report))
