from __future__ import annotations

from app.models.finding import Finding
from app.models.report import RiskSummary


def calculate_score(findings: list[Finding]) -> RiskSummary:
    total = sum(f.score_contribution for f in findings)
    total = min(total, 100)

    if total <= 30:
        status = "SAFE"
    elif total <= 70:
        status = "SUSPICIOUS"
    else:
        status = "COMPROMISED"

    critical_count = sum(1 for f in findings if f.severity == "critical")
    high_count = sum(1 for f in findings if f.severity == "high")

    if critical_count > 0:
        confidence = "high"
    elif high_count >= 2:
        confidence = "high"
    elif high_count == 1 or total > 0:
        confidence = "medium"
    else:
        confidence = "low"

    return RiskSummary(risk_score=total, status=status, confidence=confidence)
