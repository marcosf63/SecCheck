from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field

from app.models.finding import Finding


ScanType = Literal["quick", "deep"]
RiskStatus = Literal["SAFE", "SUSPICIOUS", "COMPROMISED"]


class TargetInfo(BaseModel):
    host: str
    port: int
    user: str


class ReportMetadata(BaseModel):
    tool: str = "sec-check"
    scan_type: ScanType
    target: TargetInfo
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


class RiskSummary(BaseModel):
    risk_score: int
    status: RiskStatus
    confidence: Literal["low", "medium", "high"] = "medium"


class Report(BaseModel):
    metadata: ReportMetadata
    summary: RiskSummary
    findings: list[Finding] = []
    recommended_actions: list[str] = []
    raw_sections: dict[str, list] = Field(default_factory=dict)
