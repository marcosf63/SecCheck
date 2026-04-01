from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field


ScanType = Literal["quick", "deep"]


class TargetInfo(BaseModel):
    host: str
    port: int
    user: str


class ReportMetadata(BaseModel):
    tool: str = "sec-check"
    scan_type: ScanType
    target: TargetInfo
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


class Report(BaseModel):
    metadata: ReportMetadata
    sections: dict[str, Any] = Field(default_factory=dict)
