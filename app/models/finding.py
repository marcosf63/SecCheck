from typing import Literal
from pydantic import BaseModel


Severity = Literal["critical", "high", "medium", "low", "info"]
Category = Literal["process", "network", "ssh", "cron", "systemd", "files", "users", "rootkit"]


class Evidence(BaseModel):
    command: str | None = None
    file: str | None = None
    match: str | None = None


class Finding(BaseModel):
    id: str
    severity: Severity
    category: Category
    title: str
    evidence: Evidence
    reasoning: str
    score_contribution: int = 0
