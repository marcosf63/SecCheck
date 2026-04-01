import json
from app.models.report import Report


def to_json(report: Report, indent: int = 2) -> str:
    return report.model_dump_json(indent=indent)


def save_json(report: Report, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(to_json(report))
