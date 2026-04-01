from typing import Any
from pydantic import BaseModel


class ScanResult(BaseModel):
    model_config = {"arbitrary_types_allowed": True}

    scanner_name: str
    raw_output: str = ""
    parsed_data: Any = []
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.error is None
