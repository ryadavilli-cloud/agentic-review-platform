from typing import Any

from pydantic import BaseModel, field_validator


class Metadata(BaseModel):
    category: str
    confidence: str
    cwe: list[str] | None = None
    owasp: list[str] | None = None
    impact: str | None = None
    likelihood: str | None = None
    references: list[str] | None = None
    vulnerability_class: list[str] | None = None
    subcategory: list[str] | None = None
    source: str | None = None

    @field_validator("owasp", mode="before")
    @classmethod
    def normalize_owasp(cls, v: Any) -> Any:
        # If it's a single string, wrap it in a list
        if isinstance(v, str):
            return [v]
        # If it's already a list or None, return as is
        return v


class Extra(BaseModel):
    message: str
    severity: str
    metadata: Metadata
    lines: str | None = None


class Position(BaseModel):
    line: int
    col: int
    offset: int


class Result(BaseModel):
    check_id: str
    path: str
    start: Position
    end: Position
    extra: Extra


class SemgrepToolResults(BaseModel):
    results: list[Result]
    errors: list[str]
    paths: dict[str, list[str]]
    version: str
