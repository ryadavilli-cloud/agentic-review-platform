import uuid

from pydantic import BaseModel, Field

from app.models.enums import FindingCategory, Severity


class Evidence(BaseModel):
    tool_name: str
    raw_output: str
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    code_snippet: str | None = None


class Finding(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    title: str
    description: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    category: FindingCategory
    evidence: Evidence
    recommendation: str | None = None
