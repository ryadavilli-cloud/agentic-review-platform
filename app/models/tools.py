from pydantic import BaseModel

from app.models.finding import Finding


class ToolResult(BaseModel):
    tool_name: str
    raw_output: str
    success: bool
    parsed_findings: list[Finding] = []
    execution_time_seconds: float
    error: str | None = None


class SemgrepResult(ToolResult):
    tool_name: str = "semgrep"
    rules_matched: int
    files_scanned: int


class SafetyResult(ToolResult):
    tool_name: str = "safety"
    packages_scanned: int = 0
    vulnerabilities_found: int = 0
