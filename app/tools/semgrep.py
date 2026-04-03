from datetime import datetime

from app.models.enums import FindingCategory, Severity
from app.models.finding import Evidence, Finding
from app.models.tools import SemgrepResult
from app.tools.base import BaseTool
from app.tools.semgrep_results import SemgrepToolResults


class SemgrepTool(BaseTool):
    @property
    def tool_name(self) -> str:
        return "Semgrep"

    async def run(self, target_path: str) -> SemgrepResult:
        self.common_logger(f"Running {self.tool_name} on {target_path}")
        # In a real implementation, run the semgrep command and get the output
        # catpure the raw output and time, then call transform_semgrep_output to parse.
        timer_start = datetime.now()
        time_end = datetime.now()
        execution_time = time_end - timer_start

        str_results = ""

        # Transform the output and return it. For now, use simulated result.
        return self.transform_semgrep_output(
            str_results, execution_time.total_seconds()
        )

    def transform_semgrep_output(
        self, raw_output: str, execution_time: float
    ) -> SemgrepResult:
        # Transform raw output into SemgrepToolResult,
        # then convert SemgrepToolResult to SemgrepResult

        semgrep_tool_results = SemgrepToolResults.model_validate_json(raw_output)

        findings: list[Finding] = []

        for result in semgrep_tool_results.results:
            finding = Finding(
                title=result.extra.message,
                description=f"Semgrep rule {result.check_id} matched in {result.path}",
                severity=self.map_severity_to_severity(result.extra.severity),
                confidence=0.8,  # Placeholder confidence
                category=FindingCategory.code_quality,
                evidence=Evidence(
                    tool_name=self.tool_name,
                    raw_output=str(result),
                    file_path=result.path,
                    line_start=result.start.line,
                    line_end=result.end.line,
                    code_snippet=result.extra.lines,
                ),
                recommendation="Review the matched code and apply necessary fixes.",
            )
            findings.append(finding)

        semgrep_result = SemgrepResult(
            tool_name=self.tool_name,
            raw_output=raw_output,
            success=len(semgrep_tool_results.errors) == 0,
            parsed_findings=findings,
            execution_time_seconds=execution_time,
            rules_matched=len(semgrep_tool_results.results),
            files_scanned=len(semgrep_tool_results.paths.get("scanned", [])),
        )
        return semgrep_result

    def map_severity_to_severity(self, severity: str) -> Severity:
        severity_mapping = {
            "error": Severity.high,
            "warning": Severity.medium,
            "info": Severity.low,
        }
        return severity_mapping.get(severity.lower(), Severity.low)
