import asyncio
import os
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

        try:
            env = {**os.environ, "PYTHONUTF8": "1"}

            timer_start = datetime.now()

            command = f"semgrep scan --json --config=auto {target_path}"

            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            stdout, stderr = await process.communicate()

            time_end = datetime.now()
            execution_time = time_end - timer_start

            if process.returncode is not None and process.returncode <= 1:
                self.common_logger(f"Semgrep Success: {stderr.decode()}")

                str_results = stdout.decode()

                # Transform the output and return it. For now, use simulated result.
                return self.transform_semgrep_output(
                    str_results, execution_time.total_seconds()
                )
            else:
                self.common_logger(
                    f"Semgrep Failed in {execution_time.total_seconds()} seconds"
                )

                return SemgrepResult(
                    tool_name=self.tool_name,
                    raw_output=stderr.decode(),
                    success=False,
                    parsed_findings=[],
                    execution_time_seconds=execution_time.total_seconds(),
                    rules_matched=0,
                    files_scanned=0,
                )

        except Exception as e:
            self.common_logger(f"Error occurred while running {self.tool_name}: {e}")
            raise

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
