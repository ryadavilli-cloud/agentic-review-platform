import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.types import TextContent

from app.models.enums import FindingCategory, Severity
from app.models.finding import Evidence, Finding
from app.models.tools import PipAuditResult
from app.tools.base import BaseTool
from app.tools.pip_audit_results import DependencyScanResult


class PipAuditTool(BaseTool):
    @property
    def tool_name(self) -> str:
        return "pip-audit"

    def transform_pip_audit_output(self, raw_output: str) -> PipAuditResult:

        pip_audit_results = DependencyScanResult.model_validate_json(raw_output)

        findings: list[Finding] = []

        for dep in pip_audit_results.dependencies:
            for vuln in dep.vulns:
                finding = Finding(
                    confidence=1.0,
                    category=FindingCategory.dependency,
                    severity=Severity.critical if "CVE" in vuln.id else Severity.high,
                    title=f"Vulnerability in {dep.name} {dep.version}",
                    description=vuln.description or "No description provided",
                    evidence=Evidence(
                        tool_name=self.tool_name,
                        raw_output=str(vuln.id),
                        file_path="requirements.txt",
                    ),
                )
                findings.append(finding)

        return PipAuditResult(
            tool_name=self.tool_name,
            raw_output=raw_output,
            success=True,
            parsed_findings=findings,
            execution_time_seconds=1.0,
            packages_scanned=len(pip_audit_results.dependencies),
            vulnerabilities_found=len(findings),
        )

    async def run(self, target_path: str) -> PipAuditResult:

        server_script = Path(__file__).resolve().parent / "pip_audit_server.py"

        server_params = StdioServerParameters(
            command=sys.executable,
            args=[str(server_script)],
        )
        print("Starting pip-audit server with stdio transport")
        async with stdio_client(server_params) as (read, write):  # noqa: SIM117
            async with ClientSession(read, write) as session:
                mcp_result = await session.call_tool(
                    "scan_requirements", arguments={"target_path": target_path}
                )

        content_block = mcp_result.content[0]
        if not isinstance(content_block, TextContent):
            raise ValueError("Expected text response from pip-audit server")
        content = content_block.text
        print("Calling transform result")

        result = self.transform_pip_audit_output(content)
        print(f"Transformed pip-audit output: {result}")
        return result


if __name__ == "__main__":
    pip_audit_tool = PipAuditTool()
    asyncio.run(pip_audit_tool.run("demo-packs/pack-a/requirements.txt"))
