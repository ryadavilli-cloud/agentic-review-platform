import datetime
from pathlib import Path

from app.models import ExecutionPlan, PlannedStep, ReviewRequest
from app.models.enums import Severity, StepStatus
from app.models.finding import Finding
from app.models.report import ReportMetadata
from app.models.tools import ToolResult
from app.telemetry.helpers import create_span
from app.tools.base import BaseTool


def create_execution_plan(
    local_path: Path, tools: list[BaseTool], review_request: ReviewRequest
) -> ExecutionPlan:
    """Create an execution plan by iterating over provided tools."""
    with create_span("agent.create_execution_plan"):
        steps: list[PlannedStep] = []
        for i, tool in enumerate(tools, start=1):
            target_path: Path = (
                local_path / tool.target_file if tool.target_file else local_path
            )
            step = PlannedStep(
                step_number=i,
                tool_name=tool.tool_name,
                target_path=str(target_path),
                description=tool.description,
            )
            steps.append(step)

        return ExecutionPlan(
            steps=steps,
            rationale="Tools selected based on the review request "
            "and their capabilities.",
        )


async def execute_plan(
    execution_plan: ExecutionPlan,
    tools: list[BaseTool],
) -> ExecutionPlan:
    """Execute each planned step and attach tool results to the step.

    Each step moves through:
    planned -> running -> complete
    or
    planned -> running -> failed

    Tool failures are isolated to the individual step so the overall plan
    can still produce a partial result.
    """
    with create_span("agent.execute_plan"):
        tools_by_name: dict[str, BaseTool] = {tool.tool_name: tool for tool in tools}

        for step in execution_plan.steps:
            step.status = StepStatus.running

            tool = tools_by_name.get(step.tool_name)
            if tool is None:
                step.status = StepStatus.failed
                step.result = ToolResult(
                    tool_name=step.tool_name,
                    raw_output="",
                    success=False,
                    parsed_findings=[],
                    execution_time_seconds=0.0,
                    error=f"No tool found for step tool_name='{step.tool_name}'",
                )
                continue

            try:
                result = await tool.run(step.target_path or "")
                step.result = result
                step.status = StepStatus.completed

            except Exception as exc:
                elapsed = 0.0
                step.result = ToolResult(
                    tool_name=step.tool_name,
                    raw_output="",
                    success=False,
                    parsed_findings=[],
                    execution_time_seconds=elapsed,
                    error=str(exc),
                )
                step.status = StepStatus.failed

        return execution_plan


def assemble_findings(execution_plan: ExecutionPlan) -> list[Finding]:
    """Collect parsed findings from all successfully completed steps."""
    with create_span("agent.assemble_findings"):
        findings: list[Finding] = []

        for step in execution_plan.steps:
            if step.status == StepStatus.completed and step.result is not None:
                findings.extend(step.result.parsed_findings)

        return findings


def build_report_metadata(
    execution_plan: ExecutionPlan,
    duration_seconds: float,
) -> ReportMetadata:
    """Build report metadata from the completed execution plan."""
    with create_span("agent.build_report_metadata"):
        tools_used = [
            step.tool_name
            for step in execution_plan.steps
            if step.status == StepStatus.completed
        ]

        return ReportMetadata(
            duration_seconds=duration_seconds,
            tools_used=tools_used,
            token_count=0,
            cost_estimate=0.0,
            timestamp=datetime.datetime.now(datetime.UTC),
        )


SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.critical: 40.0,
    Severity.high: 20.0,
    Severity.medium: 10.0,
    Severity.low: 4.0,
    Severity.info: 1.0,
}


def compute_risk_score(findings: list[Finding]) -> float:
    """Compute a simple severity-weighted risk score capped at 100.

    Higher score means higher overall risk. The score saturates as findings
    accumulate and is deterministic for easy testing.
    """
    with create_span("agent.compute_risk_score"):
        total = 0.0

        for finding in findings:
            total += SEVERITY_WEIGHTS.get(finding.severity, 0.0)

        return min(total, 100.0)
