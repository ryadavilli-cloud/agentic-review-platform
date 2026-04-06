from pathlib import Path

from app.models import ExecutionPlan, PlannedStep, ReviewRequest
from app.tools.base import BaseTool


def create_execution_plan(
    local_path: Path, tools: list[BaseTool], review_request: ReviewRequest
) -> ExecutionPlan:
    """Create an execution plan by iterating over provided tools."""
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
        rationale="Tools selected based on the review request and their capabilities.",
    )
