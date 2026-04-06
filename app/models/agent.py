from pydantic import BaseModel

from app.models.enums import StepStatus
from app.models.tools import ToolResult


class PlannedStep(BaseModel):
    step_number: int
    tool_name: str
    description: str
    status: StepStatus = StepStatus.planned
    result: ToolResult | None = None
    target_path: str | None = None


class ExecutionPlan(BaseModel):
    steps: list[PlannedStep] = []
    rationale: str
