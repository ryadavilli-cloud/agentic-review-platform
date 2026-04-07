import datetime
from pathlib import Path

import pytest

from app.agent.orchestrator import (
    assemble_findings,
    build_report_metadata,
    compute_risk_score,
    create_execution_plan,
    execute_plan,
)
from app.models.agent import ExecutionPlan, PlannedStep
from app.models.enums import FindingCategory, Severity, StepStatus
from app.models.finding import Evidence, Finding
from app.models.review import ReviewRequest
from app.models.tools import ToolResult
from app.tools.base import BaseTool
from app.tools.pip_audit import PipAuditTool
from app.tools.semgrep import SemgrepTool


@pytest.mark.unit
def test_create_execution_plan_valid():
    result = create_execution_plan(
        local_path=Path("\\fake\\path"),
        tools=[SemgrepTool(), PipAuditTool()],
        review_request=ReviewRequest(
            local_path="\\fake\\path",
        ),
    )

    assert len(result.steps) == 2
    assert result.steps[0].tool_name == "semgrep"
    assert result.steps[0].target_path == "\\fake\\path"
    assert result.steps[0].step_number == 1
    assert result.steps[0].status == StepStatus.planned
    assert result.steps[0].result is None
    assert result.steps[1].tool_name == "pip-audit"
    assert result.steps[1].target_path == "\\fake\\path\\requirements.txt"
    assert result.steps[1].step_number == 2
    assert result.steps[1].status == StepStatus.planned
    assert result.steps[1].result is None


@pytest.mark.unit
def test_create_execution_plan_no_tools():
    result = create_execution_plan(
        local_path=Path("\\fake\\path"),
        tools=[],
        review_request=ReviewRequest(
            local_path="\\fake\\path",
        ),
    )

    assert len(result.steps) == 0


@pytest.mark.unit
def test_create_execution_plan_tool_with_no_target_file():

    result = create_execution_plan(
        local_path=Path("\\fake\\path"),
        tools=[SemgrepTool()],
        review_request=ReviewRequest(
            local_path="\\fake\\path",
        ),
    )

    assert len(result.steps) == 1
    assert result.steps[0].tool_name == "semgrep"
    assert result.steps[0].target_path == "\\fake\\path"
    assert result.steps[0].step_number == 1


## Execute Plan test below


class DummySuccessTool(BaseTool):
    def __init__(self, tool_name: str, result: ToolResult) -> None:
        self._tool_name = tool_name
        self._result = result

    async def run(self, target_path: str) -> ToolResult:
        return self._result

    @property
    def tool_name(self) -> str:
        return self._tool_name

    @property
    def description(self) -> str:
        return f"{self._tool_name} description"

    @property
    def target_file(self) -> str | None:
        return None


class DummyFailTool(BaseTool):
    def __init__(self, tool_name: str, error_message: str) -> None:
        self._tool_name = tool_name
        self._error_message = error_message

    async def run(self, target_path: str) -> ToolResult:
        raise RuntimeError(self._error_message)

    @property
    def tool_name(self) -> str:
        return self._tool_name

    @property
    def description(self) -> str:
        return f"{self._tool_name} description"

    @property
    def target_file(self) -> str | None:
        return None


def make_tool_result(tool_name: str) -> ToolResult:
    return ToolResult(
        tool_name=tool_name,
        raw_output=f"{tool_name} raw output",
        success=True,
        parsed_findings=[],
        execution_time_seconds=1.23,
        error=None,
    )


@pytest.mark.unit
@pytest.mark.asyncio
async def test_execute_plan_all_succeed() -> None:
    semgrep_result = make_tool_result("semgrep")
    pip_audit_result = make_tool_result("pip-audit")

    plan = ExecutionPlan(
        steps=[
            PlannedStep(
                step_number=1,
                tool_name="semgrep",
                description="Run semgrep",
                target_path="repo/",
            ),
            PlannedStep(
                step_number=2,
                tool_name="pip-audit",
                description="Run pip-audit",
                target_path="repo/requirements.txt",
            ),
        ],
        rationale="Test plan",
    )

    tools: list[BaseTool] = [
        DummySuccessTool("semgrep", semgrep_result),
        DummySuccessTool("pip-audit", pip_audit_result),
    ]

    completed_plan = await execute_plan(plan, tools)

    assert len(completed_plan.steps) == 2

    assert completed_plan.steps[0].status == StepStatus.completed
    assert completed_plan.steps[0].result == semgrep_result

    assert completed_plan.steps[1].status == StepStatus.completed
    assert completed_plan.steps[1].result == pip_audit_result


@pytest.mark.unit
@pytest.mark.asyncio
async def test_execute_plan_one_fails_with_exception() -> None:
    semgrep_error = "semgrep crashed"
    pip_audit_result = make_tool_result("pip-audit")

    plan = ExecutionPlan(
        steps=[
            PlannedStep(
                step_number=1,
                tool_name="semgrep",
                description="Run semgrep",
                target_path="repo/",
            ),
            PlannedStep(
                step_number=2,
                tool_name="pip-audit",
                description="Run pip-audit",
                target_path="repo/requirements.txt",
            ),
        ],
        rationale="Test plan",
    )

    tools: list[BaseTool] = [
        DummyFailTool("semgrep", semgrep_error),
        DummySuccessTool("pip-audit", pip_audit_result),
    ]

    completed_plan = await execute_plan(plan, tools)

    failed_step = completed_plan.steps[0]
    succeeded_step = completed_plan.steps[1]

    assert failed_step.status == StepStatus.failed
    assert failed_step.result is not None
    assert failed_step.result.success is False
    assert failed_step.result.error == semgrep_error

    assert succeeded_step.status == StepStatus.completed
    assert succeeded_step.result == pip_audit_result


@pytest.mark.unit
@pytest.mark.asyncio
async def test_execute_plan_missing_tool_name() -> None:
    plan = ExecutionPlan(
        steps=[
            PlannedStep(
                step_number=1,
                tool_name="nonexistent",
                description="Run missing tool",
                target_path="repo/",
            )
        ],
        rationale="Test plan",
    )

    tools: list[BaseTool] = []

    completed_plan = await execute_plan(plan, tools)

    step = completed_plan.steps[0]

    assert step.status == StepStatus.failed
    assert step.result is not None
    assert step.result.success is False
    assert step.result.error == "No tool found for step tool_name='nonexistent'"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_execute_plan_all_fail() -> None:
    plan = ExecutionPlan(
        steps=[
            PlannedStep(
                step_number=1,
                tool_name="semgrep",
                description="Run semgrep",
                target_path="repo/",
            ),
            PlannedStep(
                step_number=2,
                tool_name="pip-audit",
                description="Run pip-audit",
                target_path="repo/requirements.txt",
            ),
        ],
        rationale="Test plan",
    )

    tools: list[BaseTool] = [
        DummyFailTool("semgrep", "semgrep failed"),
        DummyFailTool("pip-audit", "pip-audit failed"),
    ]

    completed_plan = await execute_plan(plan, tools)

    assert len(completed_plan.steps) == 2
    assert completed_plan.steps[0].status == StepStatus.failed
    assert completed_plan.steps[1].status == StepStatus.failed

    assert completed_plan.steps[0].result is not None
    assert completed_plan.steps[1].result is not None


@pytest.mark.unit
@pytest.mark.asyncio
async def test_execute_plan_failure_result_fields() -> None:
    plan = ExecutionPlan(
        steps=[
            PlannedStep(
                step_number=1,
                tool_name="semgrep",
                description="Run semgrep",
                target_path="repo/",
            )
        ],
        rationale="Test plan",
    )

    tools: list[BaseTool] = [
        DummyFailTool("semgrep", "boom"),
    ]

    completed_plan = await execute_plan(plan, tools)

    step = completed_plan.steps[0]

    assert step.status == StepStatus.failed
    assert step.result is not None
    assert step.result.success is False
    assert step.result.parsed_findings == []
    assert step.result.execution_time_seconds == 0.0
    assert step.result.error is not None
    assert step.result.error != ""


# assemble_findings tests below


def make_finding(finding_id: str) -> Finding:
    return Finding(
        confidence=0.9,
        title="Finding 1",
        description="Test finding",
        severity=Severity.high,
        category=FindingCategory.vulnerability,
        recommendation="Fix it",
        evidence=Evidence(
            tool_name="test-tool",
            file_path="test.py",
            line_start=1,
            line_end=1,
            raw_output="raw output",
        ),
    )


def make_result(tool_name: str, findings: list[Finding]) -> ToolResult:
    return ToolResult(
        tool_name=tool_name,
        raw_output="raw output",
        success=True,
        parsed_findings=findings,
        execution_time_seconds=1.0,
        error=None,
    )


@pytest.mark.unit
def test_assemble_findings_all_completed() -> None:
    findings_step_1 = [make_finding("f1"), make_finding("f2")]
    findings_step_2 = [make_finding("f3"), make_finding("f4"), make_finding("f5")]

    execution_plan = ExecutionPlan(
        steps=[
            PlannedStep(
                step_number=1,
                tool_name="semgrep",
                description="Run semgrep",
                status=StepStatus.completed,
                result=make_result("semgrep", findings_step_1),
                target_path="repo/",
            ),
            PlannedStep(
                step_number=2,
                tool_name="pip-audit",
                description="Run pip-audit",
                status=StepStatus.completed,
                result=make_result("pip-audit", findings_step_2),
                target_path="repo/requirements.txt",
            ),
        ],
        rationale="Test plan",
    )

    findings = assemble_findings(execution_plan)

    assert len(findings) == 5
    assert findings == findings_step_1 + findings_step_2


@pytest.mark.unit
def test_assemble_findings_mixed_completed_and_failed() -> None:
    completed_findings = [make_finding("f1"), make_finding("f2")]
    failed_findings = [make_finding("f3"), make_finding("f4")]

    execution_plan = ExecutionPlan(
        steps=[
            PlannedStep(
                step_number=1,
                tool_name="semgrep",
                description="Run semgrep",
                status=StepStatus.completed,
                result=make_result("semgrep", completed_findings),
                target_path="repo/",
            ),
            PlannedStep(
                step_number=2,
                tool_name="pip-audit",
                description="Run pip-audit",
                status=StepStatus.failed,
                result=make_result("pip-audit", failed_findings),
                target_path="repo/requirements.txt",
            ),
        ],
        rationale="Test plan",
    )

    findings = assemble_findings(execution_plan)

    assert len(findings) == 2
    assert findings == completed_findings


@pytest.mark.unit
def test_assemble_findings_no_completed_steps() -> None:
    execution_plan = ExecutionPlan(
        steps=[
            PlannedStep(
                step_number=1,
                tool_name="semgrep",
                description="Run semgrep",
                status=StepStatus.failed,
                result=make_result("semgrep", [make_finding("f1")]),
                target_path="repo/",
            ),
            PlannedStep(
                step_number=2,
                tool_name="pip-audit",
                description="Run pip-audit",
                status=StepStatus.failed,
                result=make_result("pip-audit", [make_finding("f2")]),
                target_path="repo/requirements.txt",
            ),
        ],
        rationale="Test plan",
    )

    findings = assemble_findings(execution_plan)

    assert findings == []


@pytest.mark.unit
def test_assemble_findings_completed_with_empty_findings() -> None:
    execution_plan = ExecutionPlan(
        steps=[
            PlannedStep(
                step_number=1,
                tool_name="semgrep",
                description="Run semgrep",
                status=StepStatus.completed,
                result=make_result("semgrep", []),
                target_path="repo/",
            )
        ],
        rationale="Test plan",
    )

    findings = assemble_findings(execution_plan)

    assert findings == []


# build report metadata tests below


@pytest.mark.unit
def test_build_report_metadata_normal_case() -> None:
    execution_plan = ExecutionPlan(
        steps=[
            PlannedStep(
                step_number=1,
                tool_name="semgrep",
                description="Run semgrep",
                status=StepStatus.completed,
                target_path="repo/",
            ),
            PlannedStep(
                step_number=2,
                tool_name="pip-audit",
                description="Run pip-audit",
                status=StepStatus.completed,
                target_path="repo/requirements.txt",
            ),
        ],
        rationale="Test plan",
    )

    metadata = build_report_metadata(
        execution_plan=execution_plan,
        duration_seconds=12.34,
    )

    assert metadata.duration_seconds == 12.34
    assert metadata.tools_used == ["semgrep", "pip-audit"]
    assert metadata.token_count == 0
    assert metadata.cost_estimate == 0.0
    assert metadata.timestamp is not None
    assert isinstance(metadata.timestamp, datetime.datetime)


@pytest.mark.unit
def test_build_report_metadata_mixed_statuses() -> None:
    execution_plan = ExecutionPlan(
        steps=[
            PlannedStep(
                step_number=1,
                tool_name="semgrep",
                description="Run semgrep",
                status=StepStatus.completed,
                target_path="repo/",
            ),
            PlannedStep(
                step_number=2,
                tool_name="pip-audit",
                description="Run pip-audit",
                status=StepStatus.failed,
                target_path="repo/requirements.txt",
            ),
        ],
        rationale="Test plan",
    )

    metadata = build_report_metadata(
        execution_plan=execution_plan,
        duration_seconds=5.0,
    )

    assert metadata.duration_seconds == 5.0
    assert metadata.tools_used == ["semgrep"]
    assert metadata.token_count == 0
    assert metadata.cost_estimate == 0.0
    assert metadata.timestamp is not None


@pytest.mark.unit
def test_build_report_metadata_no_completed_steps() -> None:
    execution_plan = ExecutionPlan(
        steps=[
            PlannedStep(
                step_number=1,
                tool_name="semgrep",
                description="Run semgrep",
                status=StepStatus.failed,
                target_path="repo/",
            ),
            PlannedStep(
                step_number=2,
                tool_name="pip-audit",
                description="Run pip-audit",
                status=StepStatus.failed,
                target_path="repo/requirements.txt",
            ),
        ],
        rationale="Test plan",
    )

    metadata = build_report_metadata(
        execution_plan=execution_plan,
        duration_seconds=3.21,
    )

    assert metadata.duration_seconds == 3.21
    assert metadata.tools_used == []
    assert metadata.token_count == 0
    assert metadata.cost_estimate == 0.0
    assert metadata.timestamp is not None


# Compute risk score tests below
def make_finding_for_score(severity: Severity) -> Finding:
    return Finding(
        title="Test finding",
        description="Test finding description",
        severity=severity,
        confidence=0.9,
        category=FindingCategory.vulnerability,
        evidence=Evidence(
            tool_name="test-tool",
            raw_output="raw output",
            file_path="test.py",
            line_start=1,
            line_end=1,
            code_snippet="dangerous_code()",
        ),
        recommendation="Fix it",
    )


@pytest.mark.unit
def test_compute_risk_score_empty_findings() -> None:
    assert compute_risk_score([]) == 0.0


@pytest.mark.unit
def test_compute_risk_score_single_critical() -> None:
    findings = [make_finding_for_score(Severity.critical)]

    assert compute_risk_score(findings) == 40.0


@pytest.mark.unit
def test_compute_risk_score_single_info() -> None:
    findings = [make_finding_for_score(Severity.info)]

    assert compute_risk_score(findings) == 1.0


@pytest.mark.unit
def test_compute_risk_score_mixed_severities() -> None:
    findings = [
        make_finding_for_score(Severity.critical),
        make_finding_for_score(Severity.high),
        make_finding_for_score(Severity.medium),
    ]

    assert compute_risk_score(findings) == 70.0


@pytest.mark.unit
def test_compute_risk_score_saturates_at_100() -> None:
    findings = [
        make_finding_for_score(Severity.critical),
        make_finding_for_score(Severity.critical),
        make_finding_for_score(Severity.critical),
    ]

    assert compute_risk_score(findings) == 100.0


@pytest.mark.unit
def test_compute_risk_score_all_severity_levels() -> None:
    findings = [
        make_finding_for_score(Severity.critical),
        make_finding_for_score(Severity.high),
        make_finding_for_score(Severity.medium),
        make_finding_for_score(Severity.low),
        make_finding_for_score(Severity.info),
    ]

    assert compute_risk_score(findings) == 75.0
