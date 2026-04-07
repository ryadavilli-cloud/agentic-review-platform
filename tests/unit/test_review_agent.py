import pytest
from openai import OpenAI

from app.agent.review_agent import ReviewAgent
from app.models import (
    AnalysisStatus,
    Evidence,
    Finding,
    FindingCategory,
    ReviewRequest,
    Severity,
    ToolResult,
)
from app.models.enums import StepStatus
from app.tools.base import BaseTool


class DummySuccessTool(BaseTool):
    def __init__(
        self,
        tool_name: str,
        findings: list[Finding],
        target_file: str | None = None,
    ) -> None:
        self._tool_name = tool_name
        self._findings = findings
        self._target_file = target_file

    async def run(self, target_path: str) -> ToolResult:
        return ToolResult(
            tool_name=self.tool_name,
            raw_output=f"{self.tool_name} raw output",
            success=True,
            parsed_findings=self._findings,
            execution_time_seconds=1.0,
            error=None,
        )

    @property
    def tool_name(self) -> str:
        return self._tool_name

    @property
    def description(self) -> str:
        return f"{self.tool_name} description"

    @property
    def target_file(self) -> str | None:
        return self._target_file


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
        return f"{self.tool_name} description"

    @property
    def target_file(self) -> str | None:
        return None


def make_finding(title: str, severity: Severity) -> Finding:
    return Finding(
        title=title,
        description=f"{title} description",
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
@pytest.mark.asyncio
async def test_review_agent_run_happy_path() -> None:
    findings_1 = [make_finding("Critical finding", Severity.critical)]
    findings_2 = [make_finding("High finding", Severity.high)]

    tools: list[BaseTool] = [
        DummySuccessTool("semgrep", findings_1),
        DummySuccessTool("pip-audit", findings_2, target_file="requirements.txt"),
    ]
    agent = ReviewAgent(tool_list=tools, llm_client=OpenAI(api_key="test"))

    request = ReviewRequest(local_path="\\tmp\\test-repo")

    report = await agent.run(request)

    assert report.status == AnalysisStatus.completed
    assert len(report.findings) == 2
    assert report.score > 0.0
    assert report.metadata is not None
    assert report.metadata.duration_seconds >= 0.0
    assert report.metadata.tools_used == ["semgrep", "pip-audit"]
    assert report.metadata.token_count == 0
    assert report.metadata.cost_estimate == 0.0
    assert report.metadata.timestamp is not None

    assert report.execution_plan is not None
    assert len(report.execution_plan.steps) == 2
    assert all(
        step.status == StepStatus.completed for step in report.execution_plan.steps
    )
    assert all(step.result is not None for step in report.execution_plan.steps)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_review_agent_run_missing_local_path() -> None:
    tools: list[BaseTool] = []
    agent = ReviewAgent(tool_list=tools, llm_client=OpenAI(api_key="test"))

    request = ReviewRequest(
        repository_url="https://github.com/example/repo",
        local_path=None,
    )

    with pytest.raises(
        ValueError,
        match="ReviewRequest.local_path is required to run the review",
    ):
        await agent.run(request)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_review_agent_run_one_tool_fails() -> None:
    successful_findings = [make_finding("Critical finding", Severity.critical)]

    tools: list[BaseTool] = [
        DummyFailTool("semgrep", "semgrep crashed"),
        DummySuccessTool(
            "pip-audit", successful_findings, target_file="requirements.txt"
        ),
    ]
    agent = ReviewAgent(tool_list=tools, llm_client=OpenAI(api_key="test"))

    request = ReviewRequest(local_path="\\tmp\\test-repo")

    report = await agent.run(request)

    assert report.status == AnalysisStatus.completed
    assert len(report.findings) == 1
    assert report.findings[0].title == "Critical finding"
    assert report.score == 40.0

    assert report.metadata is not None
    assert report.metadata.tools_used == ["pip-audit"]

    assert report.execution_plan is not None
    assert len(report.execution_plan.steps) == 2

    failed_step = report.execution_plan.steps[0]
    succeeded_step = report.execution_plan.steps[1]

    assert failed_step.status == StepStatus.failed
    assert failed_step.result is not None
    assert failed_step.result.success is False
    assert failed_step.result.error == "semgrep crashed"

    assert succeeded_step.status == StepStatus.completed
    assert succeeded_step.result is not None
    assert succeeded_step.result.success is True


@pytest.mark.unit
@pytest.mark.asyncio
async def test_review_agent_run_no_findings() -> None:
    tools: list[BaseTool] = [
        DummySuccessTool("semgrep", []),
        DummySuccessTool("pip-audit", [], target_file="requirements.txt"),
    ]
    agent = ReviewAgent(tool_list=tools, llm_client=OpenAI(api_key="test"))

    request = ReviewRequest(local_path="\\tmp\\test-repo")

    report = await agent.run(request)

    assert report.status == AnalysisStatus.completed
    assert report.findings == []
    assert report.score == 0.0

    assert report.metadata is not None
    assert report.metadata.tools_used == ["semgrep", "pip-audit"]

    assert report.execution_plan is not None
    assert all(
        step.status == StepStatus.completed for step in report.execution_plan.steps
    )
    assert all(step.result is not None for step in report.execution_plan.steps)
