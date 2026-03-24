import datetime

import pytest
from pydantic import ValidationError

from app.models.agent import ExecutionPlan, PlannedStep
from app.models.enums import FindingCategory, Severity, StepStatus
from app.models.finding import Evidence, Finding
from app.models.report import ReportMetadata, SecurityReport
from app.models.review import ReviewRequest
from app.models.tools import SafetyResult, SemgrepResult, ToolResult


@pytest.mark.unit
def test_review_request_invalid_raises_error():
    with pytest.raises(ValidationError) as exc_info:
        ReviewRequest()

    assert exc_info.value.errors()[0]["type"] == "value_error"


@pytest.mark.unit
def test_review_request_valid_with_repository_url():
    request = ReviewRequest(repository_url="https://test.url")
    assert request.repository_url == "https://test.url"


@pytest.mark.unit
def test_review_request_valid_with_code_snippet():
    request = ReviewRequest(code_snippet="print('Hello, world!')")
    assert request.code_snippet == "print('Hello, world!')"


@pytest.mark.unit
def test_finding_invalid_value():
    with pytest.raises(ValidationError) as exc_info:
        Finding(
            title="Test Finding",
            description="This is a test finding.",
            confidence=1.5,
            severity=Severity.high,
            category=FindingCategory.vulnerability,
            recommendation="This is a recommendation.",
            evidence=Evidence(
                tool_name="TestTool",
                raw_output="Raw output from tool",
                file_path="src/app.py",
                line_start=10,
                line_end=20,
            ),
        )

    assert exc_info.value.errors()[0]["type"] == "less_than_equal"


@pytest.mark.unit
def test_finding_valid():
    finding = Finding(
        title="Test Finding",
        description="This is a test finding.",
        confidence=0.5,
        severity=Severity.high,
        category=FindingCategory.vulnerability,
        evidence=Evidence(
            tool_name="TestTool",
            raw_output="Raw output from tool",
            file_path="src/app.py",
            line_start=10,
            line_end=20,
        ),
    )

    assert finding.confidence == 0.5


@pytest.mark.unit
def test_security_report_valid():
    report = SecurityReport(
        metadata=ReportMetadata(
            duration_seconds=120.0,
            tools_used=["ToolA", "ToolB"],
            timestamp=datetime.datetime.now(),
        ),
        request=ReviewRequest(repository_url="https://test.url"),
        score=85.0,
        findings=[
            Finding(
                title="Test Finding",
                description="This is a test finding.",
                confidence=0.5,
                severity=Severity.high,
                category=FindingCategory.vulnerability,
                evidence=Evidence(
                    tool_name="TestTool",
                    raw_output="Raw output from tool",
                    file_path="src/app.py",
                    line_start=10,
                    line_end=20,
                ),
            )
        ],
    )

    assert report.request.repository_url == "https://test.url"
    assert len(report.findings) == 1


@pytest.mark.unit
def test_security_report_invalid_score():
    with pytest.raises(ValidationError) as exc_info:
        SecurityReport(
            metadata=ReportMetadata(
                duration_seconds=120.0,
                tools_used=["ToolA", "ToolB"],
                timestamp=datetime.datetime.now(),
            ),
            request=ReviewRequest(repository_url="https://test.url"),
            score=150.0,  # Invalid score
        )

    assert exc_info.value.errors()[0]["type"] == "less_than_equal"


@pytest.mark.unit
def test_tool_parsed_results_empty():

    result = ToolResult(
        tool_name="TestTool",
        execution_time_seconds=0.0,
        raw_output="{}",
        success=True,
    )
    assert len(result.parsed_findings) == 0


@pytest.mark.unit
def test_execution_plan_multiple_planned_steps():

    plan = ExecutionPlan(
        rationale="Testing multiple findings in execution plan",
        steps=[
            PlannedStep(
                step_number=1,
                tool_name="ToolA",
                description="Run ToolA for analysis",
                status=StepStatus.planned,
                result=ToolResult(
                    tool_name="ToolA",
                    execution_time_seconds=30.0,
                    raw_output="{}",
                    success=True,
                ),
            ),
            PlannedStep(
                step_number=2,
                tool_name="ToolB",
                description="Run ToolB for analysis",
                status=StepStatus.planned,
                result=ToolResult(
                    tool_name="ToolB",
                    execution_time_seconds=45.0,
                    raw_output="{}",
                    success=True,
                ),
            ),
        ],
    )

    assert len(plan.steps) == 2


@pytest.mark.unit
def test_model_json_finding():
    finding = Finding(
        title="Test Finding",
        description="This is a test finding.",
        confidence=0.5,
        severity=Severity.high,
        category=FindingCategory.vulnerability,
        evidence=Evidence(
            tool_name="TestTool",
            raw_output="Raw output from tool",
            file_path="src/app.py",
            line_start=10,
            line_end=20,
        ),
    )

    json_data = finding.model_dump_json()

    new_finding = Finding.model_validate_json(json_data)
    assert new_finding.id is not None
    assert new_finding.title == finding.title
    assert new_finding.evidence.tool_name == finding.evidence.tool_name


@pytest.mark.unit
def test_semgrep_result_defaults():
    result = SemgrepResult(
        rules_matched=0,
        files_scanned=0,
        raw_output="",
        success=False,
        execution_time_seconds=0.0,
    )

    assert result.tool_name == "semgrep"


@pytest.mark.unit
def test_safety_result_valid():
    result = SafetyResult(
        raw_output="{}",
        success=True,
        execution_time_seconds=30.0,
    )

    assert result.tool_name == "safety"
