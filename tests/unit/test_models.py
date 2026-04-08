import datetime

import pytest
from pydantic import ValidationError

from app.models.agent import ExecutionPlan, PlannedStep
from app.models.enums import AnalysisStatus, FindingCategory, Severity, StepStatus
from app.models.finding import Evidence, Finding
from app.models.report import RecommendationGroup, ReportMetadata, SecurityReport
from app.models.review import ReviewRequest
from app.models.tools import PipAuditResult, SemgrepResult, ToolResult


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
def test_pip_audit_result_valid():
    result = PipAuditResult(
        raw_output="{}",
        success=True,
        execution_time_seconds=30.0,
    )

    assert result.tool_name == "pip-audit"


def make_review_request() -> ReviewRequest:
    return ReviewRequest(local_path="demo-packs/pack-a")


def make_finding() -> Finding:
    return Finding(
        title="SQL injection in search endpoint",
        description="User input is used in a SQL query.",
        severity=Severity.high,
        confidence=0.9,
        category=FindingCategory.vulnerability,
        evidence=Evidence(
            tool_name="semgrep",
            raw_output="raw output",
            file_path="demo-packs/pack-a/app.py",
            line_start=27,
            line_end=27,
            code_snippet="cursor.execute(query)",
        ),
        recommendation="Use parameterized queries.",
    )


def make_report_metadata() -> ReportMetadata:
    return ReportMetadata(
        duration_seconds=12.5,
        tools_used=["semgrep", "pip-audit"],
        token_count=100,
        cost_estimate=0.01,
        timestamp=datetime.datetime.now(datetime.UTC),
    )


def make_execution_plan() -> ExecutionPlan:
    return ExecutionPlan(
        steps=[],
        rationale="Tools selected based on capabilities.",
    )


@pytest.mark.unit
def test_recommendation_group_valid_input() -> None:
    group = RecommendationGroup(
        theme="Input Validation",
        finding_titles=[
            "SQL injection in search endpoint",
            "Command injection in ping endpoint",
        ],
        impact="These issues may allow attacker-controlled "
        "input to reach dangerous sinks.",
        remediation="Use parameterized queries and strict command allowlists.",
    )

    assert group.theme == "Input Validation"
    assert len(group.finding_titles) == 2
    assert group.impact.startswith("These issues")
    assert "parameterized queries" in group.remediation


@pytest.mark.unit
def test_recommendation_group_missing_required_fields() -> None:
    with pytest.raises(ValidationError):
        RecommendationGroup.model_validate(
            {
                "theme": "Input Validation",
                "finding_titles": ["SQL injection in search endpoint"],
                "impact": "Missing remediation field should fail.",
                # remediation intentionally omitted
            }
        )


@pytest.mark.unit
def test_security_report_with_recommendation_groups_serialization_round_trip() -> None:
    report = SecurityReport(
        request=make_review_request(),
        status=AnalysisStatus.completed,
        findings=[make_finding()],
        metadata=make_report_metadata(),
        execution_plan=make_execution_plan(),
        summary="Security analysis completed.",
        recommendation_groups=[
            RecommendationGroup(
                theme="Input Validation",
                finding_titles=["SQL injection in search endpoint"],
                impact="Improper input handling may lead to injection attacks.",
                remediation="Use parameterized queries and validate inputs.",
            ),
            RecommendationGroup(
                theme="Dependency Hygiene",
                finding_titles=["Vulnerability in requests 2.25.0"],
                impact="Known vulnerable packages increase exploitability risk.",
                remediation="Upgrade to a patched dependency version.",
            ),
        ],
        score=75.0,
    )

    payload = report.model_dump()
    round_tripped = SecurityReport.model_validate(payload)

    assert len(round_tripped.recommendation_groups) == 2
    assert round_tripped.recommendation_groups[0].theme == "Input Validation"
    assert round_tripped.recommendation_groups[1].theme == "Dependency Hygiene"
    assert round_tripped.summary == "Security analysis completed."
    assert round_tripped.score == 75.0


@pytest.mark.unit
def test_security_report_with_empty_recommendation_groups_default() -> None:
    report = SecurityReport(
        request=make_review_request(),
        status=AnalysisStatus.pending,
        findings=[],
        metadata=None,
        execution_plan=None,
        summary="",
        score=0.0,
    )

    assert report.recommendation_groups == []
