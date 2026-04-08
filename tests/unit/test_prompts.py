import pytest

# Replace this import with the actual module path for the attached file.
from app.agent.prompts import (
    SYNTHESIS_SYSTEM_PROMPT,
    build_user_prompt,
    serialize_findings_for_llm,
)
from app.models.agent import ExecutionPlan, PlannedStep
from app.models.enums import FindingCategory, Severity, StepStatus
from app.models.finding import Evidence, Finding
from app.models.review import ReviewRequest


def make_finding(
    *,
    title: str = "SQL injection in search endpoint",
    severity: Severity = Severity.high,
    category: FindingCategory = FindingCategory.vulnerability,
    tool_name: str = "semgrep",
    file_path: str | None = "demo-packs/pack-a/app.py",
    code_snippet: str | None = "cursor.execute(query)",
    line_start: int | None = 27,
    line_end: int | None = 27,
) -> Finding:
    return Finding(
        title=title,
        description=f"{title} description",
        severity=severity,
        confidence=0.9,
        category=category,
        evidence=Evidence(
            tool_name=tool_name,
            raw_output="raw-tool-output",
            file_path=file_path,
            code_snippet=code_snippet,
            line_start=line_start,
            line_end=line_end,
        ),
        recommendation="Fix it",
    )


def make_request(
    *,
    local_path: str | None = "demo-packs/pack-a",
    repository_url: str | None = None,
    code_snippet: str | None = None,
) -> ReviewRequest:
    return ReviewRequest(
        local_path=local_path,
        repository_url=repository_url,
        code_snippet=code_snippet,
    )


def make_execution_plan(*steps: PlannedStep) -> ExecutionPlan:
    return ExecutionPlan(
        steps=list(steps),
        rationale="Tools selected for test execution",
    )


def make_step(
    *,
    step_number: int,
    tool_name: str,
    status: StepStatus = StepStatus.completed,
) -> PlannedStep:
    return PlannedStep(
        step_number=step_number,
        tool_name=tool_name,
        description=f"Run {tool_name}",
        status=status,
        target_path="demo-packs/pack-a",
    )


# -------------------------------------------------------------------
# System prompt tests
# -------------------------------------------------------------------


@pytest.mark.unit
def test_synthesis_system_prompt_is_non_empty_string() -> None:
    assert isinstance(SYNTHESIS_SYSTEM_PROMPT, str)
    assert SYNTHESIS_SYSTEM_PROMPT.strip() != ""


@pytest.mark.unit
def test_synthesis_system_prompt_contains_expected_key_phrases() -> None:
    prompt = SYNTHESIS_SYSTEM_PROMPT

    assert "JSON" in prompt
    assert "summary" in prompt
    assert "recommendation_groups" in prompt
    assert "raw JSON only" in prompt


# -------------------------------------------------------------------
# serialize_findings_for_llm tests
# -------------------------------------------------------------------


@pytest.mark.unit
def test_serialize_findings_for_llm_multiple_findings() -> None:
    findings = [
        make_finding(
            title="SQL injection in search endpoint",
            severity=Severity.critical,
            category=FindingCategory.vulnerability,
            tool_name="semgrep",
        ),
        make_finding(
            title="Vulnerability in requests 2.25.0",
            severity=Severity.high,
            category=FindingCategory.dependency,
            tool_name="pip-audit",
            file_path="requirements.txt",
            code_snippet=None,
            line_start=None,
            line_end=None,
        ),
    ]

    output = serialize_findings_for_llm(findings)

    assert "SQL injection in search endpoint" in output
    assert "critical" in output
    assert "vulnerability" in output
    assert "Tool: semgrep" in output

    assert "Vulnerability in requests 2.25.0" in output
    assert "high" in output
    assert "dependency" in output
    assert "Tool: pip-audit" in output


@pytest.mark.unit
def test_serialize_findings_for_llm_zero_findings() -> None:
    output = serialize_findings_for_llm([])

    assert output == "No findings were detected by the automated tools."


@pytest.mark.unit
def test_serialize_findings_for_llm_all_optional_fields_present() -> None:
    findings = [
        make_finding(
            file_path="demo-packs/pack-a/app.py",
            code_snippet="cursor.execute(query)",
            line_start=27,
            line_end=29,
        )
    ]

    output = serialize_findings_for_llm(findings)

    assert "File: demo-packs/pack-a/app.py" in output
    assert "Code Snippet: cursor.execute(query)" in output
    assert "Lines: 27 - 29" in output


@pytest.mark.unit
def test_serialize_findings_for_llm_no_optional_fields() -> None:
    findings = [
        make_finding(
            file_path=None,
            code_snippet=None,
            line_start=None,
            line_end=None,
        )
    ]

    output = serialize_findings_for_llm(findings)

    assert "Title: SQL injection in search endpoint" in output
    assert "Severity:" in output
    assert "Category:" in output

    assert "File:" not in output
    assert "Code Snippet:" not in output
    assert "Line:" not in output
    assert "Lines:" not in output


@pytest.mark.unit
def test_serialize_findings_for_llm_line_format_same_start_and_end() -> None:
    findings = [
        make_finding(
            file_path="demo-packs/pack-a/app.py",
            line_start=27,
            line_end=27,
        )
    ]

    output = serialize_findings_for_llm(findings)

    assert "File: demo-packs/pack-a/app.py, Line: 27" in output


@pytest.mark.unit
def test_serialize_findings_for_llm_line_format_different_start_and_end() -> None:
    findings = [
        make_finding(
            file_path="demo-packs/pack-a/app.py",
            line_start=27,
            line_end=29,
        )
    ]

    output = serialize_findings_for_llm(findings)

    assert "File: demo-packs/pack-a/app.py, Lines: 27 - 29" in output


@pytest.mark.unit
def test_serialize_findings_for_llm_line_format_only_start_present() -> None:
    findings = [
        make_finding(
            file_path="demo-packs/pack-a/app.py",
            line_start=27,
            line_end=None,
        )
    ]

    output = serialize_findings_for_llm(findings)

    assert "File: demo-packs/pack-a/app.py, Line: 27" in output


# -------------------------------------------------------------------
# build_user_prompt tests
# -------------------------------------------------------------------


@pytest.mark.unit
def test_build_user_prompt_happy_path() -> None:
    findings = [
        make_finding(
            title="SQL injection in search endpoint",
            tool_name="semgrep",
        ),
        make_finding(
            title="Vulnerability in urllib3",
            severity=Severity.high,
            category=FindingCategory.dependency,
            tool_name="pip-audit",
            file_path="requirements.txt",
            code_snippet=None,
            line_start=None,
            line_end=None,
        ),
    ]

    request = make_request(local_path="demo-packs/pack-a")

    execution_plan = make_execution_plan(
        make_step(step_number=1, tool_name="semgrep", status=StepStatus.completed),
        make_step(step_number=2, tool_name="pip-audit", status=StepStatus.completed),
    )

    output = build_user_prompt(findings, request, execution_plan)

    assert "Review Context:" in output
    assert "Local Path: demo-packs/pack-a" in output
    assert "Step: 1 : semgrep" in output
    assert "Step: 2 : pip-audit" in output
    assert "Findings count : 2" in output

    # Serialized findings block content
    assert "Title: SQL injection in search endpoint" in output
    assert "Tool: semgrep" in output
    assert "Title: Vulnerability in urllib3" in output
    assert "Tool: pip-audit" in output


@pytest.mark.unit
def test_build_user_prompt_repository_url() -> None:
    findings = [make_finding()]
    request = make_request(
        local_path=None,
        repository_url="https://github.com/example/repo",
    )
    execution_plan = make_execution_plan(
        make_step(step_number=1, tool_name="semgrep", status=StepStatus.completed),
    )

    output = build_user_prompt(findings, request, execution_plan)

    assert "Repository URL: https://github.com/example/repo" in output
    assert "Local Path:" not in output


@pytest.mark.unit
def test_build_user_prompt_code_snippet_fallback() -> None:
    findings = [make_finding()]
    request = make_request(
        local_path=None,
        repository_url=None,
        code_snippet="print('hello')",
    )
    execution_plan = make_execution_plan(
        make_step(step_number=1, tool_name="semgrep", status=StepStatus.completed),
    )

    output = build_user_prompt(findings, request, execution_plan)

    assert "Code Snippet Review" in output
    assert "Local Path:" not in output
    assert "Repository URL:" not in output
    assert "Repository Url:" not in output


@pytest.mark.unit
def test_build_user_prompt_failed_step_status_appears() -> None:
    findings = [make_finding()]
    request = make_request(local_path="demo-packs/pack-a")
    execution_plan = make_execution_plan(
        make_step(step_number=1, tool_name="semgrep", status=StepStatus.failed),
        make_step(step_number=2, tool_name="pip-audit", status=StepStatus.completed),
    )

    output = build_user_prompt(findings, request, execution_plan)

    assert f"Status: {StepStatus.failed.name}" in output
    assert f"Status: {StepStatus.completed.name}" in output


@pytest.mark.unit
def test_build_user_prompt_zero_findings() -> None:
    findings: list[Finding] = []
    request = make_request(local_path="demo-packs/pack-a")
    execution_plan = make_execution_plan(
        make_step(step_number=1, tool_name="semgrep", status=StepStatus.completed),
    )

    output = build_user_prompt(findings, request, execution_plan)

    assert "Findings count : 0" in output
    assert "No findings were detected by the automated tools." in output
