from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, cast

import pytest

from app.agent.review_agent import ReviewAgent
from app.config import Settings
from app.models.enums import AnalysisStatus, ReviewType, StepStatus
from app.models.finding import Finding
from app.models.review import ReviewRequest
from app.scoring.matcher import score_findings
from app.scoring.models import ExpectedFindings

# Adjust these two imports if the module filenames differ.
from app.tools.pip_audit import PipAuditTool
from app.tools.pip_audit_results import DependencyScanResult
from app.tools.semgrep import SemgrepTool

pytestmark = [pytest.mark.scenario]


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _pack_a_path() -> Path:
    pack_path = _project_root() / "demo-packs" / "pack-a"
    assert pack_path.exists(), f"Demo pack path does not exist: {pack_path}"
    return pack_path


def _manifest_path() -> Path:
    manifest_path = _pack_a_path() / "expected_findings.json"
    assert manifest_path.exists(), f"Manifest file does not exist: {manifest_path}"
    return manifest_path


def _read_expected_findings() -> ExpectedFindings:
    return ExpectedFindings.model_validate_json(
        _manifest_path().read_text(encoding="utf-8")
    )


def _has_required_binaries() -> bool:
    return shutil.which("semgrep") is not None


class _FakeUsage:
    def __init__(self, prompt_tokens: int = 1200, completion_tokens: int = 250) -> None:
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens


class _FakeMessage:
    def __init__(self, content: str) -> None:
        self.content = content


class _FakeChoice:
    def __init__(self, content: str) -> None:
        self.message = _FakeMessage(content)


class _FakeResponse:
    def __init__(self, content: str) -> None:
        self.choices = [_FakeChoice(content)]
        self.usage = _FakeUsage()


class _FakeCompletions:
    def create(self, **_: object) -> _FakeResponse:
        payload: dict[str, object] = {
            "summary": (
                "Automated analysis found code and dependency issues across "
                "the demo pack. "
                "Priority should be given to vulnerable dependencies and "
                "insecure code patterns."
            ),
            "recommendation_groups": [
                {
                    "theme": "Dependency remediation",
                    "finding_titles": [
                        "Vulnerability in werkzeug 2.0.0",
                        "Vulnerability in flask 1.0.2",
                    ],
                    "impact": "Known vulnerable packages increase exploitability risk.",
                    "remediation": "Upgrade vulnerable dependencies to fixed versions.",
                },
                {
                    "theme": "Code hardening",
                    "finding_titles": [
                        "Potential hardcoded secret",
                        "Unsafe code pattern detected",
                    ],
                    "impact": "Risky code patterns may expose secrets or "
                    "weaken security controls.",
                    "remediation": "Review Semgrep findings and remediate"
                    " unsafe patterns.",
                },
            ],
        }
        return _FakeResponse(json.dumps(payload))


class _FakeChat:
    def __init__(self) -> None:
        self.completions = _FakeCompletions()


class FakeLLMClient:
    def __init__(self) -> None:
        self.chat = _FakeChat()


def _build_agent() -> ReviewAgent:
    settings = Settings()
    semgrep_tool = SemgrepTool()
    pip_audit_tool = PipAuditTool()

    return ReviewAgent(
        tool_list=[semgrep_tool, pip_audit_tool],
        llm_client=cast(Any, FakeLLMClient()),
        settings=settings,
    )


def _build_request() -> ReviewRequest:
    return ReviewRequest(
        review_type=ReviewType.security,
        local_path=str(_pack_a_path()),
    )


@pytest.mark.asyncio
@pytest.mark.skipif(not _has_required_binaries(), reason="semgrep is not installed")
async def test_610a_full_agent_real_tools_demo_pack_a_mocked_llm() -> None:
    agent = _build_agent()
    request = _build_request()

    report = await agent.run(request)

    assert report.status == AnalysisStatus.completed

    findings = report.findings
    assert isinstance(findings, list)

    # Reasonable range from requirement; keep slightly flexible.
    assert 20 <= len(findings) <= 100, f"Unexpected findings count: {len(findings)}"

    assert report.score > 0.0

    assert report.summary.strip() != ""

    assert report.execution_plan is not None
    assert len(report.execution_plan.steps) == 2

    completed_steps = [
        step
        for step in report.execution_plan.steps
        if step.status == StepStatus.completed
    ]
    assert len(completed_steps) == 2

    assert report.metadata is not None
    assert report.metadata.duration_seconds >= 0.0
    assert len(report.metadata.tools_used) == 2
    assert "semgrep" in report.metadata.tools_used
    assert "pip-audit" in report.metadata.tools_used


@pytest.mark.asyncio
@pytest.mark.skipif(not _has_required_binaries(), reason="semgrep is not installed")
async def test_610b_score_against_manifest_detection_rate_at_least_80_percent() -> None:
    agent = _build_agent()
    request = _build_request()

    report = await agent.run(request)

    assert report.findings, "Expected at least one finding before manifest scoring"

    code_findings: list[Finding] = [
        finding
        for finding in report.findings
        if finding.evidence.tool_name == "semgrep"
    ]
    dependency_findings: list[Finding] = [
        finding
        for finding in report.findings
        if finding.evidence.tool_name == "pip-audit"
    ]

    manifest = _read_expected_findings()

    assert report.execution_plan is not None

    pip_audit_step = [
        step for step in report.execution_plan.steps if step.tool_name == "pip-audit"
    ][0]
    assert pip_audit_step.result is not None
    raw_scan = DependencyScanResult.model_validate_json(
        pip_audit_step.result.raw_output
    )

    score_result = score_findings(
        manifest=manifest,
        code_findings=code_findings,
        dep_findings=dependency_findings,
        raw_scan=raw_scan,
    )

    detection_rate = score_result.combined.recall
    assert detection_rate >= 0.80, (
        f"Detection rate below threshold: {detection_rate:.2%}"
    )
