import json
import time
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.enums import StepStatus
from app.models.finding import Finding
from app.models.report import SecurityReport
from app.scoring.matcher import score_findings
from app.scoring.models import (
    ExpectedFindings,
)
from app.tools.pip_audit_results import DependencyScanResult

PACK_A_SCENARIO_ID = "pack-a"
BASELINE_OUTPUT_DIR = Path("baselines")
MODEL_COST_PER_1K_INPUT_TOKENS = 0
MODEL_COST_PER_1K_OUTPUT_TOKENS = 0


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def expected_manifest() -> ExpectedFindings:
    path = Path("demo-packs/pack-a/expected_findings.json")
    return ExpectedFindings.model_validate_json(path.read_text())


@pytest.fixture
def baseline_output_dir() -> Path:
    Path(BASELINE_OUTPUT_DIR).mkdir(exist_ok=True)
    return Path(BASELINE_OUTPUT_DIR)


@pytest.mark.scenario
def test_pack_a_baseline_run(
    client: TestClient,
    expected_manifest: ExpectedFindings,
    baseline_output_dir: Path,
):
    start = time.perf_counter()

    response = client.post(
        url="/api/v1/analyze",
        json={"scenario_id": PACK_A_SCENARIO_ID},
    )
    end = time.perf_counter()

    assert response.status_code == 201
    security_report = SecurityReport.model_validate_json(response.content)

    assert len(security_report.findings) > 0
    assert security_report.metadata is not None
    assert security_report.metadata.token_count > 0

    # iterate though the findings and split them into code findings
    # or dependency findings.

    code_findings: list[Finding] = []
    dep_findings: list[Finding] = []
    for finding in security_report.findings:
        if finding.evidence.tool_name == "semgrep":
            code_findings.append(finding)
        elif finding.evidence.tool_name == "pip-audit":
            dep_findings.append(finding)
        # ignore the others which may not match

    str_baseline: str = ""

    pip_audit_result: DependencyScanResult | None = None

    if security_report.execution_plan and security_report.execution_plan.steps:
        for step in security_report.execution_plan.steps:
            if (
                step.tool_name == "pip-audit"
                and step.status == StepStatus.completed
                and step.result
            ):
                pip_audit_result = DependencyScanResult.model_validate_json(
                    step.result.raw_output
                )
                break  # take the first completed pip-audit step

    assert pip_audit_result is not None, (
        "No completed pip-audit step found in execution plan — "
        "cannot score dependency findings"
    )

    combined = score_findings(
        expected_manifest,
        code_findings,
        dep_findings,
        pip_audit_result,
    )

    assert combined.combined.recall >= 0.95
    assert combined.code.score.precision >= 0.8
    assert combined.dependency.score.recall == 1.0
    assert combined.code.score.recall >= 0.90

    str_baseline += f"BASELINE: recall={combined.combined.recall}"
    str_baseline += f" precision={combined.combined.precision}% "
    str_baseline += f" f1={combined.combined.f1}%"
    str_baseline += f" tp={combined.combined.true_positives}"
    str_baseline += f" fp={combined.combined.false_positives}"
    str_baseline += f" fn={combined.combined.false_negatives} |"
    str_baseline += f" code: tp={combined.code.score.true_positives}"
    str_baseline += f" fn={combined.code.score.false_negatives} |"
    str_baseline += f" dep: tp={combined.dependency.score.true_positives}"
    str_baseline += f" fn={combined.dependency.score.false_negatives} |"

    wall_duration = end - start
    agent_duration = 0.0
    token_count = 0
    tools_used = []
    if security_report.metadata:
        agent_duration = security_report.metadata.duration_seconds
        token_count = security_report.metadata.token_count
        tools_used = security_report.metadata.tools_used
        assert "semgrep" in tools_used and "pip-audit" in tools_used

    str_baseline += f"duration={wall_duration}s tokens={token_count} cost=$X.XX"

    json_obj: dict[str, object] = {
        "timestamp": str(datetime.now),
        "scenario_id": "pack-a",
        "report": security_report.model_dump(mode="json"),
        "score": combined.model_dump(mode="json"),
        "metrics": {
            "wall_duration_seconds": wall_duration,
            "agent_duration_seconds": agent_duration,
            "token_count": token_count,
            "cost_estimate_usd": 0,
            "tools_used": tools_used,
        },
    }
    timestamp = datetime.now().isoformat().replace(":", "-")  # Windows-safe
    dump_file = baseline_output_dir / f"pack-a-{timestamp}.json"
    with dump_file.open("w") as f:
        json.dump(json_obj, f, indent=2)

    print(str_baseline)
