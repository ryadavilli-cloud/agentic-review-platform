from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from app.api import router as router_module
from app.main import app
from app.models.report import SecurityReport

client = TestClient(app)


def make_security_report(**overrides: Any) -> SecurityReport:
    """
    Minimal valid SecurityReport factory for mocked agent responses.

    If your SecurityReport model has additional required fields or different
    field names, adjust only this function.
    """
    from app.models.enums import AnalysisStatus, FindingCategory, Severity

    data: dict[str, Any] = {
        "id": uuid4(),
        "request": {"local_path": "demo-packs/pack-a"},
        "status": AnalysisStatus.completed,
        "score": 75.0,
        "summary": "One high-severity finding detected.",
        "findings": [
            {
                "id": str(uuid4()),
                "title": "SQL Injection Risk",
                "description": "User input reaches a SQL query.",
                "severity": Severity.high,
                "confidence": 0.8,
                "category": FindingCategory.vulnerability,
                "evidence": {
                    "tool_name": "semgrep",
                    "file_path": "demo-packs/pack-a/app.py",
                    "raw_output": "semgrep-result-1",
                },
                "recommendation": "Use parameterized queries.",
            }
        ],
    }
    data.update(overrides)
    return SecurityReport.model_validate(data)


@pytest.fixture
def in_memory_report_store(
    monkeypatch: pytest.MonkeyPatch,
) -> dict[UUID, SecurityReport]:
    """
    Patch router store functions so tests don't depend on real persistence.
    """

    store: dict[UUID, SecurityReport] = {}

    def fake_save_report(report: SecurityReport) -> None:
        store[report.id] = report

    def fake_get_report(report_id: UUID) -> SecurityReport | None:
        return store.get(report_id)

    monkeypatch.setattr(router_module, "save_report", fake_save_report)
    monkeypatch.setattr(router_module, "get_report", fake_get_report)

    return store


@pytest.fixture
def mock_review_agent(monkeypatch: pytest.MonkeyPatch) -> type:
    from app.api import router as router_module

    class FakeReviewAgent:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def run(self, review_request: Any) -> SecurityReport:
            return make_security_report()

    def fake_create_llm_client(settings: Any) -> object:
        return object()

    monkeypatch.setattr(router_module, "ReviewAgent", FakeReviewAgent)
    monkeypatch.setattr(router_module, "create_llm_client", fake_create_llm_client)

    return FakeReviewAgent


@pytest.fixture
def mock_valid_scenario(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.api import router as router_module

    def fake_resolve_scenario_path(scenario_id: str) -> str | None:
        if scenario_id == "pack-a":
            return "demo-packs/pack-a"
        return None

    monkeypatch.setattr(
        router_module,
        "resolve_scenario_path",
        fake_resolve_scenario_path,
    )


@pytest.mark.integration
def test_post_analyze_happy_path(
    mock_review_agent: type,
    mock_valid_scenario: None,
    in_memory_report_store: dict[UUID, SecurityReport],
) -> None:
    response = client.post("/api/v1/analyze", json={"scenario_id": "pack-a"})

    assert response.status_code == 201

    body = response.json()
    assert "id" in body
    assert "status" in body
    assert "findings" in body
    assert "summary" in body
    assert isinstance(body["findings"], list)

    report_id = UUID(body["id"])
    assert report_id in in_memory_report_store


@pytest.mark.integration
def test_post_analyze_invalid_scenario(
    mock_review_agent: type,
    mock_valid_scenario: None,
    in_memory_report_store: dict[UUID, SecurityReport],
) -> None:
    response = client.post("/api/v1/analyze", json={"scenario_id": "nonexistent"})

    assert response.status_code == 404
    assert response.json() == {"detail": "Scenario not found"}


@pytest.mark.integration
def test_post_analyze_missing_scenario_id() -> None:
    response = client.post("/api/v1/analyze", json={})

    assert response.status_code == 422


@pytest.mark.integration
def test_get_analysis_happy_path(
    mock_review_agent: type,
    mock_valid_scenario: None,
    in_memory_report_store: dict[UUID, SecurityReport],
) -> None:
    post_response = client.post("/api/v1/analyze", json={"scenario_id": "pack-a"})
    assert post_response.status_code == 201

    created = post_response.json()
    report_id = created["id"]

    get_response = client.get(f"/api/v1/analysis/{report_id}")

    assert get_response.status_code == 200
    assert get_response.json() == created


@pytest.mark.integration
def test_get_analysis_not_found(
    in_memory_report_store: dict[UUID, SecurityReport],
) -> None:
    random_id = uuid4()

    response = client.get(f"/api/v1/analysis/{random_id}")

    assert response.status_code == 404
    assert response.json() == {"detail": "Analysis not found"}


@pytest.mark.integration
def test_get_demo_scenarios_happy_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.api import router as router_module

    def fake_list_demo_scenarios() -> list[dict[str, str]]:
        return [
            {
                "id": "pack-a",
                "name": "Pack A",
                "description": "Sample insecure Flask app",
                "path": "demo-packs/pack-a",
            }
        ]

    monkeypatch.setattr(
        router_module,
        "list_demo_scenarios",
        fake_list_demo_scenarios,
    )

    response = client.get("/api/v1/demo-scenarios")

    assert response.status_code == 200

    body: list[dict[str, Any]] = response.json()
    assert len(body) >= 1

    for item in body:
        assert "id" in item
        assert "name" in item
        assert "description" in item
        assert "path" not in item


@pytest.mark.integration
def test_get_report_markdown_happy_path(
    mock_review_agent: type,
    mock_valid_scenario: None,
    in_memory_report_store: dict[UUID, SecurityReport],
) -> None:
    post_response = client.post("/api/v1/analyze", json={"scenario_id": "pack-a"})
    assert post_response.status_code == 201

    report_id = post_response.json()["id"]

    response = client.get(f"/api/v1/reports/{report_id}")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")

    body = response.text
    assert "# Security Review Report" in body
    assert "## Summary" in body
    assert "## Findings" in body


@pytest.mark.integration
def test_get_report_markdown_not_found(
    in_memory_report_store: dict[UUID, SecurityReport],
) -> None:
    random_id = uuid4()

    response = client.get(f"/api/v1/reports/{random_id}")

    assert response.status_code == 404
    assert response.json() == {"detail": "Report not found"}


@pytest.mark.integration
def test_openapi_spec_contains_expected_paths_and_review_tag() -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200

    spec = response.json()
    paths = spec["paths"]

    assert "/api/v1/analyze" in paths
    assert "/api/v1/analysis/{id}" in paths
    assert "/api/v1/demo-scenarios" in paths
    assert "/api/v1/reports/{id}" in paths

    tags = spec.get("tags", [])
    tag_names = [tag["name"] for tag in tags]
    assert "Review" in tag_names
