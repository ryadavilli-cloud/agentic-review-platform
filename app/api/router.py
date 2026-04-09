from uuid import UUID

from fastapi import APIRouter, HTTPException, Response, status

from app.agent.review_agent import ReviewAgent
from app.api.formatters import format_report_as_markdown
from app.api.models import AnalyzeRequest, DemoScenarioResponseModel
from app.api.store import (
    get_report,
    list_demo_scenarios,
    resolve_scenario_path,
    save_report,
)
from app.config import get_settings
from app.llm import create_llm_client
from app.models.report import SecurityReport
from app.models.review import ReviewRequest
from app.tools.base import BaseTool
from app.tools.pip_audit import PipAuditTool
from app.tools.semgrep import SemgrepTool

router = APIRouter(prefix="/api/v1", tags=["Review"])


@router.post(
    "/analyze",
    response_model=SecurityReport,
    status_code=status.HTTP_201_CREATED,
    responses={500: {"description": "If the creation of the report fails."}},
)
async def analyze(request: AnalyzeRequest) -> SecurityReport:
    scenario_path = resolve_scenario_path(request.scenario_id)

    if scenario_path is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scenario not found",
        )

    review_request = ReviewRequest(local_path=scenario_path)

    settings = get_settings()
    tools: list[BaseTool] = [SemgrepTool(), PipAuditTool()]
    llm_client = create_llm_client(settings)

    agent = ReviewAgent(
        tool_list=tools,
        llm_client=llm_client,
        settings=settings,
    )

    report = await agent.run(review_request)
    save_report(report)

    return report


@router.get(
    "/analysis/{id}",
    response_model=SecurityReport,
    status_code=status.HTTP_200_OK,
    summary="Run security analysis",
    description="Accepts a demo scenario ID, runs Semgrep and pip-audit against it,"
    " synthesizes findings with an LLM, and returns a structured security report.",
    responses={404: {"description": "Scenario not found."}},
)
async def get_analysis(id: UUID) -> SecurityReport:
    report = get_report(id)

    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found",
        )

    return report


@router.get(
    "/demo-scenarios",
    response_model=list[DemoScenarioResponseModel],
    status_code=status.HTTP_200_OK,
    summary="Get list of demo scenarios",
    description="Gets a list of demo scenarios available in the code base currently.",
    responses={404: {"description": "Scenarios not found."}},
)
async def get_demo_scenarios() -> list[DemoScenarioResponseModel]:
    try:
        return [
            DemoScenarioResponseModel.model_validate(s) for s in list_demo_scenarios()
        ]
    except Exception:
        raise HTTPException(status_code=404, detail="Scenario not found") from None


@router.get(
    "/reports/{id}",
    status_code=status.HTTP_200_OK,
    summary="Run security analysis",
    description="Accepts a security report id, gets the corresponding report, "
    "Generates a markdown summary of the report.",
    responses={404: {"description": "Analysis Report not found."}},
)
async def get_analysis_report(id: UUID) -> Response:
    report = get_report(id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    markdown = format_report_as_markdown(report)
    return Response(content=markdown, media_type="text/markdown")
