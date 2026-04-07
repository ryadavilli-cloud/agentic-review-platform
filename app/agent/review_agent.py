from pathlib import Path
from time import perf_counter

from openai import AzureOpenAI, OpenAI

from app.agent.orchestrator import (
    assemble_findings,
    build_report_metadata,
    compute_risk_score,
    create_execution_plan,
    execute_plan,
)
from app.models import AnalysisStatus, ReviewRequest, SecurityReport
from app.tools.base import BaseTool


class ReviewAgent:
    def __init__(self, tool_list: list[BaseTool], llm_client: OpenAI | AzureOpenAI):
        self.tool_list = tool_list
        self.llm_client = llm_client

    async def run(self, request: ReviewRequest) -> SecurityReport:
        if request.local_path is None:
            raise ValueError("ReviewRequest.local_path is required to run the review")

        report = SecurityReport(
            request=request,
            status=AnalysisStatus.planning,
            findings=[],
            summary="",
            score=0.0,
        )

        local_path = Path(request.local_path)

        execution_plan = create_execution_plan(
            local_path=local_path,
            tools=self.tool_list,
            review_request=request,
        )

        report.execution_plan = execution_plan
        report.status = AnalysisStatus.analyzing

        started_at = perf_counter()
        completed_plan = await execute_plan(
            execution_plan=execution_plan,
            tools=self.tool_list,
        )
        duration_seconds = perf_counter() - started_at

        report.execution_plan = completed_plan
        report.findings = assemble_findings(completed_plan)
        report.metadata = build_report_metadata(completed_plan, duration_seconds)
        report.score = compute_risk_score(report.findings)
        report.status = AnalysisStatus.completed

        return report
