import json
import logging
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
from app.agent.prompts import SYNTHESIS_SYSTEM_PROMPT, build_user_prompt
from app.agent.synthesis import call_llm_synthesis, handle_synthesis_response
from app.config import Settings
from app.models import AnalysisStatus, ReviewRequest, SecurityReport
from app.models.report import RecommendationGroup
from app.telemetry.helpers import log_with_context
from app.tools.base import BaseTool


class ReviewAgent:
    def __init__(
        self,
        tool_list: list[BaseTool],
        llm_client: OpenAI | AzureOpenAI,
        settings: Settings,
    ):
        self.tool_list = tool_list
        self.llm_client = llm_client
        self.settings = settings

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

        try:
            llm_raw_response, usage = call_llm_synthesis(
                llm_client=self.llm_client,
                system_prompt=SYNTHESIS_SYSTEM_PROMPT,
                user_prompt=build_user_prompt(
                    execution_plan=execution_plan,
                    findings=report.findings,
                    request=request,
                ),
                settings=self.settings,
            )

            if usage is not None:
                log_with_context(
                    logger_name="agent.run",
                    message=f"Completion tokens : {usage.completion_tokens}",
                )

                log_with_context(
                    logger_name="agent.run",
                    message=f"Completion tokens : {usage.prompt_tokens}",
                )

                report.metadata.token_count = (
                    usage.completion_tokens + usage.prompt_tokens
                )

            llm_response = handle_synthesis_response(llm_raw_response)

            report.summary = str(llm_response.get("summary"))
            llm_recommendation_groups = json.loads(
                str(llm_response.get("recommendation_groups"))
            )

            for recommendation_group in llm_recommendation_groups:
                report.recommendation_groups.append(
                    RecommendationGroup(
                        finding_titles=recommendation_group.get("finding_titles"),
                        theme=recommendation_group.get("theme"),
                        impact=recommendation_group.get("impact"),
                        remediation=recommendation_group.get("remediation"),
                    )
                )

        except Exception as ex:
            log_with_context(
                logger_name="agent.run",
                message="Exception while getting LLM response",
                level=logging.ERROR,
                extra={"exception": ex},
            )
            report.summary = (
                "Automated analysis completed. "
                f"{len(report.findings)} findings detected across {len(self.tool_list)}"
                " tools. LLM synthesis unavailable."
            )

        report.status = AnalysisStatus.completed

        return report
