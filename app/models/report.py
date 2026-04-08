import datetime
import uuid

from pydantic import BaseModel, Field

from app.models.agent import ExecutionPlan
from app.models.enums import AnalysisStatus
from app.models.finding import Finding
from app.models.review import ReviewRequest


class ReportMetadata(BaseModel):
    duration_seconds: float
    tools_used: list[str]
    token_count: int = 0
    cost_estimate: float = 0.0
    timestamp: datetime.datetime


class RecommendationGroup(BaseModel):
    theme: str
    finding_titles: list[str]
    impact: str
    remediation: str


class SecurityReport(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    request: ReviewRequest
    status: AnalysisStatus = AnalysisStatus.pending
    findings: list[Finding] = []
    metadata: ReportMetadata | None = None
    execution_plan: ExecutionPlan | None = None
    summary: str = ""
    recommendation_groups: list[RecommendationGroup] = []
    score: float = Field(ge=0.0, le=100.0)
