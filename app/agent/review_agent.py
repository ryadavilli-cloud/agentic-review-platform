from openai import AzureOpenAI, OpenAI

from app.models import ReviewRequest, SecurityReport
from app.tools.base import BaseTool

# Assuming ReviewRequest and SecurityReport are defined elsewhere, e.g., in app.models


class ReviewAgent:
    def __init__(self, tool_list: list[BaseTool], llm_client: OpenAI | AzureOpenAI):
        self.tool_list = tool_list
        self.llm_client = llm_client

    async def run(self, request: ReviewRequest) -> SecurityReport:
        # Stub implementation
        return SecurityReport(request=request, findings=[], score=0.0)
