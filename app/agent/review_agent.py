from typing import Any  # Assuming tool_list is a list of tools, adjust as needed

from app.models import ReviewRequest, SecurityReport

# Assuming ReviewRequest and SecurityReport are defined elsewhere, e.g., in app.models


class ReviewAgent:
    def __init__(self, tool_list: list[Any], llm_client: Any):
        self.tool_list = tool_list
        self.llm_client = llm_client

    async def run(self, request: ReviewRequest) -> SecurityReport:
        # Stub implementation
        return SecurityReport(request=request, findings=[], score=0.0)
