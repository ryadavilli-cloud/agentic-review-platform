import uuid
from typing import Self

from pydantic import BaseModel, Field, model_validator

from app.models.enums import ReviewType


class ReviewRequest(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    repository_url: str | None = None
    code_snippet: str | None = None
    review_type: ReviewType = ReviewType.security
    options: dict[str, object] | None = None
    local_path: str | None = None

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        if not self.repository_url and not self.code_snippet and not self.local_path:
            raise ValueError(
                "Either repository_url, code_snippet, or local_path must be provided"
            )
        return self
