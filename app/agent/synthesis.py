import json

from openai import AzureOpenAI, OpenAI
from openai.types import CompletionUsage
from openai.types.chat import (
    ChatCompletionSystemMessageParam,
    ChatCompletionUserMessageParam,
)

from app.config import Settings
from app.telemetry.helpers import create_span


def call_llm_synthesis(
    llm_client: OpenAI | AzureOpenAI,
    system_prompt: str,
    user_prompt: str,
    settings: Settings,
) -> tuple[dict[str, object], CompletionUsage | None]:
    with create_span("agent.llm_synthesis"):
        messages: list[
            ChatCompletionSystemMessageParam | ChatCompletionUserMessageParam
        ] = [
            ChatCompletionSystemMessageParam(role="system", content=system_prompt),
            ChatCompletionUserMessageParam(role="user", content=user_prompt),
        ]

        response = llm_client.chat.completions.create(
            model=settings.llm_model,
            response_format={"type": "json_object"},
            messages=messages,
        )

        if response.choices and response.choices[0].message.content is not None:
            return (json.loads(response.choices[0].message.content), response.usage)
        else:
            return ({"summary": "No response received from LLM."}, response.usage)


def handle_synthesis_response(response: dict[str, object]) -> dict[str, object]:
    return {
        "summary": response.get("summary", "No response received from LLM."),
        "recommendation_groups": response.get("recommendation_groups", []),
    }
