import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.agent.synthesis import call_llm_synthesis, handle_synthesis_response
from app.config import Settings


def make_settings() -> Settings:
    return Settings()


def make_usage(
    prompt_tokens: int = 100,
    completion_tokens: int = 25,
    total_tokens: int = 125,
) -> SimpleNamespace:
    return SimpleNamespace(
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
    )


def make_response(
    *,
    choices: list[object],
    usage: object | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        choices=choices,
        usage=usage,
    )


def make_choice_with_content(content: str | None) -> SimpleNamespace:
    return SimpleNamespace(
        message=SimpleNamespace(content=content),
    )


# -------------------------------------------------------------------
# call_llm_synthesis tests
# -------------------------------------------------------------------


@pytest.mark.unit
@patch("app.agent.synthesis.create_span")
def test_call_llm_synthesis_happy_path(mock_create_span: MagicMock) -> None:
    mock_create_span.return_value.__enter__.return_value = None
    mock_create_span.return_value.__exit__.return_value = None

    expected_payload: dict[str, object] = {
        "summary": "Two high-risk findings detected.",
        "recommendation_groups": [
            {
                "theme": "Input Validation",
                "finding_titles": ["SQL injection in search endpoint"],
                "impact": "Improper input handling can lead to injection.",
                "remediation": "Use parameterized queries.",
            }
        ],
    }

    usage = make_usage()
    response = make_response(
        choices=[make_choice_with_content(json.dumps(expected_payload))],
        usage=usage,
    )

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = response

    result, returned_usage = call_llm_synthesis(
        llm_client=mock_client,
        system_prompt="system prompt",
        user_prompt="user prompt",
        settings=make_settings(),
    )

    assert result["summary"] == "Two high-risk findings detected."
    assert "recommendation_groups" in result
    assert isinstance(result["recommendation_groups"], list)
    assert result["recommendation_groups"][0]["theme"] == "Input Validation"
    assert returned_usage is usage


@pytest.mark.unit
@patch("app.agent.synthesis.create_span")
def test_call_llm_synthesis_empty_choices_returns_fallback_dict(
    mock_create_span: MagicMock,
) -> None:
    mock_create_span.return_value.__enter__.return_value = None
    mock_create_span.return_value.__exit__.return_value = None

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = make_response(
        choices=[],
        usage=None,
    )

    result, returned_usage = call_llm_synthesis(
        llm_client=mock_client,
        system_prompt="system prompt",
        user_prompt="user prompt",
        settings=make_settings(),
    )

    assert result == {"summary": "No response received from LLM."}
    assert returned_usage is None


@pytest.mark.unit
@patch("app.agent.synthesis.create_span")
def test_call_llm_synthesis_none_content_returns_fallback_dict(
    mock_create_span: MagicMock,
) -> None:
    mock_create_span.return_value.__enter__.return_value = None
    mock_create_span.return_value.__exit__.return_value = None

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = make_response(
        choices=[make_choice_with_content(None)],
        usage=None,
    )

    result, returned_usage = call_llm_synthesis(
        llm_client=mock_client,
        system_prompt="system prompt",
        user_prompt="user prompt",
        settings=make_settings(),
    )

    assert result == {"summary": "No response received from LLM."}
    assert returned_usage is None


@pytest.mark.unit
@patch("app.agent.synthesis.create_span")
def test_call_llm_synthesis_invalid_json_propagates_exception(
    mock_create_span: MagicMock,
) -> None:
    mock_create_span.return_value.__enter__.return_value = None
    mock_create_span.return_value.__exit__.return_value = None

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = make_response(
        choices=[make_choice_with_content("this is not json")],
        usage=None,
    )

    with pytest.raises(json.JSONDecodeError):
        call_llm_synthesis(
            llm_client=mock_client,
            system_prompt="system prompt",
            user_prompt="user prompt",
            settings=make_settings(),
        )


@pytest.mark.unit
@patch("app.agent.synthesis.create_span")
def test_call_llm_synthesis_calls_client_with_expected_messages_structure(
    mock_create_span: MagicMock,
) -> None:
    mock_create_span.return_value.__enter__.return_value = None
    mock_create_span.return_value.__exit__.return_value = None

    expected_payload: dict[str, object] = {
        "summary": "ok",
        "recommendation_groups": [],
    }

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = make_response(
        choices=[make_choice_with_content(json.dumps(expected_payload))],
        usage=None,
    )

    settings = make_settings()

    call_llm_synthesis(
        llm_client=mock_client,
        system_prompt="system prompt here",
        user_prompt="user prompt here",
        settings=settings,
    )

    mock_client.chat.completions.create.assert_called_once()

    kwargs = mock_client.chat.completions.create.call_args.kwargs

    assert kwargs["model"] == settings.llm_model
    assert kwargs["response_format"] == {"type": "json_object"}
    assert kwargs["messages"] == [
        {"role": "system", "content": "system prompt here"},
        {"role": "user", "content": "user prompt here"},
    ]


@pytest.mark.unit
@patch("app.agent.synthesis.create_span")
def test_call_llm_synthesis_returns_usage_object_alongside_parsed_dict(
    mock_create_span: MagicMock,
) -> None:
    mock_create_span.return_value.__enter__.return_value = None
    mock_create_span.return_value.__exit__.return_value = None

    usage = make_usage(prompt_tokens=200, completion_tokens=50, total_tokens=250)
    payload: dict[str, object] = {
        "summary": "Synthesis completed.",
        "recommendation_groups": [],
    }

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = make_response(
        choices=[make_choice_with_content(json.dumps(payload))],
        usage=usage,
    )

    result, returned_usage = call_llm_synthesis(
        llm_client=mock_client,
        system_prompt="system prompt",
        user_prompt="user prompt",
        settings=make_settings(),
    )

    assert result["summary"] == "Synthesis completed."
    assert returned_usage is not None
    assert returned_usage.prompt_tokens == 200
    assert returned_usage.completion_tokens == 50


# -------------------------------------------------------------------
# handle_synthesis_response tests
# -------------------------------------------------------------------


@pytest.mark.unit
def test_handle_synthesis_response_full_response() -> None:
    response: dict[str, object] = {
        "summary": "Two findings need attention.",
        "recommendation_groups": [
            {
                "theme": "Input Validation",
                "finding_titles": ["SQL injection in search endpoint"],
                "impact": "Attackers may inject malicious input.",
                "remediation": "Use parameterized queries.",
            }
        ],
    }

    result = handle_synthesis_response(response)

    assert result["summary"] == "Two findings need attention."
    assert result["recommendation_groups"] == response["recommendation_groups"]


@pytest.mark.unit
def test_handle_synthesis_response_missing_summary() -> None:
    response: dict[str, object] = {
        "recommendation_groups": [
            {
                "theme": "Dependency Hygiene",
                "finding_titles": ["Vulnerability in requests 2.25.0"],
                "impact": "Known vulnerable packages increase risk.",
                "remediation": "Upgrade to a patched version.",
            }
        ]
    }

    result = handle_synthesis_response(response)

    assert result["summary"] == "No response received from LLM."
    assert result["recommendation_groups"] == response["recommendation_groups"]


@pytest.mark.unit
def test_handle_synthesis_response_missing_recommendation_groups() -> None:
    response: dict[str, object] = {
        "summary": "One critical finding detected.",
    }

    result = handle_synthesis_response(response)

    assert result["summary"] == "One critical finding detected."
    assert result["recommendation_groups"] == []


@pytest.mark.unit
def test_handle_synthesis_response_empty_dict() -> None:
    result = handle_synthesis_response({})

    assert result["summary"] == "No response received from LLM."
    assert result["recommendation_groups"] == []
