from openai import AzureOpenAI, OpenAI

from app.config import Settings


def create_llm_client(settings: Settings) -> OpenAI | AzureOpenAI:
    if settings.llm_provider.lower() == "openai":
        return OpenAI(api_key=settings.openai_api_key)
    elif settings.llm_provider.lower() == "azure":
        return AzureOpenAI(
            api_key=settings.openai_api_key,
            azure_endpoint=settings.azure_openai_endpoint,
            api_version=settings.azure_openai_api_version,
        )
    else:
        raise ValueError(f"Unsupported LLM provider: {settings.llm_provider}")
