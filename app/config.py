from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "agentic-review-platform"
    app_version: str = "0.1.0"
    environment: str = "development"
    debug: bool = True
    log_level: str = "INFO"
    openai_api_key: str = ""
    llm_provider: str = "openai"  # or "azure"

    llm_model: str = "gpt-4.1-mini"

    anthropic_api_key: str = ""

    azure_openai_endpoint: str = ""
    azure_openai_api_version: str = "2024-06-01"

    applicationinsights_connection_string: str = ""

    azure_subscription_id: str = ""
    azure_resource_group: str = ""

    model_config = SettingsConfigDict(env_file=".env")


@lru_cache
def get_settings() -> Settings:
    return Settings()
