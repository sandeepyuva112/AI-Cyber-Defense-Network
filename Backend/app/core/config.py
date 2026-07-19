from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AI Cyber Defense Network API"
    app_env: str = "development"
    api_v1_prefix: str = "/api/v1"
    database_url: str = "sqlite:///../Database/ai_cyber_defense.db"
    log_level: str = "INFO"
    openai_api_key: str = ""
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost", "http://127.0.0.1"])

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

