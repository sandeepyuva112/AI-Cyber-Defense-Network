from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DATABASE_PATH = PROJECT_ROOT / "Database" / "ai_cyber_defense.db"
DEFAULT_UPLOAD_STORAGE_PATH = PROJECT_ROOT / "Database" / "uploads"


class Settings(BaseSettings):
    app_name: str = "AI Cyber Defense Network API"
    app_env: str = "development"
    api_v1_prefix: str = "/api/v1"
    database_url: str = f"sqlite:///{DEFAULT_DATABASE_PATH.as_posix()}"
    upload_storage_path: Path = DEFAULT_UPLOAD_STORAGE_PATH
    max_upload_size_mb: int = 50
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

