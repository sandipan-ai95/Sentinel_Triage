from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "development"
    secret_key: str = "local-dev-secret"
    database_url: str = "sqlite:///./soc_alerts.db"
    redis_url: str = "redis://localhost:6379/0"
    openrouter_api_key: str = ""
    openrouter_model: str = "typesafe/jev-1.13"
    rate_limit_per_minute: int = 60
    ingest_api_key: str = ""
    cors_origins: List[str] = ["http://localhost:5173"]

    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parents[2] / ".env",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
