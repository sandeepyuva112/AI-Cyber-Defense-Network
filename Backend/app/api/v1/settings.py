from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from app.core.config import settings

router = APIRouter()


class ApplicationSettingsResponse(BaseModel):
    app_name: str
    environment: str
    api_v1_prefix: str
    upload_storage_path: str
    max_upload_size_mb: int
    log_level: str


class AIConfigurationResponse(BaseModel):
    openai_configured: bool


class DetectionConfigurationResponse(BaseModel):
    # Repo currently uses deterministic rule matching and the DetectionEngine.
    detection_enabled: bool = True


class SystemInformationResponse(BaseModel):
    python_version: str


class HealthChecksResponse(BaseModel):
    status: str
    database_configured: bool
    openai_configured: bool


@router.get("/settings/application", response_model=ApplicationSettingsResponse)
async def application_settings() -> ApplicationSettingsResponse:
    return ApplicationSettingsResponse(
        app_name=settings.app_name,
        environment=settings.app_env,
        api_v1_prefix=settings.api_v1_prefix,
        upload_storage_path=str(settings.upload_storage_path),
        max_upload_size_mb=settings.max_upload_size_mb,
        log_level=settings.log_level,
    )


@router.get("/settings/ai", response_model=AIConfigurationResponse)
async def ai_configuration() -> AIConfigurationResponse:
    return AIConfigurationResponse(openai_configured=bool(settings.openai_api_key))


@router.get("/settings/detection", response_model=DetectionConfigurationResponse)
async def detection_configuration() -> DetectionConfigurationResponse:
    return DetectionConfigurationResponse()


@router.get("/settings/system", response_model=SystemInformationResponse)
async def system_information() -> SystemInformationResponse:
    import platform

    return SystemInformationResponse(python_version=platform.python_version())


@router.get("/health-checks", response_model=HealthChecksResponse)
async def health_checks() -> HealthChecksResponse:
    return HealthChecksResponse(
        status="ok",
        database_configured=bool(settings.database_url),
        openai_configured=bool(settings.openai_api_key),
    )

