from fastapi import APIRouter

from app.core.config import settings
from app.schemas.status import CapabilityStatus, ServiceStatus

router = APIRouter()


@router.get("/status", response_model=ServiceStatus)
def get_status() -> ServiceStatus:
    return ServiceStatus(
        name=settings.app_name,
        environment=settings.app_env,
        database_configured=bool(settings.database_url),
        openai_configured=bool(settings.openai_api_key),
        capabilities=[
            CapabilityStatus(name="Log Upload", status="planned"),
            CapabilityStatus(name="Log Parser", status="planned"),
            CapabilityStatus(name="AI Threat Analysis", status="planned"),
            CapabilityStatus(name="Incident Dashboard", status="ui-ready"),
            CapabilityStatus(name="PDF Reports", status="ui-ready"),
        ],
    )

