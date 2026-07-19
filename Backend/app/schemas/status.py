from pydantic import BaseModel


class CapabilityStatus(BaseModel):
    name: str
    status: str


class ServiceStatus(BaseModel):
    name: str
    environment: str
    database_configured: bool
    openai_configured: bool
    capabilities: list[CapabilityStatus]

