# Implementation Plan — Complete Every API Endpoint

## Scope
Add missing FastAPI endpoints and routers under `Backend/app/api/v1/` for:
- logs.py: upload/analyze/details/history
- dashboard.py: summary/metrics/timeline/risk distribution/recent activity/trend analytics
- alerts.py: list/details/status updates/filter/search
- threats.py: details/MITRE mapping/IOC details/threat intelligence/risk assessment
- ai.py: explanation/re-analysis/executive summary/recommended response/AI history
- reports.py: generate/list/retrieve/delete/export PDF/HTML/JSON
- settings.py: application settings/AI config/detection config/system info/health checks

### Non-breaking
Do not rename existing routes.
Maintain existing `status.py`, `ai_analyze.py`, and `reports.py` functionality.

## Shared Infrastructure Strategy (no code duplication)
Create shared modules:
1. `Backend/app/api/_common/errors.py`
2. `Backend/app/api/_common/pagination.py`
3. `Backend/app/api/_common/filtering.py`
4. `Backend/app/api/_common/sorting.py`
5. `Backend/app/api/_common/auth.py` (hook placeholder)
6. `Backend/app/api/_common/envelopes.py` (consistent response envelopes)
7. `Backend/app/api/deps.py` (dependency injection: `get_db`, auth context)

And shared response/request schemas:
- `Backend/app/schemas/api_envelopes.py`
- `Backend/app/schemas/common_pagination.py`

## Services & Repositories Strategy
- Add repository classes under `Backend/app/db/repositories/` for each aggregate:
  - LogsRepository, AlertsRepository, IncidentsRepository, ThreatsRepository,
    AIAnalysisRepository, ReportsRepository, SettingsRepository (may read from config).
- Add services under `Backend/app/services/`:
  - LogService, DetectionService, DashboardService, AlertService,
    ThreatService, AIService (explanation/re-analysis), ReportService, SettingsService.

Routers only do:
- validate request/params
- call service methods
- serialize response models

## Endpoint Contracts
All endpoints will define:
- `summary`, `description`, `tags`
- request/response schemas
- explicit status codes

Collection endpoints support:
- pagination: `limit/offset`
- filtering/sorting where applicable

## Testing
- Add unit/integration tests under `Backend/tests/`:
  - `test_logs_endpoints.py`
  - `test_dashboard_endpoints.py`
  - `test_alerts_endpoints.py`
  - `test_threats_endpoints.py`
  - `test_ai_endpoints.py`
  - `test_settings_endpoints.py`
  - `test_openapi_schema.py`

Run:
- `pytest`
- verify `GET /openapi.json` includes all routes

## Dependency Flow (target)
Router -> Service -> Repository -> SQLAlchemy Models

## Deliverables
- New router files:
  - `Backend/app/api/v1/logs.py`
  - `Backend/app/api/v1/dashboard.py`
  - `Backend/app/api/v1/alerts.py`
  - `Backend/app/api/v1/threats.py`
  - `Backend/app/api/v1/ai.py`
  - `Backend/app/api/v1/reports.py` (expanded to include export-by-format endpoints)
  - `Backend/app/api/v1/settings.py`

- New shared modules under `Backend/app/api/_common/` and schema modules.
- New repositories/services.
- Router registration updates in `Backend/app/api/router.py`.


