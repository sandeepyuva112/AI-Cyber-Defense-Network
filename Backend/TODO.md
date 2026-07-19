# Backend TODO — Database implementation

- [ ] Inspect existing DB setup (models, Alembic, session) and confirm current baseline.
- [ ] Extend `AIAnalysis` model to represent full AI response lifecycle (provider/model/prompt version/type/summaries/findings/executive summary/classification/severity/risk/confidence/mitre mapping/iocs/recommended actions/reasoning/processing time/token usage/correlation/request id/status/error/created+updated timestamps).
- [ ] Add necessary relationships from `AIAnalysis` to MITRE mappings and IOC without duplicating storage.
- [ ] Implement Alembic migrations: replace stub initial migration with create-table statements OR add a new migration that creates schema and upgrades safely.
- [ ] Add CRUD/repository pattern layer for each entity using existing `get_db()` session.
- [ ] Ensure indexes for query performance where appropriate.
- [ ] Run pytest to validate tests and fix any breakages.
- [ ] Run Alembic upgrade to verify migrations work end-to-end.

