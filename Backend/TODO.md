# AI Cyber Defense Network — TODO

## Phase 1 — Backend Completion (Highest Priority)
- [ ] Persistent log upload (store uploaded files + parsed metadata)
- [ ] Implement parser pipeline for TXT, CSV, JSON, XML, Syslog, EVTX (graceful unsupported handling)
- [ ] Persist AI analysis results linked to uploaded logs
- [ ] Threat persistence and relationships
- [ ] IOC extraction and persistence
- [ ] MITRE ATT&CK mapping persistence
- [ ] Alert lifecycle: Open → Investigating → Resolved → Closed
- [ ] Report generation persistence
- [ ] AI explanation history
- [ ] Dashboard metrics computed from persisted data
- [ ] Background jobs for long-running analysis
- [ ] Proper transactions + rollback
- [ ] Validation + error handling improvements
- [ ] Structured logging improvements
- [ ] Unit tests for all new backend services

## Phase 2 — Complete Service Layer
- [ ] Replace placeholder implementations with production-ready services
- [ ] Complete AI service (provider/model metadata, parsing robustness)
- [ ] Threat correlation
- [ ] IOC correlation
- [ ] MITRE enrichment
- [ ] Executive summary generation
- [ ] Recommended response engine
- [ ] Risk scoring
- [ ] Dashboard aggregation
- [ ] Analytics engine
- [ ] Report export
- [ ] History retrieval

## Phase 3 — React SOC Dashboard
- [ ] Build React pages: Dashboard, Live Monitor, Upload Logs, Threat Explorer, AI Analysis, AI Copilot, MITRE Matrix, IOC Explorer, Alerts, Reports, Analytics, Settings
- [ ] Wire every page to existing APIs
- [ ] Global search + command palette

## Phase 4 — Electron Desktop
- [ ] Bundle React frontend
- [ ] Start FastAPI backend automatically
- [ ] Local API communication
- [ ] Splash screen + custom icon
- [ ] Auto-update ready
- [ ] Windows installer + start-on-boot option
- [ ] Offline mode where possible

## Phase 5 — Polish
- [ ] Cyberpunk dark glassmorphism UI (theme + visuals)
- [ ] Animations + skeletons + toasts
- [ ] Empty states + error pages
- [ ] Responsive layout + keyboard shortcuts + accessibility

## Phase 6 — Testing
- [ ] Backend unit tests
- [ ] Backend API integration tests
- [ ] Frontend component tests
- [ ] End-to-end tests
- [ ] Performance checks + security validation

## Phase 7 — Documentation
- [ ] Generate README + Installation Guide
- [ ] Architecture diagram
- [ ] API documentation + Deployment Guide
- [ ] User Manual

