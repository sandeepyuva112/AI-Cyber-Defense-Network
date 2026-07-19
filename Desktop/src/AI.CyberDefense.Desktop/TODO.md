# Desktop SOC Dashboard UI - TODO

## Phase 1: Architecture + Integration
- [ ] Add DTOs/models for SOC dashboard widgets (ThreatCard, TimelineEvent, RiskSummary, AlertRow, etc.)
- [ ] Add interfaces for data sources (IStatusService, IAiAnalyzeService, ISocDashboardService placeholders)
- [ ] Implement real backend services:
  - [ ] GET /status client
  - [ ] POST /ai/analyze client
- [ ] Implement placeholder services with strongly typed contracts for:
  - [ ] Dashboard metrics
  - [ ] Alerts/incidents
  - [ ] Threat cards + timeline
  - [ ] MITRE coverage
  - [ ] Reports
- [ ] Add view-state models for loading/empty/offline/error

## Phase 2: MVVM + Navigation (without replacing pages)
- [ ] Refactor MainWindowViewModel to act as page host
- [ ] Keep existing MainWindow dashboard markup intact while adding a content region
- [ ] Add commands for navigation selection (MVVM)

## Phase 3: UI Views/Windows
- [ ] DashboardView (SOC overview + Risk Meter + Timeline preview)
- [ ] ThreatAnalysisView (Threat cards grid + search/filters)
- [ ] IncidentsView (Alert table with search/filters + row details)
- [ ] ThreatDetailsWindow (modal window, data-bound)
- [ ] SettingsView (Dark theme + backend base URL + refresh interval)
- [ ] About page (placeholder)

## Phase 4: Live Refresh + UX polish
- [ ] Implement live refresh timer/polling in relevant VMs (mock first)
- [ ] Implement graceful loading animations
- [ ] Implement error messages and retry actions
- [ ] Implement responsive layout behavior (wrapping, column collapse)

## Phase 5: Charts (native Avalonia)
- [ ] Implement lightweight native charts using Canvas/Shapes:
  - [ ] Risk meter visuals
  - [ ] Timeline plot
  - [ ] MITRE coverage visualization

## Phase 6: `/ai/analyze` mapping
- [ ] Create ReportMapper that defensively parses POST /ai/analyze response
- [ ] Populate Threat cards, Alert table, Timeline, Risk Meter using mapper output

## Phase 7: Build/Test
- [ ] dotnet build Desktop
- [ ] Manual smoke tests:
  - [ ] Offline/error states
  - [ ] Search + filters
  - [ ] Threat details window
  - [ ] Live refresh
  - [ ] Upload Logs calls /ai/analyze

