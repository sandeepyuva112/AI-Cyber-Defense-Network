# AI Cyber Defense Network

AI Cyber Defense Network is a desktop Security Operations Center (SOC) prototype that ingests security logs, correlates threats, highlights suspicious activity, and uses AI to explain incidents in plain language.

Built for the OpenAI Build Week Hackathon, the project combines a modern desktop interface with a Python/FastAPI backend, database-backed analytics, and AI-assisted threat investigation.

## What it does

- Upload and ingest security log files
- Parse and normalize multiple log formats
- Detect suspicious activity and correlate threats
- Store alerts, incidents, and analysis results in a database
- Show real-time SOC-style dashboards and threat views
- Generate AI explanations, response guidance, and reports
- Track IOC entries and MITRE ATT&CK mappings

## Key features

- Security operations dashboard with live metrics
- Live monitor for streaming or parsed event feeds
- Log upload portal with ingestion history
- Threat explorer for incident correlation
- IOC registry for extracted indicators of compromise
- MITRE ATT&CK matrix view for tactic/technique mapping
- Alert management console for triage and lifecycle updates
- Incident report center for saved forensic reports
- Settings page for backend URL and AI connectivity

## Tech stack

### Frontend
- React
- TypeScript
- Electron
- Tailwind CSS

### Backend
- Python
- FastAPI
- SQLAlchemy
- Alembic

### Database
- SQLite

### AI
- OpenAI API / Responses API

## Architecture

The current design follows a clear pipeline:

1. Upload log file
2. Parse and normalize events
3. Detect threats and extract IOCs
4. Run AI analysis for explanation and recommendations
5. Store everything in the database
6. Feed dashboard, alerts, threat explorer, and reports from persisted data

This keeps the dashboard historical, searchable, and ready for future real-time expansion.

## Screenshots

The repository includes a working desktop UI with:

- Dashboard
- Live Monitor
- Log Upload
- Threat Explorer
- IOC Registry
- MITRE Matrix
- Alerts Center
- Reports
- Settings

## Current status

This is a hackathon-ready prototype with a strong UI and a backend foundation. The remaining work is focused on finishing database-backed ingestion, finalizing the AI analysis flow, connecting all endpoints, and polishing reporting and testing.

## Project structure

- `Frontend/` - desktop application
- `Backend/` - FastAPI service and database layer
- `Database/` - local SQLite database files
- `Docs/` - documentation and design notes
- `Prompts/` - build prompts and AI workflow notes
- `Reports/` - generated report assets

## How to run

### Frontend
```bash
cd frontend
npm install
npm run desktop
```

### Backend
```bash
cd Backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Hackathon submission focus

This project was designed to demonstrate:

- AI-assisted cybersecurity analysis
- Clear incident explanation for non-experts
- SOC-style dashboarding and triage workflows
- Persistent analytics instead of one-off request processing
- Practical desktop usability for Windows and Linux environments

## License

No license has been added yet.

## Acknowledgements

Built for the OpenAI Build Week Hackathon using OpenAI APIs and open-source tools.
