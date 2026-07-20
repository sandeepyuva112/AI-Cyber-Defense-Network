<<<<<<< HEAD
#  AI Cyber Defense Network

An AI-powered desktop application that helps security analysts investigate cyber threats faster by turning raw security logs into understandable insights.

Built for the **OpenAI Build Week Hackathon**, this project combines traditional log analysis with AI to reduce investigation time and make cybersecurity more accessible for both experienced analysts and beginners.

---

#  About the Project

Modern systems generate thousands of security events every day. Finding the few that actually matter is difficult, time-consuming, and often overwhelming.

AI Cyber Defense Network was created to simplify that process.

Instead of manually reading through large log files, users can upload their logs and let the application automatically identify suspicious activity, explain what happened, estimate the severity of the threat, and recommend possible response actions.

The goal isn't to replace security analysts. It's to help them investigate incidents more quickly and make better-informed decisions.

---

#  What the Application Can Do

- Upload Windows Event Logs, JSON, CSV, and other supported log formats
- Automatically parse and normalize security events
- Detect suspicious activities and potential attacks
- Correlate related threats into incidents
- Extract Indicators of Compromise (IOCs)
- Map detected techniques to the MITRE ATT&CK framework
- Generate AI-powered explanations in plain English
- Display investigation results through an interactive SOC dashboard
- Create downloadable incident reports

---

#  Main Features

###  Security Dashboard

A central dashboard that gives analysts a quick overview of the current security posture.

It includes:

- Total alerts
- Active incidents
- Risk score
- AI analyses
- Incident timeline
- Risk distribution
- Recent activity
- AI security assistant

---

###  Live Monitor

View parsed security events in real time.

Features include:

- Auto-refresh
- Event filtering
- Search
- Severity labels
- Process and IP visibility

---

###  Log Upload

Upload security logs directly into the platform.

Supported formats include:

- Windows Event Logs (.evtx)
- JSON
- CSV
- Syslog

The application automatically selects the correct parser and stores uploaded logs for future investigation.

---

###  Threat Explorer

Browse detected threats and investigate them in detail.

Each investigation includes:

- Threat classification
- Severity
- Confidence score
- Detection time
- AI-generated explanation
- Recommended mitigation
- MITRE ATT&CK mapping
- Extracted IOCs

---

###  IOC Registry

All extracted indicators are stored in one place.

Supported IOC types include:

- IP addresses
- Domains
- URLs
- SHA256 hashes
- MD5 hashes
- File names

Everything can be searched and filtered for faster investigations.

---

###  MITRE ATT&CK Mapping

Detected attacks are automatically mapped to the MITRE ATT&CK framework, helping analysts understand attacker behavior and tactics.

---

###  Alert Management

Manage alerts throughout their lifecycle.

Available states include:

- Open
- Investigating
- Resolved
- Closed

Alerts can be filtered by severity and searched by category.

---

###  AI Security Assistant

One of the core features of the project.

The assistant uses OpenAI to:

- Explain security events
- Summarize incidents
- Recommend response actions
- Prioritize threats
- Generate investigation summaries

Instead of reading technical logs, analysts receive clear explanations written in natural language.

---

###  Incident Reports

Generate investigation reports that can be shared with security teams or management.

Available export formats include:

- PDF
- HTML
- JSON

---

#  How It Works

```
Upload Log
      │
      ▼
Parse & Normalize
      │
      ▼
Threat Detection
      │
      ▼
Extract IOCs
      │
      ▼
AI Analysis
      │
      ▼
MITRE ATT&CK Mapping
      │
      ▼
Store Results
      │
      ▼
Dashboard • Alerts • Reports
```

---

#  Tech Stack

### Frontend

- React
- TypeScript
- Electron
- Tailwind CSS

### Backend

=======
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
>>>>>>> f4efa2a348a8b8fe9c990c655fac2d2e10538751
- Python
- FastAPI
- SQLAlchemy
- Alembic

### Database
<<<<<<< HEAD

- SQLite

### AI

- OpenAI Responses API

---

#  Getting Started

Clone the repository

```bash
git clone https://github.com/sandeepyuva112/AI-Cyber-Defense-Network.git
```

Run the frontend

```bash
cd frontend

npm install

npm run desktop
```

Run the backend

```bash
cd Backend

pip install -r requirements.txt

uvicorn app.main:app --reload
```

---

#  Future Improvements

Although the current version is a working prototype, there are several features planned for future development.

- Live SIEM integration
- Threat intelligence feeds
- Multi-user authentication
- Docker deployment
- Cloud synchronization
- Additional log parsers
- Advanced AI-assisted investigations

---

#  Acknowledgements

This project was developed during the **OpenAI Build Week Hackathon**.

It was built using OpenAI APIs together with open-source technologies including Python, FastAPI, React, Electron, SQLAlchemy, SQLite, and Tailwind CSS.

A big thank you to the OpenAI team and the open-source community for providing the tools that made this project possible.
=======
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
>>>>>>> f4efa2a348a8b8fe9c990c655fac2d2e10538751
