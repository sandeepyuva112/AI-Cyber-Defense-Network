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

- Python
- FastAPI
- SQLAlchemy
- Alembic

### Database

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