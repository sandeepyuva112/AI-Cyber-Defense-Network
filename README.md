# AI Cyber Defense Network

### AI-powered desktop application for faster security log analysis and threat investigation

## About the Project

Security teams deal with thousands of alerts and log files every day. Reviewing them manually takes time, and important threats can easily be missed. Smaller organizations often don't have dedicated security analysts, making the problem even harder.

AI Cyber Defense Network was created to make security analysis simpler and faster. Instead of asking users to read through raw logs, the application analyzes uploaded security logs, highlights suspicious activity, explains why an event may be dangerous, and suggests possible response actions using AI.

This project was developed as a prototype during the **OpenAI Build Week Hackathon** to explore how Large Language Models can support cybersecurity workflows. The goal isn't to replace security professionals, but to help them understand incidents more quickly and make better-informed decisions.

## Why We Built It

Most security tools generate alerts, but they often expect users to already understand what those alerts mean. For beginners and small security teams, this can slow down investigations.

We wanted to build a tool that answers questions like:

* What happened?
* Why is this suspicious?
* How serious is it?
* What should I do next?

By combining traditional log analysis with AI-generated explanations, the platform helps reduce the time needed to investigate security events.

## What the Application Can Do

* Upload and analyze security log files
* Detect potentially suspicious activity
* Generate easy-to-understand AI explanations
* Prioritize threats based on risk
* Display findings through a dashboard
* Generate investigation reports
* Suggest possible mitigation steps

## Technology Stack

### Frontend

* React
* TypeScript
* Tailwind CSS
* Electron

### Backend

* Python
* FastAPI
* SQLAlchemy

### Database

* SQLite

### AI

* OpenAI API
* Large Language Models (LLMs)

## Current Status

This project is an active hackathon prototype. Core features are implemented, while additional improvements such as live monitoring, SIEM integration, and advanced analytics are planned for future development.

## Future Plans

Some ideas we would like to continue working on include:

* Real-time log monitoring
* Threat intelligence integration
* Multi-user authentication
* Cloud deployment
* Docker support
* Improved AI explanations
* More detailed reporting
* Support for additional log formats

## Acknowledgements

This project was built during the **OpenAI Build Week Hackathon** using open-source technologies together with OpenAI's APIs and developer tools.

We appreciate the communities behind Python, FastAPI, React, Electron, and all the open-source libraries that made this prototype possible.

## How to run 

cd frontend 
npm run desktop 
