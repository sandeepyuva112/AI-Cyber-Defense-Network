# Backend Work Tracker (Threat Detection Engine)

- [ ] Inventory repo threat-detection related code (AI pipeline, schemas, parsing) 
- [ ] Implement deterministic Threat Detection Engine (IOC detection, behavior analysis, rule engine) under `Backend/app/detection/`
- [ ] Implement threat scoring + confidence calculation (Severity 0-100 + Confidence 0-1) 
- [x] Implement structured findings output as `AiIncidentReport`
- [x] Integrate into `Backend/app/ai/service.py` using approved integration option
- [x] Add unit tests for detectors, scoring, and schema conformance
- [x] Run `pytest` and fix failures


