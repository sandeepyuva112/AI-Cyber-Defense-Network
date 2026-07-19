# TODO - Log Parsing Engine

- [x] Create normalized schema: `Backend/app/schemas/log_event.py`
- [x] Create parser interfaces: `Backend/app/parsers/base.py`, `Backend/app/parsers/factory.py`
- [x] Create shared parsing utilities: `Backend/app/parsers/utils.py`

- [x] Implement parsers:

  - [ ] Windows Event Logs (`windows_event_logs_parser.py`)
  - [ ] Syslog (`syslog_parser.py`)
  - [ ] JSON Logs (`json_logs_parser.py`)
  - [ ] CSV Logs (`csv_logs_parser.py`)
  - [ ] Apache Logs (`apache_logs_parser.py`)
  - [ ] Nginx Logs (`nginx_logs_parser.py`)
  - [ ] Firewall Logs (`firewall_logs_parser.py`)
- [ ] Export in `Backend/app/parsers/__init__.py`
- [x] Add unit tests: `Backend/tests/test_log_parsers.py`

- [x] Run `pytest` and fix any issues


