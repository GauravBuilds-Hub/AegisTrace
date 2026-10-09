# Final Test Checklist

## Validated in the consolidated build

- Python syntax compilation for `app.py` and `database.py`
- Database initialization with existing database preserved
- Jinja template syntax for all HTML templates
- Route endpoint references in templates
- GET rendering for Overview, Telemetry, Detection, Investigation, Response, Reports and Admin pages
- Rule Testing POST using a sample Event ID 4625 event
- Threat Hunt run POST workflow
- Incident creation POST workflow
- Internal blocklist POST workflow

## Before final submission

Use the real project in your local environment and capture genuine evidence:

- Upload at least one representative telemetry file
- Run HUNT-001 and HUNT-002
- Review detections and mark any genuine false positives
- Create incident records only for findings you can justify
- Export two incident reports only after analyst confirmation
- Save screenshots/notes under `evidence/`
- Export final reports to PDF if required by your course
