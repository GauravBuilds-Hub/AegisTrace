# AegisTrace — Project Structure

```text
AegisTrace/
├── app.py
├── database.py
├── aegistrace.db
├── requirements.txt
├── README.md
├── PROJECT_STRUCTURE.md
├── templates/
│   ├── auth/
│   ├── layout/
│   │   └── base.html
│   ├── pages/
│   │   ├── overview.html
│   │   ├── detection_*.html
│   │   ├── investigation_*.html
│   │   ├── response_*.html
│   │   ├── reports.html
│   │   ├── *_report.html
│   │   └── admin_*.html
│   └── components/
├── static/
│   ├── css/
│   │   ├── aegistrace.css
│   │   ├── telemetry.css
│   │   ├── admin.css
│   │   ├── response.css
│   │   ├── report.css
│   │   ├── account.css
│   │   ├── auth.css
│   │   └── workspace.css
│   ├── js/
│   └── img/
├── data/
│   ├── raw/
│   └── processed/
├── data-dictionary/
│   └── README.md
├── sigma-rules/
│   ├── README.md
│   └── 24 rule YAML files
├── mitre/
│   └── coverage.md
├── threat-hunts/
│   ├── HUNT-001-authentication-abuse.md
│   └── HUNT-002-suspicious-powershell.md
├── playbooks/
│   ├── PB-001-brute-force-response.md
│   ├── PB-002-suspicious-powershell-response.md
│   └── PB-003-ioc-investigation-containment.md
├── evidence/
│   ├── rule-tests/
│   ├── hunts/
│   └── incidents/
├── incidents/
├── ioc-research/
├── reports/
├── presentation/
└── instance/
```

## SQLite tables

The application maintains:

- `users`
- `telemetry_uploads`
- `events`
- `detections`
- `iocs`
- `incidents`
- `threat_hunt_runs`
- `response_blocklist`
- `response_actions`
- `admin_audit_log`

Database initialization is migration-friendly: missing tables/columns are created without deleting the existing database.
