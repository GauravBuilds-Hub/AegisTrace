# AegisTrace

AegisTrace is a student-focused detection engineering and threat analysis platform built with Flask and SQLite. It ingests CSV/JSON telemetry, normalizes events, runs rule-based detections, extracts IOCs, supports analyst investigation workflows, and generates evidence-based reports.

## Current capabilities

- Session-based login/register with hashed passwords
- Analyst/Admin role-based access control
- CSV and JSON telemetry upload (10 MB configured limit)
- Parsing, normalization and SQLite event storage
- 24 configured detection rules mapped to 22 MITRE ATT&CK techniques
- Detection feed, rule library, rule testing, false-positive triage and ATT&CK mapping
- IOC extraction for IPs, domains, URLs, MD5, SHA1 and SHA256 values
- IOC investigation workspace
- Two repeatable threat-hunt workflows with recorded run history
- Analyst-created incident management with detection/IOC linkage, assignment and status workflow
- Evidence workspace (does not fabricate evidence files)
- Three manual response playbooks
- Recommended-action guidance, internal blocklist workflow and action history
- Reports Center with Executive, IOC, Detection Coverage, Incident, Threat Hunt, MITRE Coverage and Methodology reports
- Admin dashboard, user roles, telemetry management, dataset deletion, user-data cleanup, telemetry purge and audit history

## Important scope notes

- AegisTrace currently accepts **CSV and JSON** telemetry. Native EVTX ingestion is not implemented.
- Detection findings are rule-based and require analyst review.
- Extracted IOCs are observed values, not automatic malicious verdicts.
- Blocklist entries and response actions are **internal workflow records only**. The application does not change the host operating system or network firewall.
- Sigma-style YAML files are included for documentation and academic review. The current web application executes equivalent Python detection logic; it is not a full generic Sigma compiler.
- The project intentionally does not create fake incidents, hunt results or evidence.

## Run the project

From PowerShell inside the project folder:

```powershell
pip install -r requirements.txt
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

The existing `aegistrace.db` is preserved. On startup, missing tables used by new features are created automatically.

## Main workflow

```text
Upload telemetry
→ Validate
→ Parse
→ Normalize
→ Store events
→ Run detections
→ Extract IOCs
→ Investigate
→ Threat hunt / create incidents
→ Response guidance
→ Reports
```

## Detection engineering

`/sigma-rules/` contains 24 Sigma-style YAML specifications. The application rule library and rule-testing pages expose the same AegisTrace rule catalog.

Current configured ATT&CK coverage is documented in:

```text
mitre/coverage.md
```

## Threat hunts

Two built-in hypotheses are included:

- HUNT-001 — Authentication Abuse Hunt
- HUNT-002 — Suspicious PowerShell Hunt

Run them from **Investigation → Threat Hunting**. A hunt result is stored only when the analyst actually runs it against the current database.

## Evidence

Use:

```text
evidence/rule-tests/
evidence/hunts/
evidence/incidents/
```

for screenshots, exported JSON, notes or other genuine project evidence.

## Admin safety

Destructive actions require explicit confirmation and preserve the SQLite database file. Telemetry purge removes telemetry-derived records but keeps user accounts.
