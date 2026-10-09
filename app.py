import csv
import ipaddress
import json
import re
import sqlite3
import os

from functools import wraps

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

from flask import (
    Flask,
    render_template,
    request,
    session,
    redirect,
    url_for,
    flash,
    abort,
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)

from werkzeug.utils import secure_filename

from database import (
    get_connection,
    create_database,
)


# =========================================================
# APP
# =========================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "aegistrace-local-development-key"
)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024


# =========================================================
# DATABASE
# =========================================================

create_database()


# =========================================================
# PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent

UPLOAD_FOLDER = BASE_DIR / "data" / "raw"
PROCESSED_FOLDER = BASE_DIR / "data" / "processed"

UPLOAD_FOLDER.mkdir(
    parents=True,
    exist_ok=True
)

PROCESSED_FOLDER.mkdir(
    parents=True,
    exist_ok=True
)


ALLOWED_EXTENSIONS = {
    "csv",
    "json",
}


# =========================================================
# NORMALIZED SCHEMA
# =========================================================

STANDARD_SCHEMA = [
    "timestamp",
    "event_id",
    "host",
    "user",
    "source_ip",
    "destination_ip",
    "process_name",
    "command_line",
    "event_type",
    "url",
    "domain",
    "hash",
    "raw_event",
]


FIELD_ALIASES = {

    "timestamp": [
        "timestamp",
        "time",
        "event_time",
        "eventtime",
        "timecreated",
        "@timestamp",
        "datetime",
        "created_at",
    ],

    "event_id": [
        "event_id",
        "eventid",
        "event id",
    ],

    "host": [
        "host",
        "hostname",
        "computer",
        "computername",
        "device",
        "device_name",
    ],

    "user": [
        "user",
        "username",
        "user_name",
        "account",
        "account_name",
        "subjectusername",
    ],

    "source_ip": [
        "source_ip",
        "src_ip",
        "srcip",
        "sourceip",
        "client_ip",
        "sourceaddress",
    ],

    "destination_ip": [
        "destination_ip",
        "dst_ip",
        "dest_ip",
        "dstip",
        "destinationip",
        "server_ip",
        "destinationaddress",
    ],

    "process_name": [
        "process_name",
        "process",
        "processname",
        "image",
        "application",
        "executable",
    ],

    "command_line": [
        "command_line",
        "commandline",
        "cmdline",
        "process_command_line",
        "command",
    ],

    "event_type": [
        "event_type",
        "eventtype",
        "event_name",
        "action",
        "category",
        "type",
    ],

    "url": [
        "url",
        "uri",
        "request_url",
        "requesturl",
    ],

    "domain": [
        "domain",
        "remote_domain",
        "destination_domain",
    ],

    "hash": [
        "hash",
        "md5",
        "sha1",
        "sha256",
        "file_hash",
        "filehash",
    ],
}


def field_token(field_name):

    return "".join(
        character
        for character in str(field_name).lower()
        if character.isalnum()
    )


FIELD_LOOKUP = {}

for standard_field, aliases in FIELD_ALIASES.items():

    for alias in aliases:

        FIELD_LOOKUP[
            field_token(alias)
        ] = standard_field

    FIELD_LOOKUP[
        field_token(standard_field)
    ] = standard_field

# =========================================================
# DETECTION RULE CATALOG
# =========================================================

DETECTION_RULE_CATALOG = [
    {"rule_id": "AT-WIN-001", "name": "Windows Failed Logon", "severity": "Medium", "mitre": "T1110", "technique": "Brute Force", "category": "Authentication"},
    {"rule_id": "AT-AUTH-002", "name": "Possible Brute Force Attempt", "severity": "High", "mitre": "T1110", "technique": "Brute Force", "category": "Authentication"},
    {"rule_id": "AT-PS-001", "name": "Suspicious Encoded PowerShell", "severity": "High", "mitre": "T1059.001", "technique": "PowerShell", "category": "Execution"},
    {"rule_id": "AT-WIN-002", "name": "Windows Audit Log Cleared", "severity": "High", "mitre": "T1070.001", "technique": "Clear Windows Event Logs", "category": "Defense Evasion"},
    {"rule_id": "AT-WIN-003", "name": "Local User Account Created", "severity": "Medium", "mitre": "T1136.001", "technique": "Local Account", "category": "Persistence"},
    {"rule_id": "AT-WIN-004", "name": "User Added to Privileged Group", "severity": "High", "mitre": "T1098", "technique": "Account Manipulation", "category": "Persistence"},
    {"rule_id": "AT-WIN-005", "name": "Windows Service Installed", "severity": "High", "mitre": "T1543.003", "technique": "Windows Service", "category": "Persistence"},
    {"rule_id": "AT-WIN-006", "name": "Scheduled Task Created", "severity": "Medium", "mitre": "T1053.005", "technique": "Scheduled Task", "category": "Persistence"},
    {"rule_id": "AT-LOL-001", "name": "Certutil Download Activity", "severity": "High", "mitre": "T1105", "technique": "Ingress Tool Transfer", "category": "Command and Control"},
    {"rule_id": "AT-LOL-002", "name": "Suspicious Rundll32 Execution", "severity": "High", "mitre": "T1218.011", "technique": "Rundll32", "category": "Defense Evasion"},
    {"rule_id": "AT-LOL-003", "name": "Regsvr32 Remote Scriptlet", "severity": "High", "mitre": "T1218.010", "technique": "Regsvr32", "category": "Defense Evasion"},
    {"rule_id": "AT-LOL-004", "name": "MSHTA Remote Content", "severity": "High", "mitre": "T1218.005", "technique": "Mshta", "category": "Defense Evasion"},
    {"rule_id": "AT-LOL-005", "name": "BITSAdmin Transfer", "severity": "Medium", "mitre": "T1197", "technique": "BITS Jobs", "category": "Persistence"},
    {"rule_id": "AT-DEF-001", "name": "Shadow Copy Deletion", "severity": "High", "mitre": "T1490", "technique": "Inhibit System Recovery", "category": "Impact"},
    {"rule_id": "AT-DEF-002", "name": "Command-line Event Log Clear", "severity": "High", "mitre": "T1070.001", "technique": "Clear Windows Event Logs", "category": "Defense Evasion"},
    {"rule_id": "AT-DISC-001", "name": "Account Discovery", "severity": "Low", "mitre": "T1087.001", "technique": "Local Account Discovery", "category": "Discovery"},
    {"rule_id": "AT-DISC-002", "name": "Process Discovery", "severity": "Low", "mitre": "T1057", "technique": "Process Discovery", "category": "Discovery"},
    {"rule_id": "AT-DISC-003", "name": "Network Configuration Discovery", "severity": "Low", "mitre": "T1016", "technique": "System Network Configuration Discovery", "category": "Discovery"},
    {"rule_id": "AT-DISC-004", "name": "System Information Discovery", "severity": "Low", "mitre": "T1082", "technique": "System Information Discovery", "category": "Discovery"},
    {"rule_id": "AT-CRED-001", "name": "LSASS Credential Dump Indicator", "severity": "Critical", "mitre": "T1003.001", "technique": "LSASS Memory", "category": "Credential Access"},
    {"rule_id": "AT-SCRIPT-001", "name": "Suspicious Windows Script Host", "severity": "Medium", "mitre": "T1059.005", "technique": "Visual Basic", "category": "Execution"},
    {"rule_id": "AT-CMD-001", "name": "Suspicious Windows Command Shell", "severity": "Medium", "mitre": "T1059.003", "technique": "Windows Command Shell", "category": "Execution"},
    {"rule_id": "AT-PERSIST-001", "name": "Registry Run Key Modification", "severity": "High", "mitre": "T1060", "technique": "Registry Run Keys / Startup Folder", "category": "Persistence"},
    {"rule_id": "AT-NET-001", "name": "Remote Desktop Activity", "severity": "Medium", "mitre": "T1021.001", "technique": "Remote Desktop Protocol", "category": "Lateral Movement"},
]

MITRE_TECHNIQUE_CATALOG = []
_seen_mitre = set()
for _rule in DETECTION_RULE_CATALOG:
    if _rule["mitre"] not in _seen_mitre:
        _seen_mitre.add(_rule["mitre"])
        MITRE_TECHNIQUE_CATALOG.append({
            "id": _rule["mitre"],
            "name": _rule["technique"],
            "category": _rule["category"],
        })


# =========================================================
# BUILT-IN THREAT HUNTS
# =========================================================

THREAT_HUNTS = [
    {
        "id": "HUNT-001",
        "title": "Authentication Abuse Hunt",
        "hypothesis": "Repeated authentication failures may indicate password guessing or brute-force activity.",
        "method": "Review failed-logon detections and grouped source/user authentication failures.",
        "mitre": "T1110",
    },
    {
        "id": "HUNT-002",
        "title": "Suspicious PowerShell Hunt",
        "hypothesis": "Encoded or obfuscated PowerShell activity may indicate malicious script execution.",
        "method": "Review PowerShell detections and command lines containing encoded execution indicators.",
        "mitre": "T1059.001",
    },
]


def detection_rule(rule_id):
    for rule in DETECTION_RULE_CATALOG:
        if rule["rule_id"] == rule_id:
            return rule
    return None


def event_search_text(event):
    values = []
    for key in [
        "event_id", "host", "user", "source_ip", "destination_ip",
        "process_name", "command_line", "event_type", "url", "domain",
        "hash", "raw_event"
    ]:
        value = event.get(key)
        if isinstance(value, (dict, list)):
            value = json.dumps(value, default=str)
        values.append(str(value or ""))
    return " ".join(values).lower()


def contains_all(text, terms):
    return all(term.lower() in text for term in terms)


def contains_any(text, terms):
    return any(term.lower() in text for term in terms)


# =========================================================
# LOGIN ACCESS CONTROL
# =========================================================

def login_required(view_function):

    @wraps(view_function)
    def wrapped_view(*args, **kwargs):

        if "user_id" not in session:

            return redirect(
                url_for("login")
            )

        return view_function(
            *args,
            **kwargs
        )

    return wrapped_view


# =========================================================
# RESPONSE - PLAYBOOKS
# =========================================================

@app.route("/response/playbooks")
def response_playbooks():

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    playbooks = [

        {
            "id": "PB-001",

            "title":
                "Brute Force Response",

            "severity":
                "High",

            "trigger":
                "Repeated failed authentication attempts "
                "or AT-AUTH-002 detection.",

            "mitre":
                "T1110",

            "steps": [
                "Review failed authentication events.",
                "Identify the affected user account.",
                "Identify the source IP address.",
                "Check whether the source IP appears across other users or hosts.",
                "Review successful logins following the failed attempts.",
                "Validate whether the activity is expected.",
                "If malicious, recommend account protection and source blocking.",
                "Document evidence and create an incident when escalation is required.",
            ],
        },


        {
            "id": "PB-002",

            "title":
                "Suspicious PowerShell Response",

            "severity":
                "High",

            "trigger":
                "Encoded or suspicious PowerShell command "
                "or AT-PS-001 detection.",

            "mitre":
                "T1059.001",

            "steps": [
                "Review the complete PowerShell command line.",
                "Identify the host and user that executed the process.",
                "Inspect encoded-command indicators.",
                "Review nearby process and authentication events.",
                "Extract URLs, domains, IP addresses or hashes from the command.",
                "Check whether related IOCs appear elsewhere in telemetry.",
                "Recommend process isolation or endpoint investigation when required.",
                "Preserve relevant evidence and create an incident for confirmed suspicious activity.",
            ],
        },


        {
            "id": "PB-003",

            "title":
                "IOC Investigation and Containment",

            "severity":
                "Medium",

            "trigger":
                "Suspicious IP, domain, URL or file hash "
                "identified during telemetry analysis.",

            "mitre":
                "IOC Triage",

            "steps": [
                "Identify the IOC type and original source event.",
                "Review the associated host and user.",
                "Search all telemetry for additional occurrences.",
                "Check related source and destination network activity.",
                "Review associated processes and command lines.",
                "Determine whether the indicator is expected, unknown or suspicious.",
                "Recommend blocking or containment only after analyst confirmation.",
                "Record the evidence and escalate to an incident when necessary.",
            ],
        },

    ]

    return render_template(

        "pages/playbooks.html",

        module=
            MODULES["response"],

        active_module=
            "response",

        playbooks=
            playbooks,
    )

# =========================================================
# REPORTS - MAIN DASHBOARD
# =========================================================

@app.route("/reports/dashboard")
@login_required
def reports_dashboard():

    connection = get_connection()

    total_uploads = connection.execute("""
        SELECT COUNT(*)
        FROM telemetry_uploads
    """).fetchone()[0]

    total_events = connection.execute("""
        SELECT COUNT(*)
        FROM events
    """).fetchone()[0]

    total_detections = connection.execute("""
        SELECT COUNT(*)
        FROM detections
    """).fetchone()[0]

    total_iocs = connection.execute("""
        SELECT COUNT(*)
        FROM iocs
    """).fetchone()[0]

    total_incidents = connection.execute("""
        SELECT COUNT(*)
        FROM incidents
    """).fetchone()[0]

    connection.close()


    reports = [

        {
            "title": "Incident Report",
            "description":
                "Summarize incident details, severity, evidence and response activity.",
            "status":
                "Ready" if total_incidents > 0 else "Awaiting Incidents",
        },

        {
            "title": "Threat Hunt Report",
            "description":
                "Document hunt hypotheses, analysis methods, evidence and conclusions.",
            "status": "Ready",
        },

        {
            "title": "IOC Intelligence Report",
            "description":
                "Summarize extracted IPs, domains, URLs and file hashes.",
            "status":
                "Ready" if total_iocs > 0 else "Awaiting IOCs",
        },

        {
            "title": "Detection Coverage Report",
            "description":
                "Summarize detection rules, triggered findings and security coverage.",
            "status":
                "Ready" if total_detections > 0 else "Awaiting Detections",
        },

        {
            "title": "MITRE Coverage Report",
            "description":
                "Map configured detection capabilities against MITRE ATT&CK techniques.",
            "status": "Ready",
        },

        {
            "title": "Methodology Report",
            "description":
                "Explain the AegisTrace telemetry, detection and investigation methodology.",
            "status": "Ready",
        },

        {
            "title": "Executive Summary",
            "description":
                "Provide a high-level summary of security analysis and findings.",
            "status":
                "Ready" if total_uploads > 0 else "Awaiting Data",
        },
    ]


    return render_template(
        "pages/reports.html",

        module=MODULES["reports"],

        active_module="reports",

        reports=reports,

        total_uploads=total_uploads,

        total_events=total_events,

        total_detections=total_detections,

        total_iocs=total_iocs,

        total_incidents=total_incidents,
    )

# =========================================================
# REPORTS - EXECUTIVE SUMMARY
# =========================================================

@app.route("/reports/executive-summary")
@login_required
def reports_executive_summary():

    connection = get_connection()

    total_uploads = connection.execute("""
        SELECT COUNT(*)
        FROM telemetry_uploads
    """).fetchone()[0]

    total_events = connection.execute("""
        SELECT COUNT(*)
        FROM events
    """).fetchone()[0]

    total_detections = connection.execute("""
        SELECT COUNT(*)
        FROM detections
    """).fetchone()[0]

    total_iocs = connection.execute("""
        SELECT COUNT(*)
        FROM iocs
    """).fetchone()[0]

    total_incidents = connection.execute("""
        SELECT COUNT(*)
        FROM incidents
    """).fetchone()[0]

    severity_counts = connection.execute("""
        SELECT

            SUM(
                CASE
                    WHEN LOWER(severity) = 'critical'
                    THEN 1
                    ELSE 0
                END
            ) AS critical_count,

            SUM(
                CASE
                    WHEN LOWER(severity) = 'high'
                    THEN 1
                    ELSE 0
                END
            ) AS high_count,

            SUM(
                CASE
                    WHEN LOWER(severity) = 'medium'
                    THEN 1
                    ELSE 0
                END
            ) AS medium_count,

            SUM(
                CASE
                    WHEN LOWER(severity) = 'low'
                    THEN 1
                    ELSE 0
                END
            ) AS low_count

        FROM detections
    """).fetchone()

    critical_detections = (
        severity_counts["critical_count"]
        or 0
    )

    high_detections = (
        severity_counts["high_count"]
        or 0
    )

    medium_detections = (
        severity_counts["medium_count"]
        or 0
    )

    low_detections = (
        severity_counts["low_count"]
        or 0
    )

    open_incidents = connection.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE status != 'Closed'
    """).fetchone()[0]

    top_detection_rules = connection.execute("""
        SELECT

            rule_id,
            rule_name,
            severity,
            mitre_technique,
            COUNT(*) AS match_count

        FROM detections

        GROUP BY
            rule_id,
            rule_name,
            severity,
            mitre_technique

        ORDER BY
            match_count DESC,
            rule_name ASC

        LIMIT 5
    """).fetchall()

    top_ioc_types = connection.execute("""
        SELECT

            ioc_type,
            COUNT(*) AS ioc_count

        FROM iocs

        GROUP BY ioc_type

        ORDER BY
            ioc_count DESC,
            ioc_type ASC

        LIMIT 5
    """).fetchall()

    latest_upload = connection.execute("""
        SELECT

            original_name,
            file_type,
            uploaded_at,
            status,
            normalization_status,
            event_count,
            detection_count,
            ioc_count

        FROM telemetry_uploads

        ORDER BY id DESC

        LIMIT 1
    """).fetchone()

    connection.close()

    if critical_detections > 0:

        highest_severity = "Critical"

    elif high_detections > 0:

        highest_severity = "High"

    elif medium_detections > 0:

        highest_severity = "Medium"

    elif low_detections > 0:

        highest_severity = "Low"

    else:

        highest_severity = "No Findings"

    if total_uploads == 0:

        summary_text = (
            "No telemetry has been analyzed yet. "
            "Upload a CSV or JSON security dataset to "
            "generate an evidence-based executive summary."
        )

    elif total_detections == 0:

        summary_text = (
            f"AegisTrace processed {total_events} events "
            f"from {total_uploads} dataset(s). "
            "No configured detection rules produced findings "
            "in the currently stored telemetry."
        )

    else:

        summary_text = (
            f"AegisTrace processed {total_events} events "
            f"from {total_uploads} dataset(s) and generated "
            f"{total_detections} detection finding(s). "
            f"The highest observed detection severity is "
            f"{highest_severity}. "
            f"{total_iocs} indicator(s) of compromise were "
            f"extracted from the analyzed telemetry."
        )

    generated_at = datetime.now(
        timezone.utc
    ).strftime(
        "%d %B %Y, %H:%M UTC"
    )

    return render_template(

        "pages/executive_summary.html",

        module=MODULES["reports"],

        active_module="reports",

        total_uploads=total_uploads,

        total_events=total_events,

        total_detections=total_detections,

        total_iocs=total_iocs,

        total_incidents=total_incidents,

        open_incidents=open_incidents,

        critical_detections=critical_detections,

        high_detections=high_detections,

        medium_detections=medium_detections,

        low_detections=low_detections,

        highest_severity=highest_severity,

        summary_text=summary_text,

        top_detection_rules=top_detection_rules,

        top_ioc_types=top_ioc_types,

        latest_upload=latest_upload,

        generated_at=generated_at,
    )


# =========================================================
# MODULES
# =========================================================

MODULES = {

    "overview": {

        "title":
            "Security Operations Overview",

        "short":
            "Overview",

        "description":
            "Security posture, recent findings, "
            "activity and operational status.",

        "context": [
            "Security Posture",
            "Detection Activity",
            "Recent Findings",
            "SOC Activity",
        ],
    },


    "telemetry": {

        "title":
            "Telemetry",

        "short":
            "Telemetry",

        "description":
            "Ingest, inspect and organize "
            "security logs and entities.",

        "context": [
            "Upload Logs",
            "Parsed Events",
            "Hosts",
            "Users",
            "Processes",
            "Network",
        ],
    },


    "detection": {

        "title":
            "Detection",

        "short":
            "Detection",

        "description":
            "Detection feed, Sigma rules, "
            "rule testing and ATT&CK coverage.",

        "context": [
            "Detection Feed",
            "Sigma Rules",
            "Rule Testing",
            "False Positives",
            "MITRE ATT&CK",
            "Coverage",
        ],
    },


    "investigation": {

        "title":
            "Investigation",

        "short":
            "Investigation",

        "description":
            "IOC intelligence, threat hunts, "
            "incidents and evidence.",

        "context": [
            "IOC Intelligence",
            "Threat Hunting",
            "Incidents",
            "Evidence",
        ],
    },


    "response": {

        "title":
            "Response",

        "short":
            "Response",

        "description":
            "Recommended actions, blocklist, "
            "playbooks and response history.",

        "context": [
            "Recommended Actions",
            "Blocklist",
            "Playbooks",
            "Action History",
        ],
    },


    "reports": {

        "title":
            "Reports",

        "short":
            "Reports",

        "description":
            "Incident, hunt, IOC, coverage, "
            "methodology and executive reports.",

        "context": [
            "Incident Reports",
            "Threat Hunt Reports",
            "IOC Reports",
            "Coverage Reports",
            "Methodology",
            "Executive Summary",
        ],
    },
}
ADMIN_MODULE = {

    "title":
        "Administration",

    "description":
        "Manage AegisTrace users, telemetry data "
        "and administrative activity.",

    "context": [
        "Dashboard",
        "User Management",
        "Telemetry Management",
        "Audit History",
    ],
}
# =========================================================
# FILE VALIDATION
# =========================================================

def allowed_file(filename):

    if "." not in filename:

        return False

    extension = (
        filename
        .rsplit(".", 1)[1]
        .lower()
    )

    return extension in ALLOWED_EXTENSIONS


# =========================================================
# CSV
# =========================================================

def parse_csv_file(file_path):

    preview = []
    fields = []
    event_count = 0

    with open(
        file_path,
        "r",
        encoding="utf-8-sig",
        errors="replace",
        newline=""
    ) as file:

        reader = csv.DictReader(file)

        if reader.fieldnames:

            fields = [
                field.strip()
                if field
                else "unknown"

                for field in reader.fieldnames
            ]

        for row in reader:

            event_count += 1

            if len(preview) < 5:

                preview.append(
                    dict(row)
                )

    return {
        "event_count": event_count,
        "fields": fields,
        "preview": preview,
    }


# =========================================================
# JSON
# =========================================================

def parse_json_file(file_path):

    with open(
        file_path,
        "r",
        encoding="utf-8-sig",
        errors="replace"
    ) as file:

        data = json.load(file)

    events = []

    if isinstance(
        data,
        list
    ):

        events = data

    elif isinstance(
        data,
        dict
    ):

        for key in [
            "events",
            "records",
            "data",
            "logs",
        ]:

            if (
                key in data
                and isinstance(
                    data[key],
                    list
                )
            ):

                events = data[key]
                break

        if not events:

            events = [data]

    else:

        raise ValueError(
            "Unsupported JSON structure."
        )

    fields = []

    for event in events[:100]:

        if isinstance(
            event,
            dict
        ):

            for field in event.keys():

                if field not in fields:

                    fields.append(
                        field
                    )

    preview = []

    for event in events[:5]:

        if isinstance(
            event,
            dict
        ):

            preview.append(
                event
            )

        else:

            preview.append({
                "value": str(event)
            })

    return {
        "event_count": len(events),
        "fields": fields,
        "preview": preview,
    }


def parse_telemetry_file(
    file_path,
    extension
):

    if extension == "csv":

        return parse_csv_file(
            file_path
        )

    if extension == "json":

        return parse_json_file(
            file_path
        )

    raise ValueError(
        "Unsupported telemetry type."
    )


# =========================================================
# LOAD EVENTS
# =========================================================

def load_csv_events(file_path):

    events = []

    with open(
        file_path,
        "r",
        encoding="utf-8-sig",
        errors="replace",
        newline=""
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:

            events.append(
                dict(row)
            )

    return events


def load_json_events(file_path):

    with open(
        file_path,
        "r",
        encoding="utf-8-sig",
        errors="replace"
    ) as file:

        data = json.load(file)

    if isinstance(
        data,
        list
    ):

        return data

    if isinstance(
        data,
        dict
    ):

        for key in [
            "events",
            "records",
            "data",
            "logs",
        ]:

            if (
                key in data
                and isinstance(
                    data[key],
                    list
                )
            ):

                return data[key]

        return [data]

    raise ValueError(
        "Unsupported JSON structure."
    )


def load_events_for_normalization(
    file_path,
    extension
):

    if extension == "csv":

        return load_csv_events(
            file_path
        )

    if extension == "json":

        return load_json_events(
            file_path
        )

    raise ValueError(
        "Unsupported telemetry type."
    )


# =========================================================
# NORMALIZATION
# =========================================================

def normalize_event(event):

    if not isinstance(
        event,
        dict
    ):

        event = {
            "value": str(event)
        }

    normalized = {

        "timestamp": None,

        "event_id": None,

        "host": None,

        "user": None,

        "source_ip": None,

        "destination_ip": None,

        "process_name": None,

        "command_line": None,

        "event_type": None,

        "url": None,

        "domain": None,

        "hash": None,
    }

    for original_field, value in event.items():

        token = field_token(
            original_field
        )

        standard_field = FIELD_LOOKUP.get(
            token
        )

        if standard_field:

            current_value = normalized[
                standard_field
            ]

            if (
                current_value is None
                or current_value == ""
            ):

                normalized[
                    standard_field
                ] = value

    normalized[
        "raw_event"
    ] = event

    return normalized


def normalize_telemetry_file(
    file_path,
    extension,
    original_name,
    stored_name
):

    events = load_events_for_normalization(
        file_path,
        extension
    )

    normalized_events = [

        normalize_event(
            event
        )

        for event in events
    ]

    normalized_name = (
        f"{Path(stored_name).stem}"
        ".normalized.json"
    )

    normalized_path = (
        PROCESSED_FOLDER
        / normalized_name
    )

    payload = {

        "schema_version":
            "1.0",

        "source_file":
            original_name,

        "normalized_at":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "event_count":
            len(
                normalized_events
            ),

        "fields":
            STANDARD_SCHEMA,

        "events":
            normalized_events,
    }

    with open(
        normalized_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            payload,
            file,
            indent=2,
            ensure_ascii=False,
            default=str
        )

    return {

        "normalized_name":
            normalized_name,

        "event_count":
            len(
                normalized_events
            ),

        "fields":
            STANDARD_SCHEMA,

        "preview":
            normalized_events[:5],

        "events":
            normalized_events,
    }


# =========================================================
# SAVE EVENTS
# =========================================================

def save_normalized_events(
    upload_id,
    user_id,
    events
):

    connection = get_connection()

    try:

        for event in events:

            connection.execute("""
            INSERT INTO events
            (
                upload_id,
                user_id,
                timestamp,
                event_id,
                host,
                username,
                source_ip,
                destination_ip,
                process_name,
                command_line,
                event_type,
                url,
                domain,
                hash_value,
                raw_event_json
            )

            VALUES (
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?
            )
            """, (

                upload_id,

                user_id,

                event.get(
                    "timestamp"
                ),

                event.get(
                    "event_id"
                ),

                event.get(
                    "host"
                ),

                event.get(
                    "user"
                ),

                event.get(
                    "source_ip"
                ),

                event.get(
                    "destination_ip"
                ),

                event.get(
                    "process_name"
                ),

                event.get(
                    "command_line"
                ),

                event.get(
                    "event_type"
                ),

                event.get(
                    "url"
                ),

                event.get(
                    "domain"
                ),

                event.get(
                    "hash"
                ),

                json.dumps(
                    event.get(
                        "raw_event"
                    ),
                    default=str
                ),

            ))

        connection.commit()

    except Exception:

        connection.rollback()
        raise

    finally:

        connection.close()


# =========================================================
# DETECTION ENGINE
# =========================================================

def create_detection(
    rule_id,
    rule_name,
    severity,
    description,
    mitre_technique,
    event
):

    return {

        "rule_id":
            rule_id,

        "rule_name":
            rule_name,

        "severity":
            severity,

        "description":
            description,

        "mitre_technique":
            mitre_technique,

        "host":
            event.get(
                "host"
            ),

        "user":
            event.get(
                "user"
            ),

        "source_ip":
            event.get(
                "source_ip"
            ),

        "event_id":
            event.get(
                "event_id"
            ),

        "event":
            event,
    }


def run_detection_engine(events):

    detections = []
    failed_login_groups = defaultdict(list)

    def emit(rule_id, event, description):
        rule = detection_rule(rule_id)
        if rule is None:
            return
        detections.append(
            create_detection(
                rule["rule_id"],
                rule["name"],
                rule["severity"],
                description,
                rule["mitre"],
                event,
            )
        )

    for event in events:

        if not isinstance(event, dict):
            continue

        event_id = str(event.get("event_id") or "").strip()
        process_name = str(event.get("process_name") or "").lower()
        command_line = str(event.get("command_line") or "").lower()
        source_ip = str(event.get("source_ip") or "").strip()
        username = str(event.get("user") or "").strip()
        text = event_search_text(event)

        # AT-WIN-001 - Windows failed logon
        if event_id == "4625":
            emit(
                "AT-WIN-001",
                event,
                "Windows Event ID 4625 indicates a failed authentication attempt.",
            )
            failed_login_groups[(source_ip, username)].append(event)

        # AT-PS-001 - Encoded PowerShell
        powershell_process = (
            "powershell" in process_name
            or "pwsh" in process_name
            or "powershell" in command_line
            or "pwsh" in command_line
        )
        encoded_command = contains_any(
            command_line,
            ["-enc", "-encodedcommand", "frombase64string", "-e "]
        )
        if powershell_process and encoded_command:
            emit(
                "AT-PS-001",
                event,
                "PowerShell executed with encoded or base64-related command-line content.",
            )

        # AT-WIN-002 - Event log cleared
        if event_id == "1102":
            emit(
                "AT-WIN-002",
                event,
                "Windows Event ID 1102 indicates the audit log was cleared.",
            )

        # AT-WIN-003 - Local user account created
        if event_id == "4720":
            emit(
                "AT-WIN-003",
                event,
                "Windows Event ID 4720 indicates that a user account was created.",
            )

        # AT-WIN-004 - Privileged group membership change
        if event_id in {"4728", "4732", "4756"}:
            emit(
                "AT-WIN-004",
                event,
                "A Windows group-membership event indicates that an account was added to a security group.",
            )

        # AT-WIN-005 - Service installation
        if event_id in {"7045", "4697"}:
            emit(
                "AT-WIN-005",
                event,
                "A Windows service-installation event was observed.",
            )

        # AT-WIN-006 - Scheduled task creation
        if event_id == "4698" or (
            "schtasks" in text and "/create" in text
        ):
            emit(
                "AT-WIN-006",
                event,
                "Scheduled task creation activity was observed.",
            )

        # AT-LOL-001 - Certutil download
        if "certutil" in text and (
            contains_any(text, ["urlcache", "http://", "https://", "-split"])
        ):
            emit(
                "AT-LOL-001",
                event,
                "Certutil was used with download or URL-cache related arguments.",
            )

        # AT-LOL-002 - Rundll32 suspicious execution
        if "rundll32" in text and contains_any(
            text,
            ["javascript:", "url.dll", "http://", "https://", "shell32.dll,control_rundll"]
        ):
            emit(
                "AT-LOL-002",
                event,
                "Rundll32 was observed with a suspicious script, URL, or proxy-execution pattern.",
            )

        # AT-LOL-003 - Regsvr32 remote scriptlet
        if "regsvr32" in text and contains_any(
            text,
            ["scrobj.dll", "/i:http", "/i:https", "http://", "https://"]
        ):
            emit(
                "AT-LOL-003",
                event,
                "Regsvr32 was observed with remote or scriptlet-related execution indicators.",
            )

        # AT-LOL-004 - MSHTA remote content
        if "mshta" in text and contains_any(
            text,
            ["http://", "https://", "javascript:", "vbscript:"]
        ):
            emit(
                "AT-LOL-004",
                event,
                "Mshta was observed loading remote or script-based content.",
            )

        # AT-LOL-005 - BITSAdmin transfer
        if "bitsadmin" in text and contains_any(
            text,
            ["/transfer", "/addfile", "http://", "https://"]
        ):
            emit(
                "AT-LOL-005",
                event,
                "BITSAdmin was observed performing a transfer-related action.",
            )

        # AT-DEF-001 - Shadow copy deletion
        if (
            "vssadmin" in text and "delete" in text and "shadows" in text
        ) or (
            "wmic" in text and "shadowcopy" in text and "delete" in text
        ):
            emit(
                "AT-DEF-001",
                event,
                "A command associated with deleting Windows shadow copies was observed.",
            )

        # AT-DEF-002 - Command-line event log clear
        if "wevtutil" in text and contains_any(text, [" cl ", " clear-log", "clear-log"]):
            emit(
                "AT-DEF-002",
                event,
                "Command-line clearing of a Windows event log was observed.",
            )

        # AT-DISC-001 - Account discovery
        if contains_any(
            text,
            ["whoami /all", "net user", "net1 user", "dsquery user", "wmic useraccount"]
        ):
            emit(
                "AT-DISC-001",
                event,
                "Command-line account discovery activity was observed.",
            )

        # AT-DISC-002 - Process discovery
        if contains_any(text, ["tasklist", "get-process", "wmic process get"]):
            emit(
                "AT-DISC-002",
                event,
                "Process discovery activity was observed.",
            )

        # AT-DISC-003 - Network configuration discovery
        if contains_any(text, ["ipconfig /all", "ifconfig", "get-netipconfiguration"]):
            emit(
                "AT-DISC-003",
                event,
                "Network configuration discovery activity was observed.",
            )

        # AT-DISC-004 - System information discovery
        if contains_any(text, ["systeminfo", "wmic os get", "get-computerinfo"]):
            emit(
                "AT-DISC-004",
                event,
                "System information discovery activity was observed.",
            )

        # AT-CRED-001 - LSASS credential dump indicators
        if "lsass" in text and contains_any(
            text,
            ["procdump", "minidump", "comsvcs.dll", "sekurlsa", "dumpert", "rundll32"]
        ):
            emit(
                "AT-CRED-001",
                event,
                "Process or command-line content contains indicators commonly associated with LSASS memory dumping.",
            )

        # AT-SCRIPT-001 - Windows Script Host
        if contains_any(process_name, ["wscript", "cscript"]) and contains_any(
            text,
            ["http://", "https://", "javascript", "vbscript", ".vbs", ".js"]
        ):
            emit(
                "AT-SCRIPT-001",
                event,
                "Windows Script Host executed script or remote-content related arguments.",
            )

        # AT-CMD-001 - Suspicious Windows command shell
        if contains_any(process_name, ["cmd.exe", "cmd"]) and contains_any(
            command_line,
            ["powershell", "certutil", "bitsadmin", "curl ", "wget ", "whoami", "net user"]
        ):
            emit(
                "AT-CMD-001",
                event,
                "Windows command shell launched a command associated with scripting, transfer, or discovery activity.",
            )

        # AT-PERSIST-001 - Registry Run key modification
        if "reg add" in text and contains_any(
            text,
            ["\\currentversion\\run", "\\currentversion\\runonce", "\\startup"]
        ):
            emit(
                "AT-PERSIST-001",
                event,
                "Registry command-line activity targeted a Run or RunOnce persistence location.",
            )

        # AT-NET-001 - Remote Desktop activity
        if event_id == "4624" and contains_any(
            text,
            ["logontype\": 10", "logon type 10", "logontype=10", "remoteinteractive"]
        ):
            emit(
                "AT-NET-001",
                event,
                "A successful Remote Desktop / RemoteInteractive logon indicator was observed.",
            )

    # AT-AUTH-002 - Dataset-scoped brute-force grouping
    for (source_ip, username), grouped_events in failed_login_groups.items():
        if len(grouped_events) >= 3:
            emit(
                "AT-AUTH-002",
                grouped_events[0],
                f"{len(grouped_events)} failed login attempts were detected for the same source/user within the uploaded dataset.",
            )

    return detections


def save_detections(
    upload_id,
    user_id,
    detections
):

    connection = get_connection()

    try:

        for detection in detections:

            connection.execute("""
            INSERT INTO detections
            (
                upload_id,
                user_id,
                rule_id,
                rule_name,
                severity,
                description,
                mitre_technique,
                host,
                username,
                source_ip,
                event_id,
                event_json,
                status
            )

            VALUES (
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?
            )
            """, (

                upload_id,

                user_id,

                detection[
                    "rule_id"
                ],

                detection[
                    "rule_name"
                ],

                detection[
                    "severity"
                ],

                detection[
                    "description"
                ],

                detection[
                    "mitre_technique"
                ],

                detection[
                    "host"
                ],

                detection[
                    "user"
                ],

                detection[
                    "source_ip"
                ],

                detection[
                    "event_id"
                ],

                json.dumps(
                    detection[
                        "event"
                    ],
                    default=str
                ),

                "Open",

            ))

        connection.commit()

    except Exception:

        connection.rollback()
        raise

    finally:

        connection.close()


# =========================================================
# IOC EXTRACTION
# =========================================================

URL_PATTERN = re.compile(
    r'https?://[^\s<>"\']+',
    re.IGNORECASE
)

IP_PATTERN = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)

HASH_PATTERN = re.compile(
    r'\b(?:'
    r'[A-Fa-f0-9]{64}|'
    r'[A-Fa-f0-9]{40}|'
    r'[A-Fa-f0-9]{32}'
    r')\b'
)

DOMAIN_PATTERN = re.compile(
    r'\b'
    r'(?:'
    r'[A-Za-z0-9]'
    r'(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
    r'\.)+'
    r'[A-Za-z]{2,63}'
    r'\b'
)


def valid_ip(value):

    try:

        ipaddress.ip_address(
            value
        )

        return True

    except ValueError:

        return False


def classify_hash(value):

    if len(value) == 32:

        return "MD5"

    if len(value) == 40:

        return "SHA1"

    if len(value) == 64:

        return "SHA256"

    return "HASH"


def add_ioc(
    results,
    seen,
    ioc_type,
    value,
    source_field,
    event
):

    value = str(
        value
    ).strip()

    if not value:

        return

    key = (
        ioc_type.lower(),
        value.lower(),
    )

    if key in seen:

        return

    seen.add(
        key
    )

    results.append({

        "ioc_type":
            ioc_type,

        "ioc_value":
            value,

        "source_field":
            source_field,

        "host":
            event.get(
                "host"
            ),

        "user":
            event.get(
                "user"
            ),

        "context":
            event,
    })


def extract_urls(
    value,
    source_field,
    event,
    results,
    seen
):

    if not value:

        return

    for found_url in URL_PATTERN.findall(
        str(value)
    ):

        clean_url = found_url.rstrip(
            ".,);]"
        )

        add_ioc(
            results,
            seen,
            "URL",
            clean_url,
            source_field,
            event
        )

        hostname = urlparse(
            clean_url
        ).hostname

        if hostname:

            if valid_ip(
                hostname
            ):

                add_ioc(
                    results,
                    seen,
                    "IP",
                    hostname,
                    source_field,
                    event
                )

            else:

                add_ioc(
                    results,
                    seen,
                    "DOMAIN",
                    hostname.lower(),
                    source_field,
                    event
                )


def extract_ips(
    value,
    source_field,
    event,
    results,
    seen
):

    if not value:

        return

    for candidate in IP_PATTERN.findall(
        str(value)
    ):

        if valid_ip(
            candidate
        ):

            add_ioc(
                results,
                seen,
                "IP",
                candidate,
                source_field,
                event
            )


def extract_hashes(
    value,
    source_field,
    event,
    results,
    seen
):

    if not value:

        return

    for found_hash in HASH_PATTERN.findall(
        str(value)
    ):

        add_ioc(
            results,
            seen,
            classify_hash(
                found_hash
            ),
            found_hash.lower(),
            source_field,
            event
        )


def extract_domains(
    value,
    source_field,
    event,
    results,
    seen
):

    if not value:

        return

    for domain in DOMAIN_PATTERN.findall(
        str(value)
    ):

        domain = (
            domain
            .lower()
            .rstrip(".")
        )

        if valid_ip(
            domain
        ):

            continue

        add_ioc(
            results,
            seen,
            "DOMAIN",
            domain,
            source_field,
            event
        )


def run_ioc_extraction(events):

    results = []
    seen = set()

    for event in events:

        if not isinstance(
            event,
            dict
        ):

            continue

        for field_name in [
            "source_ip",
            "destination_ip",
        ]:

            extract_ips(
                event.get(
                    field_name
                ),
                field_name,
                event,
                results,
                seen
            )

        extract_urls(
            event.get(
                "url"
            ),
            "url",
            event,
            results,
            seen
        )

        extract_domains(
            event.get(
                "domain"
            ),
            "domain",
            event,
            results,
            seen
        )

        extract_hashes(
            event.get(
                "hash"
            ),
            "hash",
            event,
            results,
            seen
        )

        command_line = event.get(
            "command_line"
        )

        extract_urls(
            command_line,
            "command_line",
            event,
            results,
            seen
        )

        extract_ips(
            command_line,
            "command_line",
            event,
            results,
            seen
        )

        extract_hashes(
            command_line,
            "command_line",
            event,
            results,
            seen
        )

    return results


def save_iocs(
    upload_id,
    user_id,
    iocs
):

    connection = get_connection()

    try:

        for ioc in iocs:

            connection.execute("""
            INSERT INTO iocs
            (
                upload_id,
                user_id,
                ioc_type,
                ioc_value,
                source_field,
                host,
                username,
                context_json,
                status
            )

            VALUES (
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?
            )
            """, (

                upload_id,

                user_id,

                ioc[
                    "ioc_type"
                ],

                ioc[
                    "ioc_value"
                ],

                ioc[
                    "source_field"
                ],

                ioc[
                    "host"
                ],

                ioc[
                    "user"
                ],

                json.dumps(
                    ioc[
                        "context"
                    ],
                    default=str
                ),

                "Observed",

            ))

        connection.commit()

    except Exception:

        connection.rollback()
        raise

    finally:

        connection.close()


# =========================================================
# REGISTER
# =========================================================

@app.route(
    "/register",
    methods=[
        "GET",
        "POST"
    ]
)
def register():

    if "user_id" in session:

        return redirect(
            url_for(
                "index"
            )
        )

    error = None
    full_name = ""
    email = ""

    if request.method == "POST":

        full_name = request.form.get(
            "full_name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if len(full_name) < 2:

            error = (
                "Please enter your full name."
            )

        elif (
            "@" not in email
            or "." not in email.split("@")[-1]
        ):

            error = (
                "Please enter a valid email address."
            )

        elif len(password) < 8:

            error = (
                "Your password must contain "
                "at least 8 characters."
            )

        elif password != confirm_password:

            error = (
                "The passwords you entered "
                "do not match."
            )

        else:

            connection = get_connection()

            try:

                connection.execute("""
                INSERT INTO users
                (
                    full_name,
                    email,
                    password_hash,
                    role
                )

                VALUES (?, ?, ?, ?)
                """, (

                    full_name,

                    email,

                    generate_password_hash(
                        password
                    ),

                    "Analyst",

                ))

                connection.commit()

            except sqlite3.IntegrityError:

                error = (
                    "An account with this "
                    "email already exists."
                )

            finally:

                connection.close()

            if error is None:

                return redirect(

                    url_for(
                        "login",
                        registered="1"
                    )

                )

    return render_template(

        "auth/register.html",

        error=
            error,

        full_name=
            full_name,

        email=
            email,

    )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=[
        "GET",
        "POST"
    ]
)
def login():

    if "user_id" in session:

        return redirect(
            url_for(
                "index"
            )
        )

    error = None
    email = ""

    registered = (
        request.args.get(
            "registered"
        )
        == "1"
    )

    logged_out = (
        request.args.get(
            "logged_out"
        )
        == "1"
    )

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        connection = get_connection()

        user = connection.execute("""
        SELECT *
        FROM users
        WHERE email = ?
        """, (

            email,

        )).fetchone()

        connection.close()

        if (
            user is None
            or not check_password_hash(
                user[
                    "password_hash"
                ],
                password
            )
        ):

            error = (
                "The email or password "
                "you entered is incorrect."
            )

        else:

            session.clear()

            session[
                "user_id"
            ] = user[
                "id"
            ]

            session[
                "full_name"
            ] = user[
                "full_name"
            ]

            session[
                "email"
            ] = user[
                "email"
            ]

            session[
                "role"
            ] = user[
                "role"
            ]

            return redirect(
                url_for(
                    "index"
                )
            )

    return render_template(

        "auth/login.html",

        error=
            error,

        registered=
            registered,

        logged_out=
            logged_out,

        email=
            email,

    )


# =========================================================
# LOGOUT
# =========================================================

@app.route(
    "/logout",
    methods=["POST"]
)
def logout():

    session.clear()

    return redirect(

        url_for(
            "login",
            logged_out="1"
        )

    )


# =========================================================
# GLOBAL DATA
# =========================================================

# =========================================================
# ADMIN ACCESS CONTROL
# =========================================================

def admin_required(view_function):

    @wraps(view_function)
    def wrapped_view(*args, **kwargs):

        # User must be logged in
        if "user_id" not in session:
            return redirect(
                url_for("login")
            )

        connection = get_connection()

        user = connection.execute("""
            SELECT
                id,
                full_name,
                email,
                role

            FROM users

            WHERE id = ?
        """, (
            session["user_id"],
        )).fetchone()

        connection.close()


        # Account no longer exists
        if user is None:

            session.clear()

            return redirect(
                url_for("login")
            )


        # Keep session role synchronized with database
        session["role"] = user["role"]


        # Server-side protection
        if user["role"] != "Admin":

            abort(403)


        return view_function(
            *args,
            **kwargs
        )

    return wrapped_view

def record_admin_audit(action, target_type=None, target_id=None, target_name=None, details=None):

    admin_user_id = session.get("user_id")

    connection = get_connection()
    try:
        connection.execute("""
            INSERT INTO admin_audit_log
            (
                admin_user_id,
                action,
                target_type,
                target_id,
                target_name,
                details
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            admin_user_id,
            action,
            target_type,
            str(target_id) if target_id is not None else None,
            target_name,
            details,
        ))
        connection.commit()
    finally:
        connection.close()


def record_response_action(action_type, target_type=None, target_value=None, notes=None, status="Recorded"):

    connection = get_connection()
    try:
        connection.execute("""
            INSERT INTO response_actions
            (
                user_id,
                action_type,
                target_type,
                target_value,
                notes,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            session.get("user_id"),
            action_type,
            target_type,
            target_value,
            notes,
            status,
        ))
        connection.commit()
    finally:
        connection.close()


@app.context_processor
def inject_global_data():

    current_user = None

    if "user_id" in session:

        current_user = {

            "id":
                session.get(
                    "user_id"
                ),

            "full_name":
                session.get(
                    "full_name"
                ),

            "email":
                session.get(
                    "email"
                ),

            "role":
                session.get(
                    "role"
                ),

        }

    return {

        "modules":
            MODULES,

        "current_user":
            current_user,

    }


# =========================================================
# OVERVIEW
# =========================================================

@app.route("/")
def index():

    if "user_id" not in session:

        return redirect(
            url_for(
                "login"
            )
        )

    return render_template(

        "pages/overview.html",

        module=
            MODULES[
                "overview"
            ],

        active_module=
            "overview",

    )


# =========================================================
# TELEMETRY UPLOAD
# =========================================================

@app.route(
    "/telemetry/upload",
    methods=["POST"]
)
def upload_telemetry():

    if "user_id" not in session:

        return redirect(
            url_for(
                "login"
            )
        )

    telemetry_file = request.files.get(
        "telemetry_file"
    )

    if (
        telemetry_file is None
        or telemetry_file.filename == ""
    ):

        flash(
            "Please select a telemetry file.",
            "error"
        )

        return redirect(

            url_for(
                "module_page",
                module_name="telemetry"
            )

        )

    if not allowed_file(
        telemetry_file.filename
    ):

        flash(
            "Unsupported file type. "
            "Upload a CSV or JSON file.",
            "error"
        )

        return redirect(

            url_for(
                "module_page",
                module_name="telemetry"
            )

        )

    original_name = secure_filename(
        telemetry_file.filename
    )

    extension = (
        original_name
        .rsplit(".", 1)[1]
        .lower()
    )

    stored_name = (
        f"{uuid4().hex}."
        f"{extension}"
    )

    file_path = (
        UPLOAD_FOLDER
        / stored_name
    )

    telemetry_file.save(
        file_path
    )

    file_size = (
        file_path.stat().st_size
    )

    if file_size == 0:

        file_path.unlink(
            missing_ok=True
        )

        flash(
            "The selected file is empty.",
            "error"
        )

        return redirect(

            url_for(
                "module_page",
                module_name="telemetry"
            )

        )


    status = "Parsed"
    event_count = 0
    fields = []
    preview = []
    error_message = None


    try:

        result = parse_telemetry_file(
            file_path,
            extension
        )

        event_count = result[
            "event_count"
        ]

        fields = result[
            "fields"
        ]

        preview = result[
            "preview"
        ]

    except Exception as error:

        status = "Parse Failed"

        error_message = str(
            error
        )


    normalization_status = "Pending"
    normalized_name = None
    normalized_event_count = 0
    normalized_fields = []
    normalized_preview = []
    normalized_events = []
    normalization_error = None


    if status == "Parsed":

        try:

            normalized_result = normalize_telemetry_file(
                file_path,
                extension,
                original_name,
                stored_name
            )

            normalization_status = "Normalized"

            normalized_name = normalized_result[
                "normalized_name"
            ]

            normalized_event_count = normalized_result[
                "event_count"
            ]

            normalized_fields = normalized_result[
                "fields"
            ]

            normalized_preview = normalized_result[
                "preview"
            ]

            normalized_events = normalized_result[
                "events"
            ]

        except Exception as error:

            normalization_status = "Failed"

            normalization_error = str(
                error
            )


    connection = get_connection()

    try:

        cursor = connection.execute("""
        INSERT INTO telemetry_uploads
        (
            user_id,
            original_name,
            stored_name,
            file_type,
            file_size,
            status,
            event_count,
            field_count,
            fields_json,
            preview_json,
            error_message,
            normalized_name,
            normalization_status,
            normalized_event_count,
            normalized_fields_json,
            normalized_preview_json,
            normalization_error,
            detection_status,
            detection_count,
            ioc_status,
            ioc_count
        )

        VALUES (
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?
        )
        """, (

            session[
                "user_id"
            ],

            original_name,

            stored_name,

            extension.upper(),

            file_size,

            status,

            event_count,

            len(
                fields
            ),

            json.dumps(
                fields
            ),

            json.dumps(
                preview,
                default=str
            ),

            error_message,

            normalized_name,

            normalization_status,

            normalized_event_count,

            json.dumps(
                normalized_fields
            ),

            json.dumps(
                normalized_preview,
                default=str
            ),

            normalization_error,

            "Pending",

            0,

            "Pending",

            0,

        ))

        upload_id = cursor.lastrowid

        connection.commit()

    except sqlite3.Error as error:

        connection.rollback()
        connection.close()

        print(
            "Telemetry database error:",
            error
        )

        flash(
            "Telemetry record could not be saved.",
            "error"
        )

        return redirect(

            url_for(
                "module_page",
                module_name="telemetry"
            )

        )

    connection.close()


    # Save events
    if normalization_status == "Normalized":

        try:

            save_normalized_events(

                upload_id,

                session[
                    "user_id"
                ],

                normalized_events

            )

        except Exception as error:

            print(
                "Event save error:",
                error
            )


    # Detection
    detections = []
    detection_status = "Pending"

    if normalization_status == "Normalized":

        try:

            detections = run_detection_engine(
                normalized_events
            )

            save_detections(

                upload_id,

                session[
                    "user_id"
                ],

                detections

            )

            detection_status = "Completed"

        except Exception as error:

            detection_status = "Failed"

            print(
                "Detection error:",
                error
            )


    # IOC
    iocs = []
    ioc_status = "Pending"

    if normalization_status == "Normalized":

        try:

            iocs = run_ioc_extraction(
                normalized_events
            )

            save_iocs(

                upload_id,

                session[
                    "user_id"
                ],

                iocs

            )

            ioc_status = "Completed"

        except Exception as error:

            ioc_status = "Failed"

            print(
                "IOC error:",
                error
            )


    connection = get_connection()

    connection.execute("""
    UPDATE telemetry_uploads

    SET
        detection_status = ?,
        detection_count = ?,
        ioc_status = ?,
        ioc_count = ?

    WHERE id = ?
    """, (

        detection_status,

        len(
            detections
        ),

        ioc_status,

        len(
            iocs
        ),

        upload_id,

    ))

    connection.commit()
    connection.close()


    flash(
        f"{original_name} processed. "
        f"{normalized_event_count} events, "
        f"{len(detections)} detection(s), "
        f"{len(iocs)} IOC(s).",
        "success"
    )

    return redirect(

        url_for(
            "module_page",
            module_name="telemetry"
        )

    )


# =========================================================
# PARSED EVENTS
# =========================================================

@app.route(
    "/telemetry/events"
)
def telemetry_events():

    if "user_id" not in session:

        return redirect(
            url_for(
                "login"
            )
        )

    search = request.args.get(
        "q",
        ""
    ).strip()

    connection = get_connection()

    total_events = connection.execute("""
    SELECT COUNT(*) AS total
    FROM events
    """).fetchone()[
        "total"
    ]

    if search:

        search_value = (
            f"%{search}%"
        )

        events = connection.execute("""
        SELECT
            events.*,
            telemetry_uploads.original_name

        FROM events

        LEFT JOIN telemetry_uploads
            ON events.upload_id =
               telemetry_uploads.id

        WHERE
            COALESCE(events.timestamp, '') LIKE ?

        OR
            COALESCE(events.event_id, '') LIKE ?

        OR
            COALESCE(events.host, '') LIKE ?

        OR
            COALESCE(events.username, '') LIKE ?

        OR
            COALESCE(events.source_ip, '') LIKE ?

        OR
            COALESCE(events.destination_ip, '') LIKE ?

        OR
            COALESCE(events.process_name, '') LIKE ?

        OR
            COALESCE(events.command_line, '') LIKE ?

        OR
            COALESCE(events.event_type, '') LIKE ?

        OR
            COALESCE(telemetry_uploads.original_name, '') LIKE ?

        ORDER BY
            events.id DESC

        LIMIT 250
        """, (

            search_value,
            search_value,
            search_value,
            search_value,
            search_value,
            search_value,
            search_value,
            search_value,
            search_value,
            search_value,

        )).fetchall()

    else:

        events = connection.execute("""
        SELECT
            events.*,
            telemetry_uploads.original_name

        FROM events

        LEFT JOIN telemetry_uploads
            ON events.upload_id =
               telemetry_uploads.id

        ORDER BY
            events.id DESC

        LIMIT 250
        """).fetchall()

    connection.close()

    return render_template(

        "pages/telemetry_events.html",

        module=
            MODULES[
                "telemetry"
            ],

        active_module=
            "telemetry",

        events=
            events,

        total_events=
            total_events,

        search=
            search,

    )


# =========================================================
# HOSTS
# =========================================================

@app.route(
    "/telemetry/hosts"
)
def telemetry_hosts():

    if "user_id" not in session:

        return redirect(
            url_for(
                "login"
            )
        )

    search = request.args.get(
        "q",
        ""
    ).strip()

    connection = get_connection()

    total_hosts = connection.execute("""
    SELECT COUNT(DISTINCT host) AS total

    FROM events

    WHERE
        host IS NOT NULL

    AND
        TRIM(host) != ''
    """).fetchone()[
        "total"
    ]


    host_event_total = connection.execute("""
    SELECT COUNT(*) AS total

    FROM events

    WHERE
        host IS NOT NULL

    AND
        TRIM(host) != ''
    """).fetchone()[
        "total"
    ]


    sql = """
    SELECT

        e.host AS host_name,

        COUNT(*) AS event_count,

        COUNT(
            DISTINCT CASE

                WHEN
                    e.username IS NOT NULL

                AND
                    TRIM(e.username) != ''

                THEN
                    e.username

            END
        ) AS unique_users,

        COUNT(
            DISTINCT CASE

                WHEN
                    e.source_ip IS NOT NULL

                AND
                    TRIM(e.source_ip) != ''

                THEN
                    e.source_ip

            END
        ) AS unique_source_ips,

        (
            SELECT COUNT(*)

            FROM detections d

            WHERE
                d.host = e.host

        ) AS detection_count,

        MAX(
            CASE

                WHEN
                    e.timestamp IS NOT NULL

                AND
                    TRIM(e.timestamp) != ''

                THEN
                    e.timestamp

                ELSE
                    e.created_at

            END
        ) AS last_seen

    FROM events e

    WHERE
        e.host IS NOT NULL

    AND
        TRIM(e.host) != ''
    """

    parameters = []

    if search:

        sql += """
        AND LOWER(e.host)
            LIKE LOWER(?)
        """

        parameters.append(
            f"%{search}%"
        )

    sql += """
    GROUP BY
        e.host

    ORDER BY
        detection_count DESC,
        event_count DESC,
        e.host ASC

    LIMIT 250
    """

    hosts = connection.execute(
        sql,
        parameters
    ).fetchall()

    connection.close()

    return render_template(

        "pages/telemetry_hosts.html",

        module=
            MODULES[
                "telemetry"
            ],

        active_module=
            "telemetry",

        hosts=
            hosts,

        total_hosts=
            total_hosts,

        host_event_total=
            host_event_total,

        search=
            search,

    )


# =========================================================
# USERS
# =========================================================

@app.route(
    "/telemetry/users"
)
def telemetry_users():

    if "user_id" not in session:

        return redirect(
            url_for(
                "login"
            )
        )

    search = request.args.get(
        "q",
        ""
    ).strip()

    connection = get_connection()


    # -----------------------------------------------------
    # UNIQUE USERS
    # -----------------------------------------------------

    total_users = connection.execute("""
    SELECT COUNT(DISTINCT username) AS total

    FROM events

    WHERE
        username IS NOT NULL

    AND
        TRIM(username) != ''
    """).fetchone()[
        "total"
    ]


    # -----------------------------------------------------
    # EVENTS WITH USER INFORMATION
    # -----------------------------------------------------

    user_event_total = connection.execute("""
    SELECT COUNT(*) AS total

    FROM events

    WHERE
        username IS NOT NULL

    AND
        TRIM(username) != ''
    """).fetchone()[
        "total"
    ]


    # -----------------------------------------------------
    # USER QUERY
    # -----------------------------------------------------

    sql = """
    SELECT

        e.username AS username,

        COUNT(*) AS event_count,

        COUNT(
            DISTINCT CASE

                WHEN
                    e.host IS NOT NULL

                AND
                    TRIM(e.host) != ''

                THEN
                    e.host

            END
        ) AS unique_hosts,

        COUNT(
            DISTINCT CASE

                WHEN
                    e.source_ip IS NOT NULL

                AND
                    TRIM(e.source_ip) != ''

                THEN
                    e.source_ip

            END
        ) AS unique_source_ips,

        (
            SELECT COUNT(*)

            FROM detections d

            WHERE
                d.username = e.username

        ) AS detection_count,

        MAX(
            CASE

                WHEN
                    e.timestamp IS NOT NULL

                AND
                    TRIM(e.timestamp) != ''

                THEN
                    e.timestamp

                ELSE
                    e.created_at

            END
        ) AS last_seen

    FROM events e

    WHERE
        e.username IS NOT NULL

    AND
        TRIM(e.username) != ''
    """

    parameters = []

    if search:

        sql += """
        AND LOWER(e.username)
            LIKE LOWER(?)
        """

        parameters.append(
            f"%{search}%"
        )

    sql += """
    GROUP BY
        e.username

    ORDER BY
        detection_count DESC,
        event_count DESC,
        e.username ASC

    LIMIT 250
    """

    users = connection.execute(
        sql,
        parameters
    ).fetchall()

    connection.close()


    return render_template(

        "pages/telemetry_users.html",

        module=
            MODULES[
                "telemetry"
            ],

        active_module=
            "telemetry",

        users=
            users,

        total_users=
            total_users,

        user_event_total=
            user_event_total,

        search=
            search,

    )

# =========================================================
# PROCESSES
# =========================================================

@app.route("/telemetry/processes")
def telemetry_processes():

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    search = request.args.get(
        "q",
        ""
    ).strip()

    connection = get_connection()


    # -----------------------------------------------------
    # TOTAL UNIQUE PROCESSES
    # -----------------------------------------------------

    total_processes = connection.execute("""
        SELECT COUNT(
            DISTINCT LOWER(TRIM(process_name))
        ) AS total

        FROM events

        WHERE process_name IS NOT NULL
        AND TRIM(process_name) != ''
    """).fetchone()["total"]


    # -----------------------------------------------------
    # EVENTS CONTAINING PROCESS DATA
    # -----------------------------------------------------

    process_event_total = connection.execute("""
        SELECT COUNT(*) AS total

        FROM events

        WHERE process_name IS NOT NULL
        AND TRIM(process_name) != ''
    """).fetchone()["total"]


    # -----------------------------------------------------
    # PROCESS QUERY
    # -----------------------------------------------------

    sql = """
        SELECT

            MIN(e.process_name) AS process_name,

            COUNT(*) AS event_count,

            COUNT(
                DISTINCT CASE

                    WHEN e.host IS NOT NULL
                    AND TRIM(e.host) != ''

                    THEN e.host

                END
            ) AS unique_hosts,

            COUNT(
                DISTINCT CASE

                    WHEN e.username IS NOT NULL
                    AND TRIM(e.username) != ''

                    THEN e.username

                END
            ) AS unique_users,

            SUM(
                CASE

                    WHEN e.command_line IS NOT NULL
                    AND TRIM(e.command_line) != ''

                    THEN 1

                    ELSE 0

                END
            ) AS command_line_events,

            MAX(
                CASE

                    WHEN e.timestamp IS NOT NULL
                    AND TRIM(e.timestamp) != ''

                    THEN e.timestamp

                    ELSE e.created_at

                END
            ) AS last_seen,

            (
                SELECT e2.command_line

                FROM events e2

                WHERE
                    LOWER(TRIM(e2.process_name))
                    =
                    LOWER(TRIM(e.process_name))

                AND e2.command_line IS NOT NULL
                AND TRIM(e2.command_line) != ''

                ORDER BY e2.id DESC

                LIMIT 1
            ) AS latest_command_line

        FROM events e

        WHERE e.process_name IS NOT NULL
        AND TRIM(e.process_name) != ''
    """

    parameters = []


    if search:

        search_value = f"%{search}%"

        sql += """
            AND (
                LOWER(e.process_name)
                LIKE LOWER(?)

                OR

                LOWER(
                    COALESCE(
                        e.command_line,
                        ''
                    )
                )
                LIKE LOWER(?)
            )
        """

        parameters.extend([
            search_value,
            search_value,
        ])


    sql += """
        GROUP BY
            LOWER(TRIM(e.process_name))

        ORDER BY
            event_count DESC,
            process_name ASC

        LIMIT 250
    """


    processes = connection.execute(
        sql,
        parameters
    ).fetchall()

    connection.close()


    return render_template(
        "pages/telemetry_processes.html",

        module=
            MODULES["telemetry"],

        active_module=
            "telemetry",

        processes=
            processes,

        total_processes=
            total_processes,

        process_event_total=
            process_event_total,

        search=
            search,
    )


# =========================================================
# NETWORK
# =========================================================

@app.route("/telemetry/network")
def telemetry_network():

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    search = request.args.get(
        "q",
        ""
    ).strip()

    connection = get_connection()


    # -----------------------------------------------------
    # TOTAL NETWORK EVENTS
    # -----------------------------------------------------

    total_network_events = connection.execute("""
        SELECT COUNT(*) AS total

        FROM events

        WHERE
            (
                source_ip IS NOT NULL
                AND TRIM(source_ip) != ''
            )

            OR

            (
                destination_ip IS NOT NULL
                AND TRIM(destination_ip) != ''
            )

            OR

            (
                domain IS NOT NULL
                AND TRIM(domain) != ''
            )

            OR

            (
                url IS NOT NULL
                AND TRIM(url) != ''
            )
    """).fetchone()["total"]


    # -----------------------------------------------------
    # UNIQUE SOURCE IPS
    # -----------------------------------------------------

    unique_source_ips = connection.execute("""
        SELECT COUNT(
            DISTINCT source_ip
        ) AS total

        FROM events

        WHERE
            source_ip IS NOT NULL

        AND
            TRIM(source_ip) != ''
    """).fetchone()["total"]


    # -----------------------------------------------------
    # UNIQUE DESTINATION IPS
    # -----------------------------------------------------

    unique_destination_ips = connection.execute("""
        SELECT COUNT(
            DISTINCT destination_ip
        ) AS total

        FROM events

        WHERE
            destination_ip IS NOT NULL

        AND
            TRIM(destination_ip) != ''
    """).fetchone()["total"]


    # -----------------------------------------------------
    # UNIQUE DOMAINS
    # -----------------------------------------------------

    unique_domains = connection.execute("""
        SELECT COUNT(
            DISTINCT domain
        ) AS total

        FROM events

        WHERE
            domain IS NOT NULL

        AND
            TRIM(domain) != ''
    """).fetchone()["total"]


    # -----------------------------------------------------
    # NETWORK ACTIVITY QUERY
    # -----------------------------------------------------

    sql = """
        SELECT

            e.source_ip,

            e.destination_ip,

            e.domain,

            e.url,

            COUNT(*) AS event_count,

            COUNT(
                DISTINCT CASE

                    WHEN e.host IS NOT NULL
                    AND TRIM(e.host) != ''

                    THEN e.host

                END
            ) AS unique_hosts,

            COUNT(
                DISTINCT CASE

                    WHEN e.username IS NOT NULL
                    AND TRIM(e.username) != ''

                    THEN e.username

                END
            ) AS unique_users,

            MAX(
                CASE

                    WHEN e.timestamp IS NOT NULL
                    AND TRIM(e.timestamp) != ''

                    THEN e.timestamp

                    ELSE e.created_at

                END
            ) AS last_seen

        FROM events e

        WHERE
            (
                e.source_ip IS NOT NULL
                AND TRIM(e.source_ip) != ''
            )

            OR

            (
                e.destination_ip IS NOT NULL
                AND TRIM(e.destination_ip) != ''
            )

            OR

            (
                e.domain IS NOT NULL
                AND TRIM(e.domain) != ''
            )

            OR

            (
                e.url IS NOT NULL
                AND TRIM(e.url) != ''
            )
    """

    parameters = []


    if search:

        search_value = f"%{search}%"

        sql += """
            AND (
                LOWER(
                    COALESCE(
                        e.source_ip,
                        ''
                    )
                ) LIKE LOWER(?)

                OR

                LOWER(
                    COALESCE(
                        e.destination_ip,
                        ''
                    )
                ) LIKE LOWER(?)

                OR

                LOWER(
                    COALESCE(
                        e.domain,
                        ''
                    )
                ) LIKE LOWER(?)

                OR

                LOWER(
                    COALESCE(
                        e.url,
                        ''
                    )
                ) LIKE LOWER(?)

                OR

                LOWER(
                    COALESCE(
                        e.host,
                        ''
                    )
                ) LIKE LOWER(?)

                OR

                LOWER(
                    COALESCE(
                        e.username,
                        ''
                    )
                ) LIKE LOWER(?)
            )
        """

        parameters.extend([
            search_value,
            search_value,
            search_value,
            search_value,
            search_value,
            search_value,
        ])


    sql += """
        GROUP BY

            COALESCE(
                e.source_ip,
                ''
            ),

            COALESCE(
                e.destination_ip,
                ''
            ),

            COALESCE(
                e.domain,
                ''
            ),

            COALESCE(
                e.url,
                ''
            )

        ORDER BY

            event_count DESC,

            last_seen DESC

        LIMIT 250
    """


    network_events = connection.execute(
        sql,
        parameters
    ).fetchall()

    connection.close()


    return render_template(

        "pages/telemetry_network.html",

        module=
            MODULES["telemetry"],

        active_module=
            "telemetry",

        network_events=
            network_events,

        total_network_events=
            total_network_events,

        unique_source_ips=
            unique_source_ips,

        unique_destination_ips=
            unique_destination_ips,

        unique_domains=
            unique_domains,

        search=
            search,
    )

# =========================================================
# ADMINISTRATION
# =========================================================

@app.route("/admin")
@admin_required
def admin_dashboard():

    connection = get_connection()


    total_users = connection.execute("""
        SELECT COUNT(*) AS total
        FROM users
    """).fetchone()["total"]


    admin_users = connection.execute("""
        SELECT COUNT(*) AS total

        FROM users

        WHERE role = 'Admin'
    """).fetchone()["total"]


    total_uploads = connection.execute("""
        SELECT COUNT(*) AS total
        FROM telemetry_uploads
    """).fetchone()["total"]


    total_events = connection.execute("""
        SELECT COUNT(*) AS total
        FROM events
    """).fetchone()["total"]


    total_detections = connection.execute("""
        SELECT COUNT(*) AS total
        FROM detections
    """).fetchone()["total"]


    total_iocs = connection.execute("""
        SELECT COUNT(*) AS total
        FROM iocs
    """).fetchone()["total"]


    recent_users = connection.execute("""
        SELECT
            id,
            full_name,
            email,
            role

        FROM users

        ORDER BY id DESC

        LIMIT 5
    """).fetchall()


    recent_uploads = connection.execute("""
        SELECT
            telemetry_uploads.id,
            telemetry_uploads.original_name,
            telemetry_uploads.status,
            telemetry_uploads.event_count,
            telemetry_uploads.uploaded_at,
            users.full_name AS uploaded_by

        FROM telemetry_uploads

        LEFT JOIN users
            ON telemetry_uploads.user_id = users.id

        ORDER BY telemetry_uploads.id DESC

        LIMIT 5
    """).fetchall()


    connection.close()



    return render_template(

        "pages/admin_dashboard.html",

        module=ADMIN_MODULE,

        active_module="admin",

        total_users=total_users,

        admin_users=admin_users,

        total_uploads=total_uploads,

        total_events=total_events,

        total_detections=total_detections,

        total_iocs=total_iocs,

        recent_users=recent_users,

        recent_uploads=recent_uploads,
    )

# =========================================================
# ADMIN - USER MANAGEMENT
# =========================================================

@app.route("/admin/users")
@admin_required
def admin_users():

    search = request.args.get(
        "q",
        ""
    ).strip()

    connection = get_connection()


    total_users = connection.execute("""
        SELECT COUNT(*) AS total
        FROM users
    """).fetchone()["total"]


    total_admins = connection.execute("""
        SELECT COUNT(*) AS total

        FROM users

        WHERE role = 'Admin'
    """).fetchone()["total"]


    total_analysts = connection.execute("""
        SELECT COUNT(*) AS total

        FROM users

        WHERE role = 'Analyst'
    """).fetchone()["total"]


    if search:

        search_value = f"%{search}%"

        users = connection.execute("""
            SELECT
                id,
                full_name,
                email,
                role

            FROM users

            WHERE
                LOWER(full_name) LIKE LOWER(?)

            OR
                LOWER(email) LIKE LOWER(?)

            OR
                LOWER(role) LIKE LOWER(?)

            ORDER BY
                CASE
                    WHEN role = 'Admin' THEN 0
                    ELSE 1
                END,

                full_name ASC
        """, (
            search_value,
            search_value,
            search_value,
        )).fetchall()

    else:

        users = connection.execute("""
            SELECT
                id,
                full_name,
                email,
                role

            FROM users

            ORDER BY
                CASE
                    WHEN role = 'Admin' THEN 0
                    ELSE 1
                END,

                full_name ASC
        """).fetchall()


    connection.close()


    return render_template(
        "pages/admin_users.html",

        module=ADMIN_MODULE,

        active_module="admin",

        users=users,

        total_users=total_users,

        total_admins=total_admins,

        total_analysts=total_analysts,

        search=search,
    )


# =========================================================
# ADMIN - TELEMETRY MANAGEMENT
# =========================================================

@app.route("/admin/telemetry")
@admin_required
def admin_telemetry():

    search = request.args.get(
        "q",
        ""
    ).strip()

    connection = get_connection()


    total_uploads = connection.execute("""
        SELECT COUNT(*) AS total
        FROM telemetry_uploads
    """).fetchone()["total"]


    total_events = connection.execute("""
        SELECT COUNT(*) AS total
        FROM events
    """).fetchone()["total"]


    total_detections = connection.execute("""
        SELECT COUNT(*) AS total
        FROM detections
    """).fetchone()["total"]


    total_iocs = connection.execute("""
        SELECT COUNT(*) AS total
        FROM iocs
    """).fetchone()["total"]


    sql = """
        SELECT

            t.id,
            t.original_name,
            t.file_type,
            t.file_size,
            t.status,
            t.normalization_status,
            t.uploaded_at,

            u.full_name AS uploaded_by,

            (
                SELECT COUNT(*)
                FROM events e
                WHERE e.upload_id = t.id
            ) AS stored_events,

            (
                SELECT COUNT(*)
                FROM detections d
                WHERE d.upload_id = t.id
            ) AS detection_count,

            (
                SELECT COUNT(*)
                FROM iocs i
                WHERE i.upload_id = t.id
            ) AS ioc_count

        FROM telemetry_uploads t

        LEFT JOIN users u
            ON t.user_id = u.id

        WHERE 1 = 1
    """

    parameters = []


    if search:

        search_value = f"%{search}%"

        sql += """
            AND (
                LOWER(
                    COALESCE(
                        t.original_name,
                        ''
                    )
                ) LIKE LOWER(?)

                OR

                LOWER(
                    COALESCE(
                        t.file_type,
                        ''
                    )
                ) LIKE LOWER(?)

                OR

                LOWER(
                    COALESCE(
                        t.status,
                        ''
                    )
                ) LIKE LOWER(?)

                OR

                LOWER(
                    COALESCE(
                        u.full_name,
                        ''
                    )
                ) LIKE LOWER(?)
            )
        """

        parameters.extend([
            search_value,
            search_value,
            search_value,
            search_value,
        ])


    sql += """
        ORDER BY
            t.id DESC

        LIMIT 250
    """


    uploads = connection.execute(
        sql,
        parameters
    ).fetchall()

    connection.close()


    return render_template(

        "pages/admin_telemetry.html",

        module=ADMIN_MODULE,

        active_module="admin",

        uploads=uploads,

        total_uploads=total_uploads,

        total_events=total_events,

        total_detections=total_detections,

        total_iocs=total_iocs,

        search=search,
    )

# =========================================================
# ADMIN - DELETE DATASET
# =========================================================

@app.route(
    "/admin/telemetry/<int:upload_id>/delete",
    methods=["GET", "POST"]
)
@admin_required
def admin_delete_dataset(upload_id):

    connection = get_connection()

    upload = connection.execute("""
        SELECT
            id,
            original_name,
            stored_name,
            normalized_name,
            user_id,
            uploaded_at

        FROM telemetry_uploads

        WHERE id = ?
    """, (
        upload_id,
    )).fetchone()


    if upload is None:

        connection.close()

        abort(404)


    # -----------------------------------------------------
    # CONFIRMATION PAGE
    # -----------------------------------------------------

    if request.method == "GET":

        connection.close()

        return render_template(
            "pages/admin_delete_dataset.html",

            module=ADMIN_MODULE,

            active_module="admin",

            upload=upload,
        )


    # -----------------------------------------------------
    # SERVER-SIDE CONFIRMATION
    # -----------------------------------------------------

    confirm_name = request.form.get(
        "confirm_name",
        ""
    ).strip()


    if confirm_name != upload["original_name"]:

        connection.close()

        flash(
            "Dataset name did not match. "
            "Nothing was deleted.",
            "error"
        )

        return redirect(
            url_for(
                "admin_delete_dataset",
                upload_id=upload_id
            )
        )


    stored_name = upload["stored_name"]

    normalized_name = upload["normalized_name"]


    try:

        # -------------------------------------------------
        # DATABASE TRANSACTION
        # -------------------------------------------------

        connection.execute("BEGIN")


        connection.execute("""
            DELETE FROM incidents
            WHERE linked_detection_id IN (
                SELECT id FROM detections WHERE upload_id = ?
            )
            OR linked_ioc_id IN (
                SELECT id FROM iocs WHERE upload_id = ?
            )
        """, (
            upload_id,
            upload_id,
        ))


        connection.execute("""
            DELETE FROM iocs
            WHERE upload_id = ?
        """, (
            upload_id,
        ))


        connection.execute("""
            DELETE FROM detections
            WHERE upload_id = ?
        """, (
            upload_id,
        ))


        connection.execute("""
            DELETE FROM events
            WHERE upload_id = ?
        """, (
            upload_id,
        ))


        connection.execute("""
            DELETE FROM telemetry_uploads
            WHERE id = ?
        """, (
            upload_id,
        ))


        connection.commit()


    except Exception as error:

        connection.rollback()
        connection.close()

        print(
            "Dataset delete error:",
            error
        )

        flash(
            "Dataset could not be deleted.",
            "error"
        )

        return redirect(
            url_for("admin_telemetry")
        )


    connection.close()


    # -----------------------------------------------------
    # DELETE RAW FILE
    # -----------------------------------------------------

    if stored_name:

        raw_file = (
            UPLOAD_FOLDER
            / Path(stored_name).name
        )

        try:

            raw_file.unlink(
                missing_ok=True
            )

        except OSError as error:

            print(
                "Raw file delete warning:",
                error
            )


    # -----------------------------------------------------
    # DELETE NORMALIZED FILE
    # -----------------------------------------------------

    if normalized_name:

        normalized_file = (
            PROCESSED_FOLDER
            / Path(normalized_name).name
        )

        try:

            normalized_file.unlink(
                missing_ok=True
            )

        except OSError as error:

            print(
                "Normalized file delete warning:",
                error
            )


    record_admin_audit(
        "Delete Dataset",
        "telemetry_upload",
        upload_id,
        upload["original_name"],
        "Deleted one telemetry dataset and its derived events, detections, IOCs and incident links."
    )


    flash(
        f'{upload["original_name"]} was deleted.',
        "success"
    )


    return redirect(
        url_for("admin_telemetry")
    )
# =========================================================
# ADMIN - CHANGE USER ROLE
# =========================================================

@app.route(
    "/admin/users/<int:user_id>/role",
    methods=["POST"]
)
@admin_required
def admin_update_user_role(user_id):

    new_role = request.form.get(
        "role",
        ""
    ).strip()


    if new_role not in {
        "Admin",
        "Analyst"
    }:

        flash(
            "Invalid user role.",
            "error"
        )

        return redirect(
            url_for("admin_users")
        )


    # Admin cannot demote their own account.
    if user_id == session["user_id"]:

        flash(
            "You cannot change the role of "
            "your own administrator account.",
            "error"
        )

        return redirect(
            url_for("admin_users")
        )


    connection = get_connection()


    target_user = connection.execute("""
        SELECT
            id,
            full_name,
            email,
            role

        FROM users

        WHERE id = ?
    """, (
        user_id,
    )).fetchone()


    if target_user is None:

        connection.close()

        abort(404)


    if target_user["role"] == new_role:

        connection.close()

        flash(
            "The user already has that role.",
            "error"
        )

        return redirect(
            url_for("admin_users")
        )


    connection.execute("""
        UPDATE users

        SET role = ?

        WHERE id = ?
    """, (
        new_role,
        user_id,
    ))

    connection.commit()
    connection.close()


    record_admin_audit(
        "Change User Role",
        "user",
        user_id,
        target_user["full_name"],
        f'Role changed from {target_user["role"]} to {new_role}.'
    )


    flash(
        f'{target_user["full_name"]} is now {new_role}.',
        "success"
    )

    return redirect(
        url_for("admin_users")
    )

# =========================================================
# GLOBAL SEARCH
# =========================================================

@app.route("/search")
@login_required
def global_search():
    query = request.args.get("q", "").strip()
    events = []
    detections = []
    iocs = []
    incidents = []

    if query:
        value = f"%{query}%"
        connection = get_connection()
        events = connection.execute("""
            SELECT id, timestamp, event_id, host, username, source_ip,
                   destination_ip, process_name, event_type, domain, url, hash_value
            FROM events
            WHERE LOWER(COALESCE(event_id,'')) LIKE LOWER(?)
               OR LOWER(COALESCE(host,'')) LIKE LOWER(?)
               OR LOWER(COALESCE(username,'')) LIKE LOWER(?)
               OR LOWER(COALESCE(source_ip,'')) LIKE LOWER(?)
               OR LOWER(COALESCE(destination_ip,'')) LIKE LOWER(?)
               OR LOWER(COALESCE(process_name,'')) LIKE LOWER(?)
               OR LOWER(COALESCE(command_line,'')) LIKE LOWER(?)
               OR LOWER(COALESCE(domain,'')) LIKE LOWER(?)
               OR LOWER(COALESCE(url,'')) LIKE LOWER(?)
               OR LOWER(COALESCE(hash_value,'')) LIKE LOWER(?)
            ORDER BY id DESC LIMIT 50
        """, [value] * 10).fetchall()
        detections = connection.execute("""
            SELECT id, rule_id, rule_name, severity, status, host, username,
                   source_ip, mitre_technique, detected_at
            FROM detections
            WHERE LOWER(COALESCE(rule_id,'')) LIKE LOWER(?)
               OR LOWER(COALESCE(rule_name,'')) LIKE LOWER(?)
               OR LOWER(COALESCE(host,'')) LIKE LOWER(?)
               OR LOWER(COALESCE(username,'')) LIKE LOWER(?)
               OR LOWER(COALESCE(source_ip,'')) LIKE LOWER(?)
               OR LOWER(COALESCE(mitre_technique,'')) LIKE LOWER(?)
            ORDER BY id DESC LIMIT 50
        """, [value] * 6).fetchall()
        iocs = connection.execute("""
            SELECT id, ioc_type, ioc_value, host, username, status, extracted_at
            FROM iocs
            WHERE LOWER(COALESCE(ioc_type,'')) LIKE LOWER(?)
               OR LOWER(COALESCE(ioc_value,'')) LIKE LOWER(?)
               OR LOWER(COALESCE(host,'')) LIKE LOWER(?)
               OR LOWER(COALESCE(username,'')) LIKE LOWER(?)
            ORDER BY id DESC LIMIT 50
        """, [value] * 4).fetchall()
        incidents = connection.execute("""
            SELECT id, title, summary, severity, status, host, username, source_ip,
                   updated_at
            FROM incidents
            WHERE LOWER(COALESCE(title,'')) LIKE LOWER(?)
               OR LOWER(COALESCE(summary,'')) LIKE LOWER(?)
               OR LOWER(COALESCE(host,'')) LIKE LOWER(?)
               OR LOWER(COALESCE(username,'')) LIKE LOWER(?)
               OR LOWER(COALESCE(source_ip,'')) LIKE LOWER(?)
            ORDER BY id DESC LIMIT 50
        """, [value] * 5).fetchall()
        connection.close()

    return render_template(
        "pages/search_results.html",
        module=MODULES["overview"],
        active_module="overview",
        query=query,
        events=events,
        detections=detections,
        iocs=iocs,
        incidents=incidents,
    )


# =========================================================
# DETECTION WORKSPACE
# =========================================================

@app.route("/detection/feed")
@login_required
def detection_feed():
    status_filter = request.args.get("status", "").strip()
    severity_filter = request.args.get("severity", "").strip()
    search = request.args.get("q", "").strip()

    connection = get_connection()
    sql = """
        SELECT d.*, t.original_name
        FROM detections d
        LEFT JOIN telemetry_uploads t ON d.upload_id = t.id
        WHERE 1 = 1
    """
    parameters = []

    if status_filter:
        sql += " AND LOWER(d.status) = LOWER(?)"
        parameters.append(status_filter)
    if severity_filter:
        sql += " AND LOWER(d.severity) = LOWER(?)"
        parameters.append(severity_filter)
    if search:
        value = f"%{search}%"
        sql += """
            AND (
                LOWER(COALESCE(d.rule_id, '')) LIKE LOWER(?) OR
                LOWER(COALESCE(d.rule_name, '')) LIKE LOWER(?) OR
                LOWER(COALESCE(d.host, '')) LIKE LOWER(?) OR
                LOWER(COALESCE(d.username, '')) LIKE LOWER(?) OR
                LOWER(COALESCE(d.source_ip, '')) LIKE LOWER(?) OR
                LOWER(COALESCE(d.mitre_technique, '')) LIKE LOWER(?)
            )
        """
        parameters.extend([value] * 6)

    sql += " ORDER BY d.id DESC LIMIT 300"
    detections = connection.execute(sql, parameters).fetchall()

    metrics = connection.execute("""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN LOWER(status) = 'open' THEN 1 ELSE 0 END) AS open_count,
            SUM(CASE WHEN LOWER(status) = 'false positive' THEN 1 ELSE 0 END) AS fp_count,
            SUM(CASE WHEN LOWER(severity) IN ('high', 'critical') THEN 1 ELSE 0 END) AS priority_count
        FROM detections
    """).fetchone()
    connection.close()

    return render_template(
        "pages/detection_feed.html",
        module=MODULES["detection"],
        active_module="detection",
        detections=detections,
        metrics=metrics,
        status_filter=status_filter,
        severity_filter=severity_filter,
        search=search,
    )


@app.route("/detection/<int:detection_id>/status", methods=["POST"])
@login_required
def detection_update_status(detection_id):
    new_status = request.form.get("status", "").strip()
    allowed = {"Open", "Investigating", "Closed", "False Positive"}
    if new_status not in allowed:
        flash("Invalid detection status.", "error")
        return redirect(request.referrer or url_for("detection_feed"))

    connection = get_connection()
    detection = connection.execute(
        "SELECT id FROM detections WHERE id = ?", (detection_id,)
    ).fetchone()
    if detection is None:
        connection.close()
        abort(404)
    connection.execute(
        "UPDATE detections SET status = ? WHERE id = ?",
        (new_status, detection_id),
    )
    connection.commit()
    connection.close()
    flash(f"Detection #{detection_id} marked as {new_status}.", "success")
    return redirect(request.referrer or url_for("detection_feed"))


@app.route("/detection/rules")
@login_required
def detection_rules():
    return render_template(
        "pages/detection_rules.html",
        module=MODULES["detection"],
        active_module="detection",
        rules=DETECTION_RULE_CATALOG,
        rule_count=len(DETECTION_RULE_CATALOG),
        technique_count=len(MITRE_TECHNIQUE_CATALOG),
    )


@app.route("/detection/rule-testing", methods=["GET", "POST"])
@login_required
def detection_rule_testing():
    input_json = request.form.get("event_json", "") if request.method == "POST" else ""
    test_events = []
    test_detections = []
    error_message = None

    if request.method == "POST":
        try:
            payload = json.loads(input_json)
            if isinstance(payload, dict):
                payload = [payload]
            if not isinstance(payload, list):
                raise ValueError("JSON must be an event object or a list of event objects.")
            for item in payload:
                if not isinstance(item, dict):
                    raise ValueError("Every test event must be a JSON object.")
                test_events.append(normalize_event(item))
            test_detections = run_detection_engine(test_events)
        except (json.JSONDecodeError, ValueError, TypeError) as error:
            error_message = str(error)

    return render_template(
        "pages/detection_rule_testing.html",
        module=MODULES["detection"],
        active_module="detection",
        input_json=input_json,
        test_events=test_events,
        test_detections=test_detections,
        error_message=error_message,
    )


@app.route("/detection/false-positives")
@login_required
def detection_false_positives():
    connection = get_connection()
    detections = connection.execute("""
        SELECT d.*, t.original_name
        FROM detections d
        LEFT JOIN telemetry_uploads t ON d.upload_id = t.id
        WHERE LOWER(d.status) = 'false positive'
        ORDER BY d.id DESC
        LIMIT 300
    """).fetchall()
    connection.close()
    return render_template(
        "pages/detection_false_positives.html",
        module=MODULES["detection"],
        active_module="detection",
        detections=detections,
    )


@app.route("/detection/mitre")
@login_required
def detection_mitre():
    connection = get_connection()
    triggered = connection.execute("""
        SELECT mitre_technique, COUNT(*) AS detection_count,
               COUNT(DISTINCT rule_id) AS rule_count
        FROM detections
        WHERE mitre_technique IS NOT NULL AND TRIM(mitre_technique) != ''
        GROUP BY mitre_technique
    """).fetchall()
    connection.close()
    triggered_map = {row["mitre_technique"]: dict(row) for row in triggered}
    techniques = []
    for item in MITRE_TECHNIQUE_CATALOG:
        row = dict(item)
        row["detection_count"] = triggered_map.get(item["id"], {}).get("detection_count", 0)
        row["rule_count"] = sum(1 for rule in DETECTION_RULE_CATALOG if rule["mitre"] == item["id"])
        techniques.append(row)
    return render_template(
        "pages/detection_mitre.html",
        module=MODULES["detection"],
        active_module="detection",
        techniques=techniques,
        technique_count=len(techniques),
    )


@app.route("/detection/coverage")
@login_required
def detection_coverage():
    return redirect(url_for("reports_detection_coverage"))


# =========================================================
# INVESTIGATION WORKSPACE
# =========================================================

@app.route("/investigation/iocs")
@login_required
def investigation_iocs():
    search = request.args.get("q", "").strip()
    ioc_type = request.args.get("type", "").strip()
    connection = get_connection()
    sql = """
        SELECT i.*, t.original_name
        FROM iocs i
        LEFT JOIN telemetry_uploads t ON i.upload_id = t.id
        WHERE 1 = 1
    """
    parameters = []
    if ioc_type:
        sql += " AND LOWER(i.ioc_type) = LOWER(?)"
        parameters.append(ioc_type)
    if search:
        value = f"%{search}%"
        sql += """
            AND (
                LOWER(COALESCE(i.ioc_value, '')) LIKE LOWER(?) OR
                LOWER(COALESCE(i.host, '')) LIKE LOWER(?) OR
                LOWER(COALESCE(i.username, '')) LIKE LOWER(?) OR
                LOWER(COALESCE(t.original_name, '')) LIKE LOWER(?)
            )
        """
        parameters.extend([value] * 4)
    sql += " ORDER BY i.id DESC LIMIT 300"
    iocs = connection.execute(sql, parameters).fetchall()
    counts = connection.execute("""
        SELECT ioc_type, COUNT(*) AS count
        FROM iocs GROUP BY ioc_type ORDER BY count DESC
    """).fetchall()
    connection.close()
    return render_template(
        "pages/investigation_iocs.html",
        module=MODULES["investigation"],
        active_module="investigation",
        iocs=iocs,
        counts=counts,
        search=search,
        ioc_type=ioc_type,
    )


@app.route("/investigation/hunts")
@login_required
def investigation_hunts():
    connection = get_connection()
    runs = connection.execute("""
        SELECT h.*, u.full_name AS analyst_name
        FROM threat_hunt_runs h
        LEFT JOIN users u ON h.user_id = u.id
        ORDER BY h.id DESC LIMIT 100
    """).fetchall()
    connection.close()
    return render_template(
        "pages/investigation_hunts.html",
        module=MODULES["investigation"],
        active_module="investigation",
        hunts=THREAT_HUNTS,
        runs=runs,
    )


@app.route("/investigation/hunts/<hunt_id>/run", methods=["POST"])
@login_required
def investigation_run_hunt(hunt_id):
    hunt = next((h for h in THREAT_HUNTS if h["id"] == hunt_id), None)
    if hunt is None:
        abort(404)

    connection = get_connection()
    if hunt_id == "HUNT-001":
        rows = connection.execute("""
            SELECT d.id, d.rule_id, d.rule_name, d.severity, d.host,
                   d.username, d.source_ip, d.event_id, d.detected_at,
                   t.original_name
            FROM detections d
            LEFT JOIN telemetry_uploads t ON d.upload_id = t.id
            WHERE d.rule_id IN ('AT-WIN-001', 'AT-AUTH-002')
            ORDER BY d.id DESC LIMIT 100
        """).fetchall()
    else:
        rows = connection.execute("""
            SELECT d.id, d.rule_id, d.rule_name, d.severity, d.host,
                   d.username, d.source_ip, d.event_id, d.detected_at,
                   t.original_name
            FROM detections d
            LEFT JOIN telemetry_uploads t ON d.upload_id = t.id
            WHERE d.rule_id = 'AT-PS-001'
            ORDER BY d.id DESC LIMIT 100
        """).fetchall()

    evidence = [dict(row) for row in rows]
    match_count = len(evidence)
    if match_count:
        conclusion = (
            f"The hunt returned {match_count} matching detection record(s). "
            "These records require analyst validation and do not by themselves confirm malicious activity."
        )
    else:
        conclusion = (
            "No matching detection records were present in the current AegisTrace database for this hunt."
        )

    connection.execute("""
        INSERT INTO threat_hunt_runs
        (user_id, hunt_id, title, hypothesis, match_count, status, conclusion, evidence_json)
        VALUES (?, ?, ?, ?, ?, 'Completed', ?, ?)
    """, (
        session["user_id"], hunt["id"], hunt["title"], hunt["hypothesis"],
        match_count, conclusion, json.dumps(evidence, default=str)
    ))
    connection.commit()
    connection.close()
    flash(f"{hunt['id']} completed with {match_count} matching record(s).", "success")
    return redirect(url_for("investigation_hunts"))


@app.route("/investigation/incidents", methods=["GET", "POST"])
@login_required
def investigation_incidents():
    connection = get_connection()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        summary = request.form.get("summary", "").strip()
        severity = request.form.get("severity", "Medium").strip()
        detection_id = request.form.get("linked_detection_id", "").strip()
        ioc_id = request.form.get("linked_ioc_id", "").strip()
        assigned_to = request.form.get("assigned_to", "").strip()

        if not title:
            connection.close()
            flash("Incident title is required.", "error")
            return redirect(url_for("investigation_incidents"))
        if severity not in {"Low", "Medium", "High", "Critical"}:
            severity = "Medium"

        detection_id = int(detection_id) if detection_id.isdigit() else None
        ioc_id = int(ioc_id) if ioc_id.isdigit() else None
        assigned_to = int(assigned_to) if assigned_to.isdigit() else None
        host = username = source_ip = None

        if detection_id:
            d = connection.execute(
                "SELECT host, username, source_ip FROM detections WHERE id = ?",
                (detection_id,),
            ).fetchone()
            if d:
                host, username, source_ip = d["host"], d["username"], d["source_ip"]

        if ioc_id and not any([host, username, source_ip]):
            i = connection.execute(
                "SELECT host, username, ioc_type, ioc_value FROM iocs WHERE id = ?",
                (ioc_id,),
            ).fetchone()
            if i:
                host, username = i["host"], i["username"]
                if i["ioc_type"] == "IP":
                    source_ip = i["ioc_value"]

        cursor = connection.execute("""
            INSERT INTO incidents
            (user_id, title, summary, severity, status, assigned_to,
             linked_detection_id, linked_ioc_id, host, username, source_ip)
            VALUES (?, ?, ?, ?, 'Open', ?, ?, ?, ?, ?, ?)
        """, (
            session["user_id"], title, summary, severity, assigned_to,
            detection_id, ioc_id, host, username, source_ip,
        ))
        incident_id = cursor.lastrowid
        connection.commit()
        connection.close()
        flash(f"Incident #{incident_id} created.", "success")
        return redirect(url_for("investigation_incident_detail", incident_id=incident_id))

    incidents = connection.execute("""
        SELECT i.*, creator.full_name AS created_by,
               assignee.full_name AS assigned_to_name,
               d.rule_id AS detection_rule_id,
               x.ioc_type AS linked_ioc_type,
               x.ioc_value AS linked_ioc_value
        FROM incidents i
        LEFT JOIN users creator ON i.user_id = creator.id
        LEFT JOIN users assignee ON i.assigned_to = assignee.id
        LEFT JOIN detections d ON i.linked_detection_id = d.id
        LEFT JOIN iocs x ON i.linked_ioc_id = x.id
        ORDER BY i.id DESC LIMIT 300
    """).fetchall()
    users = connection.execute(
        "SELECT id, full_name, role FROM users ORDER BY full_name"
    ).fetchall()
    detections = connection.execute("""
        SELECT id, rule_id, rule_name, host, username, source_ip
        FROM detections ORDER BY id DESC LIMIT 100
    """).fetchall()
    iocs = connection.execute("""
        SELECT id, ioc_type, ioc_value, host, username
        FROM iocs ORDER BY id DESC LIMIT 100
    """).fetchall()
    connection.close()
    return render_template(
        "pages/investigation_incidents.html",
        module=MODULES["investigation"],
        active_module="investigation",
        incidents=incidents,
        users=users,
        detections=detections,
        iocs=iocs,
    )


@app.route("/investigation/incidents/<int:incident_id>", methods=["GET", "POST"])
@login_required
def investigation_incident_detail(incident_id):
    connection = get_connection()
    incident = connection.execute("""
        SELECT i.*, creator.full_name AS created_by,
               assignee.full_name AS assigned_to_name,
               d.rule_id AS detection_rule_id, d.rule_name AS detection_rule_name,
               d.mitre_technique, d.description AS detection_description,
               x.ioc_type AS linked_ioc_type, x.ioc_value AS linked_ioc_value
        FROM incidents i
        LEFT JOIN users creator ON i.user_id = creator.id
        LEFT JOIN users assignee ON i.assigned_to = assignee.id
        LEFT JOIN detections d ON i.linked_detection_id = d.id
        LEFT JOIN iocs x ON i.linked_ioc_id = x.id
        WHERE i.id = ?
    """, (incident_id,)).fetchone()
    if incident is None:
        connection.close()
        abort(404)

    if request.method == "POST":
        status = request.form.get("status", incident["status"]).strip()
        severity = request.form.get("severity", incident["severity"]).strip()
        summary = request.form.get("summary", incident["summary"] or "").strip()
        assigned_to = request.form.get("assigned_to", "").strip()
        if status not in {"Open", "Investigating", "Contained", "Closed"}:
            status = incident["status"]
        if severity not in {"Low", "Medium", "High", "Critical"}:
            severity = incident["severity"]
        assigned_to = int(assigned_to) if assigned_to.isdigit() else None
        connection.execute("""
            UPDATE incidents
            SET status = ?, severity = ?, summary = ?, assigned_to = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (status, severity, summary, assigned_to, incident_id))
        connection.commit()
        connection.close()
        flash(f"Incident #{incident_id} updated.", "success")
        return redirect(url_for("investigation_incident_detail", incident_id=incident_id))

    users = connection.execute(
        "SELECT id, full_name, role FROM users ORDER BY full_name"
    ).fetchall()
    connection.close()
    return render_template(
        "pages/investigation_incident_detail.html",
        module=MODULES["investigation"],
        active_module="investigation",
        incident=incident,
        users=users,
    )


@app.route("/investigation/evidence")
@login_required
def investigation_evidence():
    evidence_root = BASE_DIR / "evidence"
    groups = []
    for folder_name, title in [
        ("rule-tests", "Rule Tests"),
        ("hunts", "Threat Hunts"),
        ("incidents", "Incidents"),
    ]:
        folder = evidence_root / folder_name
        folder.mkdir(parents=True, exist_ok=True)
        files = [
            {"name": path.name, "size": path.stat().st_size}
            for path in sorted(folder.iterdir())
            if path.is_file() and path.name != ".gitkeep"
        ]
        groups.append({"title": title, "folder": folder_name, "files": files})
    return render_template(
        "pages/investigation_evidence.html",
        module=MODULES["investigation"],
        active_module="investigation",
        evidence_groups=groups,
    )


# =========================================================
# RESPONSE WORKSPACE
# =========================================================

@app.route("/response/recommended-actions")
@login_required
def response_recommended_actions():
    connection = get_connection()
    incidents = connection.execute("""
        SELECT id, title, severity, status, host, username, source_ip
        FROM incidents
        WHERE LOWER(status) != 'closed'
        ORDER BY CASE LOWER(severity)
            WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
            id DESC LIMIT 50
    """).fetchall()
    detections = connection.execute("""
        SELECT id, rule_id, rule_name, severity, status, host, username, source_ip
        FROM detections
        WHERE LOWER(status) NOT IN ('closed', 'false positive')
        ORDER BY CASE LOWER(severity)
            WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
            id DESC LIMIT 50
    """).fetchall()
    connection.close()
    return render_template(
        "pages/response_recommended_actions.html",
        module=MODULES["response"],
        active_module="response",
        incidents=incidents,
        detections=detections,
    )


@app.route("/response/blocklist", methods=["GET", "POST"])
@login_required
def response_blocklist():
    connection = get_connection()
    if request.method == "POST":
        indicator_type = request.form.get("indicator_type", "").strip().upper()
        indicator_value = request.form.get("indicator_value", "").strip()
        reason = request.form.get("reason", "").strip()
        if indicator_type not in {"IP", "DOMAIN", "URL", "MD5", "SHA1", "SHA256", "OTHER"}:
            connection.close()
            flash("Select a valid indicator type.", "error")
            return redirect(url_for("response_blocklist"))
        if not indicator_value:
            connection.close()
            flash("Indicator value is required.", "error")
            return redirect(url_for("response_blocklist"))
        try:
            connection.execute("""
                INSERT INTO response_blocklist
                (user_id, indicator_type, indicator_value, reason, status)
                VALUES (?, ?, ?, ?, 'Proposed')
            """, (session["user_id"], indicator_type, indicator_value, reason))
            connection.commit()
        except sqlite3.IntegrityError:
            connection.close()
            flash("That indicator already exists in the internal blocklist.", "error")
            return redirect(url_for("response_blocklist"))
        connection.close()
        record_response_action(
            "Blocklist Proposal", indicator_type, indicator_value,
            reason or "Added to internal proposal list.", "Proposed"
        )
        flash("Indicator added as a proposed internal blocklist entry.", "success")
        return redirect(url_for("response_blocklist"))

    entries = connection.execute("""
        SELECT b.*, u.full_name AS created_by
        FROM response_blocklist b
        LEFT JOIN users u ON b.user_id = u.id
        ORDER BY b.id DESC
    """).fetchall()
    connection.close()
    return render_template(
        "pages/response_blocklist.html",
        module=MODULES["response"],
        active_module="response",
        entries=entries,
    )


@app.route("/response/blocklist/<int:entry_id>/status", methods=["POST"])
@login_required
def response_blocklist_status(entry_id):
    new_status = request.form.get("status", "").strip()
    if new_status not in {"Proposed", "Approved", "Removed"}:
        flash("Invalid blocklist status.", "error")
        return redirect(url_for("response_blocklist"))
    connection = get_connection()
    entry = connection.execute(
        "SELECT * FROM response_blocklist WHERE id = ?", (entry_id,)
    ).fetchone()
    if entry is None:
        connection.close()
        abort(404)
    connection.execute("""
        UPDATE response_blocklist
        SET status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (new_status, entry_id))
    connection.commit()
    connection.close()
    record_response_action(
        "Blocklist Status Update", entry["indicator_type"], entry["indicator_value"],
        f"Internal blocklist status changed to {new_status}. No OS or network firewall was modified.",
        new_status,
    )
    flash("Internal blocklist status updated.", "success")
    return redirect(url_for("response_blocklist"))


@app.route("/response/action-history")
@login_required
def response_action_history():
    connection = get_connection()
    actions = connection.execute("""
        SELECT a.*, u.full_name AS analyst_name
        FROM response_actions a
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.id DESC LIMIT 300
    """).fetchall()
    connection.close()
    return render_template(
        "pages/response_action_history.html",
        module=MODULES["response"],
        active_module="response",
        actions=actions,
    )


# =========================================================
# REPORTS - IOC INTELLIGENCE
# =========================================================

@app.route("/reports/ioc-intelligence")
@login_required
def reports_ioc_intelligence():
    connection = get_connection()
    total_iocs = connection.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    unique_iocs = connection.execute("""
        SELECT COUNT(DISTINCT LOWER(TRIM(ioc_value))) FROM iocs
    """).fetchone()[0]
    total_ioc_types = connection.execute("SELECT COUNT(DISTINCT ioc_type) FROM iocs").fetchone()[0]
    affected_datasets = connection.execute("SELECT COUNT(DISTINCT upload_id) FROM iocs").fetchone()[0]
    ioc_types = connection.execute("""
        SELECT ioc_type, COUNT(*) AS ioc_count
        FROM iocs GROUP BY ioc_type ORDER BY ioc_count DESC, ioc_type ASC
    """).fetchall()
    recent_iocs = connection.execute("""
        SELECT i.id, i.ioc_type, i.ioc_value, i.source_field, i.host,
               i.username, i.status, i.extracted_at,
               t.original_name AS source_file
        FROM iocs i
        LEFT JOIN telemetry_uploads t ON i.upload_id = t.id
        ORDER BY i.id DESC LIMIT 100
    """).fetchall()
    connection.close()
    generated_at = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")
    return render_template(
        "pages/ioc_report.html", module=MODULES["reports"], active_module="reports",
        total_iocs=total_iocs, unique_iocs=unique_iocs, total_ioc_types=total_ioc_types,
        affected_datasets=affected_datasets, ioc_types=ioc_types,
        recent_iocs=recent_iocs, generated_at=generated_at,
    )


# =========================================================
# REPORTS - DETECTION COVERAGE
# =========================================================

@app.route("/reports/detection-coverage")
@login_required
def reports_detection_coverage():
    connection = get_connection()
    total_detections = connection.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
    unique_rules = connection.execute("SELECT COUNT(DISTINCT rule_id) FROM detections").fetchone()[0]
    unique_techniques = connection.execute("""
        SELECT COUNT(DISTINCT mitre_technique) FROM detections
        WHERE mitre_technique IS NOT NULL AND TRIM(mitre_technique) != ''
    """).fetchone()[0]
    open_detections = connection.execute("""
        SELECT COUNT(*) FROM detections
        WHERE LOWER(status) NOT IN ('closed', 'false positive')
    """).fetchone()[0]
    severity_counts = connection.execute("""
        SELECT
            SUM(CASE WHEN LOWER(severity)='critical' THEN 1 ELSE 0 END) AS critical_count,
            SUM(CASE WHEN LOWER(severity)='high' THEN 1 ELSE 0 END) AS high_count,
            SUM(CASE WHEN LOWER(severity)='medium' THEN 1 ELSE 0 END) AS medium_count,
            SUM(CASE WHEN LOWER(severity)='low' THEN 1 ELSE 0 END) AS low_count
        FROM detections
    """).fetchone()
    rule_coverage = connection.execute("""
        SELECT rule_id, rule_name, severity, mitre_technique,
               COUNT(*) AS trigger_count,
               COUNT(DISTINCT upload_id) AS dataset_count,
               COUNT(DISTINCT NULLIF(TRIM(host), '')) AS host_count,
               MAX(detected_at) AS last_triggered
        FROM detections
        GROUP BY rule_id, rule_name, severity, mitre_technique
        ORDER BY trigger_count DESC, rule_name ASC
    """).fetchall()
    mitre_coverage = connection.execute("""
        SELECT mitre_technique, COUNT(*) AS detection_count,
               COUNT(DISTINCT rule_id) AS rule_count
        FROM detections
        WHERE mitre_technique IS NOT NULL AND TRIM(mitre_technique) != ''
        GROUP BY mitre_technique
        ORDER BY detection_count DESC, mitre_technique ASC
    """).fetchall()
    detection_statuses = connection.execute("""
        SELECT status, COUNT(*) AS status_count
        FROM detections GROUP BY status ORDER BY status_count DESC, status ASC
    """).fetchall()
    connection.close()
    generated_at = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")
    return render_template(
        "pages/detection_coverage_report.html", module=MODULES["reports"], active_module="reports",
        total_detections=total_detections, unique_rules=unique_rules,
        unique_techniques=unique_techniques, open_detections=open_detections,
        critical_detections=severity_counts["critical_count"] or 0,
        high_detections=severity_counts["high_count"] or 0,
        medium_detections=severity_counts["medium_count"] or 0,
        low_detections=severity_counts["low_count"] or 0,
        rule_coverage=rule_coverage, mitre_coverage=mitre_coverage,
        detection_statuses=detection_statuses, generated_at=generated_at,
        configured_rule_count=len(DETECTION_RULE_CATALOG),
        configured_technique_count=len(MITRE_TECHNIQUE_CATALOG),
    )


# =========================================================
# REPORTS - INCIDENTS
# =========================================================

@app.route("/reports/incidents")
@login_required
def reports_incidents():
    connection = get_connection()
    total_incidents = connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    status_counts = {row["status"]: row["count"] for row in connection.execute(
        "SELECT status, COUNT(*) AS count FROM incidents GROUP BY status"
    ).fetchall()}
    severity_counts = connection.execute("""
        SELECT
            SUM(CASE WHEN LOWER(severity)='critical' THEN 1 ELSE 0 END) AS critical_count,
            SUM(CASE WHEN LOWER(severity)='high' THEN 1 ELSE 0 END) AS high_count,
            SUM(CASE WHEN LOWER(severity)='medium' THEN 1 ELSE 0 END) AS medium_count,
            SUM(CASE WHEN LOWER(severity)='low' THEN 1 ELSE 0 END) AS low_count
        FROM incidents
    """).fetchone()
    linked_detection_count = connection.execute(
        "SELECT COUNT(*) FROM incidents WHERE linked_detection_id IS NOT NULL"
    ).fetchone()[0]
    linked_ioc_count = connection.execute(
        "SELECT COUNT(*) FROM incidents WHERE linked_ioc_id IS NOT NULL"
    ).fetchone()[0]
    incidents = connection.execute("""
        SELECT i.id, i.title, i.summary, i.severity, i.status, i.host, i.username,
               i.source_ip, i.created_at, i.updated_at,
               creator.full_name AS created_by, assignee.full_name AS assigned_to_name,
               d.rule_id AS detection_rule_id, d.rule_name AS detection_rule_name,
               d.mitre_technique AS mitre_technique,
               x.ioc_type AS linked_ioc_type, x.ioc_value AS linked_ioc_value
        FROM incidents i
        LEFT JOIN users creator ON i.user_id = creator.id
        LEFT JOIN users assignee ON i.assigned_to = assignee.id
        LEFT JOIN detections d ON i.linked_detection_id = d.id
        LEFT JOIN iocs x ON i.linked_ioc_id = x.id
        ORDER BY i.id DESC LIMIT 100
    """).fetchall()
    connection.close()
    critical = severity_counts["critical_count"] or 0
    high = severity_counts["high_count"] or 0
    medium = severity_counts["medium_count"] or 0
    low = severity_counts["low_count"] or 0
    highest_severity = "Critical" if critical else "High" if high else "Medium" if medium else "Low" if low else "No Incidents"
    closed = status_counts.get("Closed", 0)
    if total_incidents == 0:
        summary_text = "No analyst-created incidents are currently stored in AegisTrace."
    else:
        summary_text = (
            f"AegisTrace currently contains {total_incidents} incident(s), with "
            f"{total_incidents - closed} active and {closed} closed. "
            f"The highest recorded incident severity is {highest_severity}."
        )
    generated_at = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")
    return render_template(
        "pages/incident_report.html", module=MODULES["reports"], active_module="reports",
        total_incidents=total_incidents,
        open_incidents=status_counts.get("Open", 0),
        investigating_incidents=status_counts.get("Investigating", 0),
        contained_incidents=status_counts.get("Contained", 0),
        closed_incidents=closed,
        critical_incidents=critical, high_incidents=high,
        medium_incidents=medium, low_incidents=low,
        linked_detection_count=linked_detection_count,
        linked_ioc_count=linked_ioc_count, incidents=incidents,
        highest_severity=highest_severity, summary_text=summary_text,
        generated_at=generated_at,
    )


# =========================================================
# REPORTS - METHODOLOGY
# =========================================================

@app.route("/reports/methodology")
@login_required
def reports_methodology():
    pipeline = [
        {"step":"01", "title":"Telemetry Upload", "description":"Analysts upload supported CSV or JSON security telemetry."},
        {"step":"02", "title":"Validation", "description":"AegisTrace validates extension and configured upload size limits."},
        {"step":"03", "title":"Parsing", "description":"CSV or JSON records are parsed into individual event objects."},
        {"step":"04", "title":"Normalization", "description":"Source fields are mapped into the common AegisTrace security schema."},
        {"step":"05", "title":"Event Storage", "description":"Normalized events are stored in SQLite for later analysis."},
        {"step":"06", "title":"Detection", "description":"Configured detection logic analyzes normalized events for suspicious patterns."},
        {"step":"07", "title":"IOC Extraction", "description":"Observable IP addresses, domains, URLs and supported hashes are extracted."},
        {"step":"08", "title":"Investigation & Reporting", "description":"Analysts review evidence, run hunts, manage incidents and generate reports."},
    ]
    limitations = [
        "AegisTrace currently accepts CSV and JSON telemetry; native EVTX ingestion is not implemented.",
        "Detection findings are rule-based and require analyst validation before being treated as confirmed malicious activity.",
        "Extracted indicators are observed values and are not automatically classified as malicious.",
        "Response actions and blocklist entries are internal workflow records; AegisTrace does not modify the host OS or network firewall.",
        "Observed coverage depends on the telemetry analyzed; an untriggered rule does not prove that a technique is absent.",
    ]
    generated_at = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")
    return render_template(
        "pages/methodology_report.html", module=MODULES["reports"], active_module="reports",
        pipeline=pipeline, normalized_fields=STANDARD_SCHEMA,
        detection_rules=DETECTION_RULE_CATALOG,
        ioc_types=["IP", "DOMAIN", "URL", "MD5", "SHA1", "SHA256"],
        limitations=limitations, generated_at=generated_at,
    )


@app.route("/reports/threat-hunts")
@login_required
def reports_threat_hunts():
    connection = get_connection()
    runs = connection.execute("""
        SELECT h.*, u.full_name AS analyst_name
        FROM threat_hunt_runs h
        LEFT JOIN users u ON h.user_id = u.id
        ORDER BY h.id DESC LIMIT 100
    """).fetchall()
    connection.close()
    generated_at = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")
    return render_template(
        "pages/threat_hunt_report.html", module=MODULES["reports"], active_module="reports",
        hunts=THREAT_HUNTS, runs=runs, generated_at=generated_at,
    )


@app.route("/reports/mitre-coverage")
@login_required
def reports_mitre_coverage():
    connection = get_connection()
    triggered = connection.execute("""
        SELECT mitre_technique, COUNT(*) AS detection_count,
               COUNT(DISTINCT rule_id) AS triggered_rule_count
        FROM detections
        WHERE mitre_technique IS NOT NULL AND TRIM(mitre_technique) != ''
        GROUP BY mitre_technique
    """).fetchall()
    connection.close()
    triggered_map = {row["mitre_technique"]: dict(row) for row in triggered}
    coverage = []
    for technique in MITRE_TECHNIQUE_CATALOG:
        item = dict(technique)
        item["configured_rules"] = sum(1 for r in DETECTION_RULE_CATALOG if r["mitre"] == technique["id"])
        item["detection_count"] = triggered_map.get(technique["id"], {}).get("detection_count", 0)
        item["triggered_rule_count"] = triggered_map.get(technique["id"], {}).get("triggered_rule_count", 0)
        coverage.append(item)
    generated_at = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")
    return render_template(
        "pages/mitre_coverage_report.html", module=MODULES["reports"], active_module="reports",
        coverage=coverage, configured_rule_count=len(DETECTION_RULE_CATALOG),
        technique_count=len(MITRE_TECHNIQUE_CATALOG), generated_at=generated_at,
    )


# =========================================================
# ADMIN - AUDIT AND DATA MANAGEMENT
# =========================================================

@app.route("/admin/audit")
@admin_required
def admin_audit_history():
    connection = get_connection()
    entries = connection.execute("""
        SELECT a.*, u.full_name AS admin_name, u.email AS admin_email
        FROM admin_audit_log a
        LEFT JOIN users u ON a.admin_user_id = u.id
        ORDER BY a.id DESC LIMIT 500
    """).fetchall()
    connection.close()
    return render_template(
        "pages/admin_audit.html", module=ADMIN_MODULE, active_module="admin", entries=entries
    )


@app.route("/admin/users/<int:user_id>/delete-data", methods=["POST"])
@admin_required
def admin_delete_user_data(user_id):
    if user_id == session.get("user_id"):
        flash("Use another administrator account for destructive cleanup of your own data.", "error")
        return redirect(url_for("admin_users"))
    connection = get_connection()
    user = connection.execute(
        "SELECT id, full_name, email FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if user is None:
        connection.close()
        abort(404)
    uploads = connection.execute(
        "SELECT id, stored_name, normalized_name FROM telemetry_uploads WHERE user_id = ?",
        (user_id,),
    ).fetchall()
    upload_ids = [row["id"] for row in uploads]
    try:
        if upload_ids:
            placeholders = ",".join("?" for _ in upload_ids)
            connection.execute(
                f"DELETE FROM incidents WHERE linked_detection_id IN (SELECT id FROM detections WHERE upload_id IN ({placeholders})) OR linked_ioc_id IN (SELECT id FROM iocs WHERE upload_id IN ({placeholders}))",
                upload_ids + upload_ids,
            )
            connection.execute(f"DELETE FROM detections WHERE upload_id IN ({placeholders})", upload_ids)
            connection.execute(f"DELETE FROM iocs WHERE upload_id IN ({placeholders})", upload_ids)
            connection.execute(f"DELETE FROM events WHERE upload_id IN ({placeholders})", upload_ids)
            connection.execute(f"DELETE FROM telemetry_uploads WHERE id IN ({placeholders})", upload_ids)
        connection.execute("DELETE FROM incidents WHERE user_id = ?", (user_id,))
        connection.execute("DELETE FROM threat_hunt_runs WHERE user_id = ?", (user_id,))
        connection.execute("DELETE FROM response_actions WHERE user_id = ?", (user_id,))
        connection.execute("DELETE FROM response_blocklist WHERE user_id = ?", (user_id,))
        connection.commit()
    except Exception:
        connection.rollback()
        connection.close()
        raise
    connection.close()
    for row in uploads:
        if row["stored_name"]:
            try: (UPLOAD_FOLDER / Path(row["stored_name"]).name).unlink(missing_ok=True)
            except OSError: pass
        if row["normalized_name"]:
            try: (PROCESSED_FOLDER / Path(row["normalized_name"]).name).unlink(missing_ok=True)
            except OSError: pass
    record_admin_audit(
        "Delete User Data", "user", user_id, user["full_name"],
        f"Deleted project data owned by {user['email']} while preserving the user account."
    )
    flash(f"Project data for {user['full_name']} was deleted; the account remains active.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/telemetry/purge", methods=["GET", "POST"])
@admin_required
def admin_purge_telemetry():
    if request.method == "GET":
        return render_template(
            "pages/admin_purge_telemetry.html", module=ADMIN_MODULE, active_module="admin"
        )
    confirmation = request.form.get("confirmation", "").strip()
    if confirmation != "PURGE TELEMETRY":
        flash("Confirmation text did not match. Nothing was deleted.", "error")
        return redirect(url_for("admin_purge_telemetry"))
    connection = get_connection()
    uploads = connection.execute(
        "SELECT stored_name, normalized_name FROM telemetry_uploads"
    ).fetchall()
    try:
        connection.execute("DELETE FROM incidents")
        connection.execute("DELETE FROM detections")
        connection.execute("DELETE FROM iocs")
        connection.execute("DELETE FROM events")
        connection.execute("DELETE FROM telemetry_uploads")
        connection.execute("DELETE FROM threat_hunt_runs")
        connection.commit()
    except Exception:
        connection.rollback()
        connection.close()
        raise
    connection.close()
    for row in uploads:
        if row["stored_name"]:
            try: (UPLOAD_FOLDER / Path(row["stored_name"]).name).unlink(missing_ok=True)
            except OSError: pass
        if row["normalized_name"]:
            try: (PROCESSED_FOLDER / Path(row["normalized_name"]).name).unlink(missing_ok=True)
            except OSError: pass
    record_admin_audit(
        "Purge Telemetry", "telemetry", "all", "All telemetry",
        "Deleted telemetry uploads, normalized events, detections, IOCs, incidents and hunt runs. User accounts were preserved."
    )
    flash("Telemetry-derived project data was purged. User accounts were preserved.", "success")
    return redirect(url_for("admin_telemetry"))


# =========================================================
# MODULE PAGES
# =========================================================


@app.route(
    "/<module_name>"
)
def module_page(
    module_name
):

    if "user_id" not in session:

        return redirect(
            url_for(
                "login"
            )
        )

    if module_name not in MODULES:

        return render_template(

            "pages/404.html",

            module=
                MODULES[
                    "overview"
                ],

            active_module=
                "overview",

        ), 404

    if module_name == "overview":

        return redirect(
            url_for(
                "index"
            )
        )

    if module_name == "reports":

        return redirect(
            url_for(
                "reports_dashboard"
            )
        )

    if module_name == "detection":

        return redirect(
            url_for("detection_feed")
        )

    if module_name == "investigation":

        return redirect(
            url_for("investigation_iocs")
        )

    if module_name == "response":

        return redirect(
            url_for("response_recommended_actions")
        )

    recent_uploads = []
    latest_analysis = None
    detections = []
    iocs = []


    if module_name == "telemetry":

        connection = get_connection()

        recent_uploads = connection.execute("""
        SELECT
            telemetry_uploads.*,
            users.full_name AS uploaded_by

        FROM telemetry_uploads

        LEFT JOIN users
            ON telemetry_uploads.user_id =
               users.id

        ORDER BY
            telemetry_uploads.id DESC

        LIMIT 10
        """).fetchall()

        connection.close()

        if recent_uploads:

            latest = recent_uploads[0]

            def safe_json(value):

                try:

                    return json.loads(
                        value
                        or "[]"
                    )

                except (
                    json.JSONDecodeError,
                    TypeError
                ):

                    return []

            latest_analysis = {

                "id":
                    latest[
                        "id"
                    ],

                "original_name":
                    latest[
                        "original_name"
                    ],

                "file_type":
                    latest[
                        "file_type"
                    ],

                "file_size":
                    latest[
                        "file_size"
                    ],

                "status":
                    latest[
                        "status"
                    ],

                "event_count":
                    latest[
                        "event_count"
                    ],

                "field_count":
                    latest[
                        "field_count"
                    ],

                "fields":
                    safe_json(
                        latest[
                            "fields_json"
                        ]
                    ),

                "preview":
                    safe_json(
                        latest[
                            "preview_json"
                        ]
                    ),

                "error_message":
                    latest[
                        "error_message"
                    ],

                "normalized_name":
                    latest[
                        "normalized_name"
                    ],

                "normalization_status":
                    latest[
                        "normalization_status"
                    ],

                "normalized_event_count":
                    latest[
                        "normalized_event_count"
                    ],

                "normalized_fields":
                    safe_json(
                        latest[
                            "normalized_fields_json"
                        ]
                    ),

                "normalized_preview":
                    safe_json(
                        latest[
                            "normalized_preview_json"
                        ]
                    ),

                "normalization_error":
                    latest[
                        "normalization_error"
                    ],

                "detection_status":
                    latest[
                        "detection_status"
                    ],

                "detection_count":
                    latest[
                        "detection_count"
                    ],

                "ioc_status":
                    latest[
                        "ioc_status"
                    ],

                "ioc_count":
                    latest[
                        "ioc_count"
                    ],
            }


    if module_name == "detection":

        connection = get_connection()

        detections = connection.execute("""
        SELECT
            detections.*,
            telemetry_uploads.original_name

        FROM detections

        LEFT JOIN telemetry_uploads
            ON detections.upload_id =
               telemetry_uploads.id

        ORDER BY
            detections.id DESC

        LIMIT 100
        """).fetchall()

        connection.close()


    if module_name == "investigation":

        connection = get_connection()

        iocs = connection.execute("""
        SELECT
            iocs.*,
            telemetry_uploads.original_name

        FROM iocs

        LEFT JOIN telemetry_uploads
            ON iocs.upload_id =
               telemetry_uploads.id

        ORDER BY
            iocs.id DESC

        LIMIT 200
        """).fetchall()

        connection.close()


    return render_template(

        "pages/module.html",

        module=
            MODULES[
                module_name
            ],

        active_module=
            module_name,

        recent_uploads=
            recent_uploads,

        latest_analysis=
            latest_analysis,

        detections=
            detections,

        iocs=
            iocs,

    )


# =========================================================
# LARGE FILE
# =========================================================

@app.errorhandler(413)
def file_too_large(
    error
):

    flash(
        "File is too large. "
        "Maximum upload size is 10 MB.",
        "error"
    )

    return redirect(

        url_for(
            "module_page",
            module_name="telemetry"
        )

    )



# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )