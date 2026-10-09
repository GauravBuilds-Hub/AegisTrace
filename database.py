import sqlite3
from pathlib import Path


# =========================================================
# DATABASE PATH
# =========================================================

BASE_DIR = Path(__file__).resolve().parent

DATABASE_PATH = BASE_DIR / "aegistrace.db"


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_connection():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    return connection


# =========================================================
# USERS
# =========================================================

def create_users_table():

    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            full_name TEXT NOT NULL,

            email TEXT NOT NULL UNIQUE,

            password_hash TEXT NOT NULL,

            role TEXT NOT NULL DEFAULT 'Analyst'
        )
    """)

    connection.commit()
    connection.close()


# =========================================================
# USER MIGRATIONS
# =========================================================

def add_missing_user_columns():

    connection = get_connection()

    columns = connection.execute("""
        PRAGMA table_info(users)
    """).fetchall()

    existing_columns = {
        column["name"]
        for column in columns
    }


    if "role" not in existing_columns:

        connection.execute("""
            ALTER TABLE users
            ADD COLUMN role TEXT NOT NULL
            DEFAULT 'Analyst'
        """)


    connection.commit()
    connection.close()


# =========================================================
# TELEMETRY UPLOADS
# =========================================================

def create_telemetry_table():

    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS telemetry_uploads (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER NOT NULL,

            original_name TEXT NOT NULL,

            stored_name TEXT NOT NULL,

            file_type TEXT,

            file_size INTEGER DEFAULT 0,

            status TEXT DEFAULT 'Pending',

            uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,

            event_count INTEGER DEFAULT 0,

            field_count INTEGER DEFAULT 0,

            fields_json TEXT,

            preview_json TEXT,

            error_message TEXT,

            normalized_name TEXT,

            normalization_status TEXT DEFAULT 'Pending',

            normalized_event_count INTEGER DEFAULT 0,

            normalized_fields_json TEXT,

            normalized_preview_json TEXT,

            normalization_error TEXT,

            detection_status TEXT DEFAULT 'Pending',

            detection_count INTEGER DEFAULT 0,

            ioc_status TEXT DEFAULT 'Pending',

            ioc_count INTEGER DEFAULT 0,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
        )
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_telemetry_user
        ON telemetry_uploads(user_id)
    """)

    connection.commit()
    connection.close()


# =========================================================
# TELEMETRY MIGRATIONS
# =========================================================

def add_missing_telemetry_columns():

    connection = get_connection()

    columns = connection.execute("""
        PRAGMA table_info(telemetry_uploads)
    """).fetchall()

    existing_columns = {
        column["name"]
        for column in columns
    }


    required_columns = {

        "event_count":
            "INTEGER DEFAULT 0",

        "field_count":
            "INTEGER DEFAULT 0",

        "fields_json":
            "TEXT",

        "preview_json":
            "TEXT",

        "error_message":
            "TEXT",

        "normalized_name":
            "TEXT",

        "normalization_status":
            "TEXT DEFAULT 'Pending'",

        "normalized_event_count":
            "INTEGER DEFAULT 0",

        "normalized_fields_json":
            "TEXT",

        "normalized_preview_json":
            "TEXT",

        "normalization_error":
            "TEXT",

        "detection_status":
            "TEXT DEFAULT 'Pending'",

        "detection_count":
            "INTEGER DEFAULT 0",

        "ioc_status":
            "TEXT DEFAULT 'Pending'",

        "ioc_count":
            "INTEGER DEFAULT 0",
    }


    for column_name, column_definition in required_columns.items():

        if column_name not in existing_columns:

            connection.execute(
                f"""
                ALTER TABLE telemetry_uploads
                ADD COLUMN
                {column_name}
                {column_definition}
                """
            )


    connection.commit()
    connection.close()


# =========================================================
# EVENTS
# =========================================================

def create_events_table():

    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS events (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            upload_id INTEGER NOT NULL,

            user_id INTEGER NOT NULL,

            timestamp TEXT,

            event_id TEXT,

            host TEXT,

            username TEXT,

            source_ip TEXT,

            destination_ip TEXT,

            process_name TEXT,

            command_line TEXT,

            event_type TEXT,

            url TEXT,

            domain TEXT,

            hash_value TEXT,

            raw_event_json TEXT,

            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (upload_id)
                REFERENCES telemetry_uploads(id),

            FOREIGN KEY (user_id)
                REFERENCES users(id)
        )
    """)


    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_events_upload
        ON events(upload_id)
    """)


    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_events_host
        ON events(host)
    """)


    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_events_username
        ON events(username)
    """)


    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_events_source_ip
        ON events(source_ip)
    """)


    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_events_process
        ON events(process_name)
    """)


    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_events_event_id
        ON events(event_id)
    """)


    connection.commit()
    connection.close()


# =========================================================
# DETECTIONS
# =========================================================

def create_detections_table():

    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS detections (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            upload_id INTEGER NOT NULL,

            user_id INTEGER NOT NULL,

            rule_id TEXT NOT NULL,

            rule_name TEXT NOT NULL,

            severity TEXT NOT NULL,

            description TEXT,

            mitre_technique TEXT,

            host TEXT,

            username TEXT,

            source_ip TEXT,

            event_id TEXT,

            event_json TEXT,

            status TEXT NOT NULL DEFAULT 'Open',

            detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (upload_id)
                REFERENCES telemetry_uploads(id),

            FOREIGN KEY (user_id)
                REFERENCES users(id)
        )
    """)


    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_detections_upload
        ON detections(upload_id)
    """)


    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_detections_rule
        ON detections(rule_id)
    """)


    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_detections_host
        ON detections(host)
    """)


    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_detections_username
        ON detections(username)
    """)


    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_detections_severity
        ON detections(severity)
    """)


    connection.commit()
    connection.close()


# =========================================================
# IOCS
# =========================================================

def create_iocs_table():

    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS iocs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            upload_id INTEGER NOT NULL,

            user_id INTEGER NOT NULL,

            ioc_type TEXT NOT NULL,

            ioc_value TEXT NOT NULL,

            source_field TEXT,

            host TEXT,

            username TEXT,

            context_json TEXT,

            status TEXT NOT NULL DEFAULT 'Observed',

            extracted_at DATETIME DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (upload_id)
                REFERENCES telemetry_uploads(id),

            FOREIGN KEY (user_id)
                REFERENCES users(id)
        )
    """)


    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_iocs_upload
        ON iocs(upload_id)
    """)


    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_iocs_type
        ON iocs(ioc_type)
    """)


    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_iocs_value
        ON iocs(ioc_value)
    """)


    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_iocs_host
        ON iocs(host)
    """)


    connection.commit()
    connection.close()


# =========================================================
# INCIDENTS
# =========================================================

def create_incidents_table():

    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS incidents (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER NOT NULL,

            title TEXT NOT NULL,

            summary TEXT,

            severity TEXT NOT NULL DEFAULT 'Medium',

            status TEXT NOT NULL DEFAULT 'Open',

            assigned_to INTEGER,

            linked_detection_id INTEGER,

            linked_ioc_id INTEGER,

            host TEXT,

            username TEXT,

            source_ip TEXT,

            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
                REFERENCES users(id),

            FOREIGN KEY (assigned_to)
                REFERENCES users(id),

            FOREIGN KEY (linked_detection_id)
                REFERENCES detections(id),

            FOREIGN KEY (linked_ioc_id)
                REFERENCES iocs(id)
        )
    """)


    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_incidents_status
        ON incidents(status)
    """)


    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_incidents_severity
        ON incidents(severity)
    """)


    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_incidents_assigned
        ON incidents(assigned_to)
    """)


    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_incidents_detection
        ON incidents(linked_detection_id)
    """)


    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_incidents_ioc
        ON incidents(linked_ioc_id)
    """)


    connection.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_incidents_host
        ON incidents(host)
    """)


    connection.commit()
    connection.close()




# =========================================================
# THREAT HUNT RUNS
# =========================================================

def create_threat_hunt_runs_table():

    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS threat_hunt_runs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            hunt_id TEXT NOT NULL,
            title TEXT NOT NULL,
            hypothesis TEXT,
            match_count INTEGER DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'Completed',
            conclusion TEXT,
            evidence_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_hunt_runs_hunt
        ON threat_hunt_runs(hunt_id)
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_hunt_runs_created
        ON threat_hunt_runs(created_at)
    """)

    connection.commit()
    connection.close()


# =========================================================
# RESPONSE BLOCKLIST
# =========================================================

def create_response_blocklist_table():

    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS response_blocklist (

            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            indicator_type TEXT NOT NULL,
            indicator_value TEXT NOT NULL,
            reason TEXT,
            status TEXT NOT NULL DEFAULT 'Proposed',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    connection.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_blocklist_value
        ON response_blocklist(indicator_type, indicator_value)
    """)

    connection.commit()
    connection.close()


# =========================================================
# RESPONSE ACTION HISTORY
# =========================================================

def create_response_actions_table():

    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS response_actions (

            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action_type TEXT NOT NULL,
            target_type TEXT,
            target_value TEXT,
            notes TEXT,
            status TEXT NOT NULL DEFAULT 'Recorded',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_response_actions_created
        ON response_actions(created_at)
    """)

    connection.commit()
    connection.close()


# =========================================================
# ADMIN AUDIT LOG
# =========================================================

def create_admin_audit_log_table():

    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS admin_audit_log (

            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_user_id INTEGER,
            action TEXT NOT NULL,
            target_type TEXT,
            target_id TEXT,
            target_name TEXT,
            details TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (admin_user_id) REFERENCES users(id)
        )
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_admin_audit_created
        ON admin_audit_log(created_at)
    """)

    connection.commit()
    connection.close()


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

def create_database():

    create_users_table()

    add_missing_user_columns()

    create_telemetry_table()

    add_missing_telemetry_columns()

    create_events_table()

    create_detections_table()

    create_iocs_table()

    create_incidents_table()

    create_threat_hunt_runs_table()

    create_response_blocklist_table()

    create_response_actions_table()

    create_admin_audit_log_table()


# =========================================================
# RUN DATABASE SETUP
# =========================================================

if __name__ == "__main__":

    create_database()

    print(
        "AegisTrace database ready"
    )

    print(
        "Users table ready"
    )

    print(
        "Telemetry table ready"
    )

    print(
        "Events table ready"
    )

    print(
        "Detections table ready"
    )

    print(
        "IOCs table ready"
    )

    print(
        "Incidents table ready"
    )