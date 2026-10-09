# HUNT-001 — Authentication Abuse Hunt

**Hypothesis:** Repeated authentication failures may indicate password guessing or brute-force activity.

**Method:** Review `AT-WIN-001` and `AT-AUTH-002` detections, source IPs, users, hosts and nearby successful logons.

**MITRE:** T1110

Run the hunt from **Investigation → Threat Hunting**. The application records the actual result; this file intentionally contains no fabricated outcome.
