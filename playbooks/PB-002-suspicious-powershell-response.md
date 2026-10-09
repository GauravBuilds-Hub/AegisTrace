# Suspicious PowerShell Response

**Mapping:** T1059.001

## Steps

1. Review full PowerShell command line.
2. Identify host and user.
3. Inspect encoded execution indicators.
4. Review nearby process/authentication activity.
5. Extract related IOCs.
6. Search for the same IOC or command patterns elsewhere.
7. Recommend endpoint containment only after validation.
8. Preserve evidence and create an incident if confirmed suspicious.

> Guidance only. AegisTrace does not automatically change endpoint or firewall configuration.