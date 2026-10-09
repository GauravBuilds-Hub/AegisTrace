# Submission Finish Steps

The application code is ready. The following items must be generated from **real project data** rather than fabricated:

1. Open **Investigation → Threat Hunting** and run both HUNT-001 and HUNT-002.
2. Review the returned detections and related telemetry.
3. Create incidents only for findings you can justify from the evidence. Use **Detection Feed → Incident** or **IOC Intelligence → Create**.
4. Update incident status/summary, then open **Reports → Incident Reports** and use **Print / Save PDF**.
5. Save real screenshots or exported notes under `evidence/hunts/`, `evidence/incidents/` and `evidence/rule-tests/`.

This workflow is intentional: AegisTrace does not auto-create fake hunt outcomes, incidents or evidence.
