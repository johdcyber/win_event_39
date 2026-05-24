---
name: analyze-cbct
description: Run the full CBCT analysis pipeline on a DICOM series — ingest QC, segmentation, detection, quantification, structured report, triage. Pass the DICOM path and an optional mode (implant | ortho | tmj | airway | oncology | screening).
---

# Skill: analyze-cbct

## When to use

User asks to "analyze a CBCT," "read this scan," "run the pipeline," "score this volume," or provides a DICOM directory/zip path.

## Args contract

```
/analyze-cbct <dicom_path> [mode=<implant|ortho|tmj|airway|oncology|screening>] [prior=<prior_dicom_path>]
```

## Steps

1. Invoke the **dicom-ingest-qc** subagent with `<dicom_path>`. Halt if `go_no_go == "re-acquire"`.
2. Invoke the **cbct-radiology-reader** subagent with the validated volume reference, the mode hint, and the optional prior for longitudinal comparison.
3. If the structured report writes back to PACS/EHR, invoke the **pacs-fhir-integrator** subagent to build and send the DICOM-SR / FHIR DiagnosticReport.
4. Return to the user:
   - The clinician-readable summary (top of message).
   - Triage level (routine / follow-up / urgent / critical) on its own line.
   - Path to the full structured JSON.
   - The assistive-AI disclaimer.

## Failure handling

- Non-diagnostic image quality: return the QC report and recommend re-acquisition. Do not run downstream models.
- Out-of-validated-profile scanner: proceed with a prominent caveat in the summary and report.
- Any model inference error: return the error class and the volume reference, never the underlying PHI.
