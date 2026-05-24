---
name: longitudinal-compare
description: Register and compare a new CBCT (or IOS) to a prior study from the same patient. Quantifies lesion growth, bone changes, airway changes, ortho progress, and post-treatment response.
---

# Skill: longitudinal-compare

## Args

```
/longitudinal-compare current=<path> prior=<path> [task=<implant|ortho|tmj|airway|oncology|periapical>]
```

## Steps

1. Run **dicom-ingest-qc** (or IOS QC) on both inputs.
2. Rigid + non-rigid registration on a stable landmark set (e.g., cranial base for ortho, anterior maxilla for ant. arch).
3. Invoke **cbct-radiology-reader** or **intraoral-scan-analyzer** with the task hint and the prior reference.
4. Report deltas per finding: Δ volume (mm³), Δ linear (mm), Δ min CSA (airway), Δ angulation (ortho), new findings vs prior, resolved findings.
5. Triage based on direction of change (growth of a lesion is upgraded; resolution is noted).
6. Include disclaimer.

## Hard rule

If registration error exceeds the clinical tolerance for the task, report deltas as "not reliably measurable" rather than quoting numbers.
