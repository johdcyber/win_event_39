---
name: airway-screen
description: Segment the pharyngeal airway on a CBCT and report minimum cross-sectional area, volume, narrowing location, and asymmetry. Screening only — not a sleep study substitute.
---

# Skill: airway-screen

## Args

```
/airway-screen <dicom_path> [prior=<prior_dicom_path>]
```

## Steps

1. Run **dicom-ingest-qc**.
2. Invoke **cbct-radiology-reader** with `mode=airway`.
3. Return:
   - Min CSA (mm²) and location (nasopharynx / oropharynx / hypopharynx).
   - Volume (mm³).
   - Lateral / AP asymmetry.
   - Longitudinal delta if prior provided.
   - Recommendation: clinical correlation, ENT or sleep medicine referral as appropriate.
   - Disclaimer + "screening only — not a sleep study replacement."
