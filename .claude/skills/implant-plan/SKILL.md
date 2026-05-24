---
name: implant-plan
description: Generate an implant-planning support packet for one or more tooth positions from a CBCT (and optional IOS for prosthetic-driven planning). Outputs ridge dimensions, IAN/sinus clearances, suggested implant envelopes, and surgical considerations for clinician review.
---

# Skill: implant-plan

## When to use

User says "plan implant #X," "implant workup," "check bone for implant," or provides a CBCT + tooth position.

## Args

```
/implant-plan <dicom_path> sites=<FDI_or_Universal_list> [ios=<mesh_path>] [opposing=<mesh_path>]
```

## Steps

1. Run **dicom-ingest-qc**.
2. Invoke **cbct-radiology-reader** with `mode=implant` and the site list.
3. If IOS supplied, invoke **intraoral-scan-analyzer** with `mode=prostho` for prosthetic axis context.
4. Combine into an implant-planning packet:
   - Per-site: ridge height, ridge width at crest/mid/apex, distance to IAN canal (mandibular) or sinus floor (maxillary), distance to adjacent roots, ridge angulation vs. opposing dentition.
   - Suggested implant length × diameter envelope (range, not a prescription).
   - Risk callouts: thin buccal plate, nerve proximity < 2 mm, sinus floor < 1 mm, anatomic variants.
5. Return the packet + disclaimer. State explicitly: surgical decisions and final implant selection remain with the clinician.

## Hard rules

- No autonomous surgical guide generation.
- No prescriptions or specific brand selections.
- Always include nerve/sinus/adjacent-root safety margins explicitly.
