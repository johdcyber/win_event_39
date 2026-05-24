---
name: analyze-ios
description: Run the intraoral-scan analysis pipeline on an STL/PLY/OBJ mesh — mesh QC, arch metrics, occlusion, wear/margin/recession findings, structured report. Pass the mesh path and optional mode (ortho | prostho | wear | recession).
---

# Skill: analyze-ios

## When to use

User asks to "analyze an intraoral scan," "check this STL," "evaluate occlusion," "check the prep margin," or provides a mesh file path.

## Args contract

```
/analyze-ios <mesh_path> [opposing=<mesh_path>] [bite=<mesh_path>] [mode=<ortho|prostho|wear|recession>]
```

## Steps

1. Invoke **intraoral-scan-analyzer** with the mesh(es) and mode hint.
2. If mesh quality is non-diagnostic, return the QC reasons and stop.
3. Return:
   - Clinician summary (top).
   - Arch metrics / occlusion summary if present.
   - Findings list.
   - Path to full structured JSON.
   - Disclaimer.

## Constraint

Never infer osseous or periapical pathology from IOS alone. If the user asks for those, recommend a CBCT or bitewing series and stop the IOS pipeline there.
