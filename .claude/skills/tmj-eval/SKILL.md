---
name: tmj-eval
description: Bilateral TMJ evaluation from a CBCT — condylar morphology, joint space, degenerative change scoring, asymmetry.
---

# Skill: tmj-eval

## Args

```
/tmj-eval <dicom_path>
```

## Steps

1. Run **dicom-ingest-qc**.
2. Invoke **cbct-radiology-reader** with `mode=tmj`.
3. Return per-side: condylar morphology (normal / flattened / erosion / osteophyte / sclerosis), joint space (sup/ant/post), translation if available, asymmetry index.
4. Triage degenerative findings; recommend clinical correlation with TMD examination.
5. Include disclaimer.
