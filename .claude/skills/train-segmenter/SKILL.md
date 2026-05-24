---
name: train-segmenter
description: Kick off (or resume) a training run for a CBCT or IOS segmentation/detection model. Handles dataset manifest checks, config diffing, run-tracking, and per-cohort metric reporting.
---

# Skill: train-segmenter

## Args

```
/train-segmenter target=<teeth|jaws|sinus|tmj|airway|ian|caries|periapical|...> config=<path> [resume=<run_id>]
```

## Steps

1. Invoke **ml-training-engineer** with the target and config.
2. Validate the dataset manifest:
   - Patient-level split (no leakage).
   - Per-cohort coverage: scanner manufacturer, voxel size bucket, age band, anatomy variant.
   - Rare-class held-out set present.
3. Launch the run with seed pinning and a versioned manifest.
4. On completion, return:
   - Overall Dice / sensitivity / specificity / HD95 / ECE.
   - Per-cohort breakdown.
   - Rare-class stress-test results.
   - Calibration plot reference.
   - Out-of-distribution detection metrics.
5. If the run is a release candidate, automatically queue **/regulatory-check** on the model-card diff and validation report.

## Hard rules

- No "tune until metric improves" without a corresponding validation set lockdown.
- No silent threshold changes — every operating point change is logged.
