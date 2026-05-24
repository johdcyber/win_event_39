---
name: design-review
description: Review a UI change against the clinical design system — triage color reservation, confidence-bar monochromatic rule, accessibility (WCAG 2.1 AA), PHI-leak surfaces (URLs, tooltips, telemetry), and Figma ↔ code parity. Returns pass/fail with specific findings.
---

# Skill: design-review

## When to use

Before merging any change to the clinician-facing UI, component library, or Figma sync.

## Args

```
/design-review [pr=<number>] [base=<branch>]
```

## Steps

1. Invoke **design-system-owner** and **frontend-engineer** in coordination.
2. Verify:
   - Triage colors are not used decoratively anywhere.
   - Confidence is not encoded with red/green.
   - No PHI in URLs, query strings, tooltips, telemetry events, error reporters.
   - Every clinical finding renders model version, confidence, and an evidence link.
   - Keyboard navigation works for slice scrub, finding list, and report sign-off.
   - Screen-reader labels present on measurements, triage badges, signature controls.
   - Loading and error states do not break the viewer; mask failure falls back gracefully.
   - Figma components in scope are mapped via Code Connect; deltas flagged.
3. Print PASS/FAIL with file:line for each violation.
