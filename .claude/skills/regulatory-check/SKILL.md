---
name: regulatory-check
description: Audit the current diff (or a PR) for FDA SaMD, HIPAA/GDPR, IEC 62304, and clinical-decision-support positioning risk before merge. Returns a pass/fail with specific findings.
---

# Skill: regulatory-check

## Args

```
/regulatory-check [pr=<number>] [base=<branch>]
```

## Steps

1. Determine the diff scope (current branch vs base, or a specific PR via the GitHub MCP tools).
2. Invoke the **regulatory-compliance-reviewer** subagent with the diff.
3. Print the structured PASS/FAIL report. On FAIL, list each blocker with file:line and recommended fix.
4. Do not auto-merge. Do not weaken checks to make this pass.
