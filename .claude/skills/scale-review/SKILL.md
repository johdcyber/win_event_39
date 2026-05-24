---
name: scale-review
description: Capacity, latency, and cost review for a change — GPU/CPU pool sizing, queue behavior under load, per-tenant quotas, multi-region residency, DR posture, and any cost-driven model-routing changes.
---

# Skill: scale-review

## When to use

Before merging changes that affect inference pipelines, autoscaling, queues, region topology, or model routing/cost.

## Args

```
/scale-review [pr=<number>] [base=<branch>]
```

## Steps

1. Invoke **platform-sre** with the diff.
2. Verify:
   - GPU autoscaling keyed on queue depth + p95 latency, not CPU.
   - Per-tenant quotas in place; no single tenant can starve others.
   - End-to-end backpressure preserved; no silent case drops.
   - No cross-region replication of patient data added.
   - Audit pipeline cannot scale to zero.
   - Any cost-driven model swap is routed through **llm-proxy-engineer** and **regulatory-compliance-reviewer**.
   - DR RPO/RTO targets still met; observability tags include `case_id` and `tenant_id`.
   - SLO impact estimated for the changed surface.
3. Print PASS/FAIL plus a short capacity / cost note.
