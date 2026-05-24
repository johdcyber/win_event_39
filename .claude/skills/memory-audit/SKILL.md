---
name: memory-audit
description: Audit a memory-layer change for tenant isolation, PHI segregation, retention compliance, and audit-log integrity. Catches new tables without tenant_id, PHI flowing into vector stores, and missing audit signatures.
---

# Skill: memory-audit

## When to use

Before merging changes to schemas, storage clients, vector stores, retention sweeps, or anything that touches patient memory or audit memory.

## Args

```
/memory-audit [pr=<number>] [base=<branch>]
```

## Steps

1. Invoke **memory-systems-engineer** with the diff.
2. Verify:
   - Every new table has `tenant_id` and a row-level security policy.
   - No DELETE / UPDATE grants added to audit tables.
   - No PHI-bearing text path lands in a vector store outside the in-VPC encoder.
   - Retention windows preserved or extended; no silent shortening.
   - Per-tenant KMS keying intact for object-store writes.
   - Cross-region replication scope unchanged unless explicitly approved.
   - Erasure path goes through the governed cryptographic-shred procedure, not raw DELETE.
3. Cross-call **database-architect** for index/partition implications and **regulatory-compliance-reviewer** for retention/PHI calls.
4. Print PASS/FAIL with file:line for each violation.
