---
name: db-migration-review
description: Review a database migration for tenant isolation, audit-table integrity, residency, indexing, and forward-only safety with a documented rollback. Catches missing tenant_id, dropped audit rows, and cross-tenant joins.
---

# Skill: db-migration-review

## When to use

On every migration PR, schema change, or new table.

## Args

```
/db-migration-review [pr=<number>] [base=<branch>]
```

## Steps

1. Invoke **database-architect** with the diff.
2. Verify:
   - Every new table has `tenant_id` and a row-level security policy.
   - No DELETE / UPDATE on audit tables; no grant changes that enable them.
   - Forward-only migration with a documented rollback procedure.
   - Indexes match the declared access pattern; EXPLAIN included on prod-shaped data.
   - No foreign key from analytics → patient memory.
   - DICOM/IOS pixel data stays in object store, not Postgres.
   - Per-region residency unaffected.
   - Soft-delete used for clinical entities; no hard DELETE outside the governed erasure path.
3. Cross-call **memory-systems-engineer** for tier ownership and **regulatory-compliance-reviewer** for retention impact.
4. Print PASS/FAIL with file:line for each violation.
