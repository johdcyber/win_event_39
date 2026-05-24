---
name: llm-proxy-check
description: Audit the current diff for LLM proxy compliance — no direct provider SDK imports in services, PHI redaction in place, model routing declared, output schemas enforced, audit logging on every call, no PHI in cache keys or logs.
---

# Skill: llm-proxy-check

## When to use

Before merging any change that adds, modifies, or wires up an LLM call, prompt, or agent.

## Args

```
/llm-proxy-check [pr=<number>] [base=<branch>]
```

## Steps

1. Invoke **llm-proxy-engineer** with the diff scope.
2. Verify:
   - No service code imports `anthropic`, `openai`, or another provider SDK directly.
   - Every new LLM call goes through the proxy client and declares a `task_class`.
   - Every prompt has a versioned ref; no inline strings.
   - Every output has a JSON schema and a retry policy.
   - PHI redaction runs on inputs; redaction failures reject the call.
   - Audit log entry is emitted with hashes only — no raw prompt/response.
   - Prompt cache keys are PHI-free; PHI-bearing prompts bypass cache.
   - Tool allowlist updated in the agent manifest for any new tool call.
   - Determinism settings (temperature, top_p, seed) pinned in the manifest.
3. Print PASS/FAIL with file:line for each violation.
4. On FAIL, do not bypass — fix the underlying issue.
