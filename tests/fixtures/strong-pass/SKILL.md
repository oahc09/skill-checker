---
name: strong-pass
description: Build polished audit feedback for creative coding skills and explain when each workflow applies. Use when an agent needs to evaluate a skill with staged instructions, clear constraints, and a shareable review summary.
metadata:
  owner: skill-team
  category: review
compatibility: generic-agent
allowed-tools: shell_command apply_patch
---

# Strong Pass

## Principle

Work in visible phases so another agent can follow the review without guessing.

## Workflow

1. Inspect the target skill and confirm the requested audience.
2. Evaluate the frontmatter, body structure, and output expectations.
3. Record the exact problems, explain the impact, and provide repair steps.

## Output

Return a concise result, then list the highest-priority fixes and any remaining warnings.
