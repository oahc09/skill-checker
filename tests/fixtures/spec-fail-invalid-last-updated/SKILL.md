---
name: spec-fail-invalid-last-updated
description: Validate metadata update dates. Use when checking whether malformed last-updated values are rejected.
license: MIT
metadata:
  author: qa-team
  version: "1.0.0"
  last-updated: "2026-02-30"
  keywords: metadata, date validation
---

# Invalid Last Updated

## Workflow

1. Read the metadata date.
2. Validate its format and calendar value.
3. Report the invalid date.
