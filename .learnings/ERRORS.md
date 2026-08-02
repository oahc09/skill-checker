# Errors

## [ERR-20260802-001] optional-directory-probe

**Logged**: 2026-08-02T00:00:00+08:00
**Priority**: low
**Status**: resolved
**Area**: docs

### Summary

Probing a not-yet-created optional directory returned a non-zero exit code.

### Error

```text
Get-ChildItem returned exit code 1 because the docs directory did not exist.
```

### Context

- The design workflow checked whether `docs/` already existed.
- A missing optional directory is expected and should not fail the orchestration call.

### Suggested Fix

Use `Test-Path` before listing an optional directory, or handle the missing path as an expected result.

### Metadata

- Reproducible: yes
- Related Files: docs/

### Resolution

- **Resolved**: 2026-08-02T00:00:00+08:00
- **Notes**: The workflow proceeded by creating the required document path directly.

---
