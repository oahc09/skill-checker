---
name: skill-checker
description: Audit a SKILL.md against the Agent Skills specification, statically scan its Skill directory for security risks, and generate an HTML report. Use when checking, reviewing, or optimizing a Skill before publication.
description_en: Audit a SKILL.md against the Agent Skills specification, statically scan its Skill directory for security risks, and generate an HTML report. Use when checking, reviewing, or optimizing a Skill before publication.
description_zh: 根据 Agent Skills 规范审查 SKILL.md，静态扫描整个 Skill 目录中的安全风险并生成 HTML 报告。适用于发布前检查、审阅或优化 Skill。
license: MIT
metadata:
  author: oahcfly
  version: 1.1.0
  last-updated: '2026-08-02'
  keywords: skill audit, SKILL.md, specification, compliance, security scanning
---

# Skill Checker

Check `SKILL.md` for specification compliance and statically scan common text and source files across the Skill directory for security risks.

Use this skill when the user explicitly wants to check, audit, review, or optimize a `SKILL.md` file.

Accept either a `SKILL.md` path or a skill directory path. If the input is a file, scan its parent Skill directory. If it is a directory, resolve `SKILL.md` inside it and scan that directory.
Support absolute paths directly. Prefer absolute paths when auditing skills outside the current workspace.

Run the checker script (PowerShell):

```powershell
# Auto locate this skill directory (works even if you run from another folder)
$SkillDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $SkillDir

# Run
python .\scripts\check_skill.py <target-path> [--out <report-path>]
```

Use `--fail-on-audit` only when a strict CI-style exit code is required.

Example with absolute paths:

```powershell
$SkillDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $SkillDir
python .\scripts\check_skill.py "C:\path\to\skill\SKILL.md" --out ".\reports\skill-report.html"
```

Strict exit code example:

```powershell
python .\scripts\check_skill.py "C:\path\to\skill\SKILL.md" --out ".\reports\skill-report.html" --fail-on-audit
```

Use the generated HTML report as the primary output. Summarize the overall result, the severe issue count, and the highest-priority fixes in the final response.

## What to check

Validate the target `SKILL.md` against the Agent Skills specification:

1. Confirm YAML frontmatter exists and is parseable.
2. Confirm required fields such as `name` and `description`.
3. Validate optional specification fields when present.
4. Check that `name` matches the skill directory name when it can be inferred.
5. Review whether `description` says what the skill does and when to use it.
6. Review whether the body contains enough actionable guidance to help another agent execute the skill.

Statically scan the Skill directory without executing or importing target content:

1. Detect high-confidence prompt injection and instruction-hijacking patterns.
2. Detect exposed credentials, private keys, and contextual personal information.
3. Detect composed malicious-code patterns such as download-and-execute, credential exfiltration, persistence, defense evasion, and destructive actions.
4. Flag executable or archive artifacts that require manual review.

The scanner is bounded to common text and source files, at most 150 files, 256 KiB per file, and 5 MiB total. It skips symlinks, binaries, archives, dependency directories, build output, and caches. Static scanning cannot prove a Skill is safe.

Treat specification violations as severe issues.

Treat obvious semantic failures as severe issues too, including:

- descriptions that are too short or too vague to support triggering
- bodies that are nearly empty or do not provide actionable guidance

Treat weaker organization or thin guidance as warnings.

Return a failing result when severe issues are `2` or more. Otherwise return a passing result.

Independently aggregate security findings as `allow`, `review`, or `block`. Any `critical` or `high` finding blocks publication; two or more `medium` findings also block publication; incomplete coverage requires review. A security `block` makes the overall result fail.

## Reporting

Always point the user to the generated HTML report path, especially when the target skill lives outside the current repo.

When summarizing results:

1. State whether the result is passing or failing.
2. Mention the severe issue count, warning count, security decision, and scan coverage.
3. For security findings, report only redacted evidence, risk level, and disposition recommendation.

## References

Read `references/specification-checklist.md` when you need the exact rules and severity mapping used by this skill.
