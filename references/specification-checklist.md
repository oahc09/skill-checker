# Skill Checker Specification Checklist

Use this checklist to keep the checker aligned with the Agent Skills specification while staying consistent with this skill's audit policy.

## Hard checks

- Require YAML frontmatter delimited by `---` at the top of the file.
- Require `name`, `description`, `license`, and `metadata`.
- Accept only these top-level frontmatter fields:
  - `name`
  - `description`
  - `description_en`
  - `description_zh`
  - `license`
  - `compatibility`
  - `metadata`
  - `allowed-tools`
- Require `name` to use lowercase letters, digits, and hyphens only.
- Require `name` to match the parent directory name when the directory is known.
- Require `description` to be non-empty and at most 1024 characters.
- Require `metadata` to be a simple string-to-string mapping.
- Require `metadata.author`, `metadata.version`, `metadata.last-updated`, and `metadata.keywords` to be present and non-empty strings.
- Require `metadata.last-updated` to use a valid `YYYY-MM-DD` date.
- Store `metadata.keywords` as a comma-separated string of skill keywords.

## Semantic checks

- Mark as severe when `description` is too short to express capability and trigger context.
- Mark as severe when `description` does not clearly say when the skill should be used.
- Mark as warning when recommended bilingual fields `description_en` or `description_zh` are missing or empty.
- Mark as severe when the body is empty or too thin to guide execution.
- Mark as warning when the body exists but has weak structure or thin execution guidance.
- Mark as warning when `SKILL.md` reaches 500 lines or its body is estimated at 5000 tokens or more.
- Mark as warning when file references are not relative to the Skill root or are nested more than one directory deep.

## Final decision

- Return `不通过` when severe findings are `2` or more.
- Return `通过` when severe findings are fewer than `2`.
- If the target path cannot be resolved or parsed, emit blocking severe findings so the final result becomes `不通过`.

## Static security scan

- Scan the entire Skill directory when given either a directory or its `SKILL.md` file.
- Treat target content only as data; never execute, import, install, evaluate, or send it to a model or external service.
- Scan common text and source files only, with limits of 150 files, 256 KiB per file, and 5 MiB total.
- Skip symlinks, binaries, archives, lock files, dependency directories, build output, and caches.
- Detect high-confidence prompt injection, secrets and contextual PII, composed malicious-code patterns, and dangerous packaged artifacts.
- Redact sensitive values and escape all evidence before displaying it.
- Return security decision `block` for any `critical` or `high` finding, or for two or more `medium` findings.
- Return security decision `review` for one `medium` finding or incomplete coverage; otherwise return `allow`.
- Make the overall audit fail when the security decision is `block`.
- Report only evidence, risk level, and disposition recommendation for each security finding.

## Invocation guidance

- Accept both absolute `SKILL.md` paths and absolute skill directory paths.
- Keep examples in documentation absolute-path friendly so the skill remains easy to use across repositories.
