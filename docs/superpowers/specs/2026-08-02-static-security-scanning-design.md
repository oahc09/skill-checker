# Skill Checker Static Security Scanning Design

## Status

- Target release: `1.1.0`
- Design date: `2026-08-02`
- State: approved direction, awaiting written-spec review

## Objective

Add a deterministic, local, static security scan for the entire uploaded Skill directory. The scanner must detect high-confidence prompt injection, sensitive information, malicious code patterns, and policy violations without executing Skill code, using network access, or sending file content to a model.

The scanner produces evidence, risk level, and a disposition recommendation only. It does not publish, delete, quarantine, contact third parties, or notify regulators.

## Security Invariants

1. Untrusted Skill content is treated only as data and is never executed, imported, installed, or evaluated.
2. Every scanned path must resolve inside the selected Skill directory.
3. Symbolic links, binary files, archives, executables, dependency trees, caches, and build outputs are not parsed in the first release.
4. Scan work is bounded by file count, per-file bytes, total bytes, and deterministic file selection.
5. Sensitive evidence is redacted before it enters findings, logs, JSON, terminal output, or HTML.
6. User-controlled paths and evidence are escaped before HTML rendering.
7. A scan that cannot cover its selected scope reports `scan.incomplete` and recommends review; it must not silently claim safety.

## Non-Goals

- Executing the Skill in a sandbox.
- Installing dependencies or invoking package scripts.
- Antivirus, binary reverse engineering, archive extraction, or macro analysis.
- Model-based classification or token-consuming content review.
- Guaranteeing that a Skill is safe when no finding is produced.
- Automatically notifying regulators or any external party.
- User-defined rules or remote rule updates in the first release.

## Recommended Architecture

Use a separate security-scanning module rather than adding more responsibilities to the existing checker.

### Components

`FileCollector`

- Resolves the target Skill root.
- Rejects paths that escape the root after canonicalization.
- Skips symbolic links and non-regular files.
- Filters excluded directories, extensions, generated files, lock files, and probable binary files.
- Orders candidates deterministically by priority and relative path.
- Enforces the scan budget.

`SecurityRule`

- Defines rule ID, category, description, match strategy, risk level, confidence requirements, evidence redaction, and recommendation.
- Uses bounded regular expressions and small deterministic helpers.
- Does not permit arbitrary executable callbacks loaded from the target Skill.

`SecurityScanner`

- Reads selected files incrementally.
- Applies rules by line or small bounded context window.
- Deduplicates repeated matches without hiding distinct files or locations.
- Continues collecting bounded evidence after a blocking match so the report remains useful.

`SecurityFinding`

- Contains `rule_id`, `category`, `risk_level`, `confidence`, `relative_path`, `line`, `redacted_evidence`, and `disposition`.
- Never contains a full secret, password, private key, identity number, or unrestricted source excerpt.

`SecurityDecision`

- Aggregates findings and coverage into `allow`, `review`, or `block`.
- Keeps the existing specification audit result available for backward compatibility.

## File Selection

### Hard Budget

- Maximum candidate files read: `150`
- Maximum bytes per file: `256 KiB`
- Maximum bytes read across the Skill: `5 MiB`
- Selection is deterministic so repeated scans of unchanged input produce the same coverage.

### Priority

1. Root `SKILL.md`.
2. Files under `scripts/`.
3. Root configuration and environment-style files.
4. Remaining supported source and text files ordered by relative path.

### Supported Files

The first release scans common text and source formats:

- Documentation and data: `.md`, `.txt`, `.yaml`, `.yml`, `.json`, `.toml`, `.ini`, `.cfg`, `.xml`, `.sql`.
- Environment/config names: `.env`, `.env.*`, and common credential/config names when they are regular text files.
- Scripts: `.py`, `.js`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.jsx`, `.sh`, `.bash`, `.ps1`, `.bat`, `.cmd`, `.rb`, `.php`, `.pl`, `.lua`.
- Compiled-language source: `.java`, `.kt`, `.kts`, `.swift`, `.go`, `.rs`, `.c`, `.h`, `.cpp`, `.hpp`, `.cs`.

### Exclusions

- Directories: `.git`, `node_modules`, `vendor`, `dist`, `build`, `out`, `target`, `.venv`, `venv`, `__pycache__`, `coverage`, `reports`, `.cache`.
- Archives, executables, shared libraries, images, audio, video, fonts, generated maps, minified bundles, and lock files.
- Files containing NUL bytes or failing a conservative text check.
- Symbolic links and filesystem objects that are not regular files.

When candidates exceed the budget, the collector records skipped counts and reasons. Budget exhaustion creates `scan.incomplete` with disposition `review`.

## Detection Rules

### Prompt Injection

Detect explicit instructions that attempt to override trusted instructions, obtain higher privilege, expose secrets, disable safeguards, or cause an agent to execute untrusted content.

Single generic words such as "ignore" or documentation discussing prompt injection are not high risk. High confidence requires a combination of directive language, a protected target such as system instructions or credentials, and an unsafe requested action. Examples and test fixtures may be downgraded through path and context-aware allowlisting, but are not globally ignored.

### Sensitive Information

Detect:

- Known high-confidence API key and cloud credential prefixes.
- PEM private-key blocks.
- Password, token, or secret assignments with non-placeholder values.
- High-entropy credential-like values only when paired with credential context.
- High-confidence personal identity and payment patterns with checksum validation where practical.

Placeholder values such as `example`, `changeme`, `${ENV_VAR}`, and documented redacted forms are allowlisted. Email addresses and phone-like strings should default to low or medium risk unless stronger context establishes sensitive personal data.

### Malicious Code Patterns

Prefer composed behavior patterns over isolated API names. High-risk examples include:

- Download followed by execution.
- Decode or decrypt followed by `eval`, dynamic import, or shell execution.
- Credential-file access combined with network exfiltration.
- Persistence installation or security-tool disabling.
- Destructive filesystem commands aimed at broad or protected locations.

Ordinary uses of subprocesses, HTTP clients, Base64, filesystem APIs, or package managers are not independently blocking.

### Security Policy

Detect unsupported dangerous file types, suspicious hidden executable content, path-containment violations, and incomplete coverage. These checks describe packaging and coverage risk even when no content signature matches.

## Risk And Disposition

| Risk | Meaning | Default disposition |
|---|---|---|
| `critical` | Clear credential exposure or highly credible malicious execution chain | `block` |
| `high` | High-confidence prompt injection, secret, or dangerous behavior | `block` |
| `medium` | Credible risk requiring context or multiple weaker signals | `review`; contributes one severe finding |
| `low` | Weak signal, hygiene issue, or informational policy concern | `allow_with_warning` |

Aggregation rules:

- One `critical` or `high` finding immediately makes the security decision `block`.
- Medium findings participate in the existing severe threshold; two or more severe findings produce `block`.
- One medium finding produces `review` unless another audit rule already blocks the Skill.
- Low findings do not block.
- `scan.incomplete` produces at least `review`.

The HTML report must clearly separate specification findings from security findings and show the final publication recommendation.

## Evidence Handling

- Store only repository-relative paths.
- Record a one-based line number when available.
- Limit evidence to a short bounded excerpt.
- HTML-escape every path, message, and excerpt.
- Replace credential bodies with a stable redacted form showing only minimal prefix/suffix characters when safe.
- Never render complete passwords, tokens, private keys, identity numbers, or payment numbers.
- Deduplicate repeated findings by rule, path, line, and normalized evidence fingerprint.

## Failure Handling

- Unreadable file: record coverage warning and continue.
- Unsupported encoding: skip and record the reason.
- File changes during scan: record incomplete coverage for that file.
- Budget exhausted: stop selecting new files and return `review`.
- Rule error: isolate the failed rule, record scanner error, and return at least `review`.
- Scanner-level unexpected exception: fail closed to `review`, not `allow`; preserve the specification-audit result.

## CLI And Report Behavior

Security scanning is enabled by default in `1.1.0` for both directory and `SKILL.md` inputs. A file input scans its parent Skill directory.

The command output and HTML report add:

- Security decision: `allow`, `review`, or `block`.
- Files selected, files skipped, bytes read, and whether the budget was exhausted.
- Finding counts by risk and category.
- Redacted evidence and remediation guidance.
- A statement that static scanning reduces risk but does not prove safety.

No target content is sent over the network and no model tokens are consumed.

## Testing Strategy

### Unit Tests

- File extension and directory filters.
- Path-containment and symbolic-link rejection.
- Deterministic priority ordering.
- File-count, per-file, and total-byte limits.
- Binary and encoding detection.
- Every rule with positive, negative, placeholder, documentation, and boundary cases.
- Date-independent and locale-independent result behavior.
- Evidence truncation, redaction, and HTML escaping.
- Risk aggregation and publication recommendations.

### Adversarial Tests

- Catastrophic-backtracking inputs for every regular expression.
- Very long lines and files without newlines.
- NUL bytes, mixed encodings, malformed Unicode, and terminal escape sequences.
- Symlink escape and path traversal attempts.
- Secret-like test strings that must never appear unredacted in reports.
- Benign security documentation containing attack terminology.
- Common build scripts using subprocesses or network clients legitimately.

### Integration Tests

- Small clean Skill returns `allow`.
- One high-risk finding returns `block`.
- One medium finding returns `review`.
- Two severe findings return `block`.
- Budget exhaustion returns `review` with coverage evidence.
- Existing specification-only fixtures retain their intended semantics after security scanning is integrated.

## Rollout

1. Introduce scanner data models, file collection, and coverage reporting.
2. Add secrets and evidence-redaction rules first because they have the clearest validation criteria.
3. Add composed malicious-code and prompt-injection rules with benign counterexamples.
4. Integrate the security decision into CLI and HTML reporting.
5. Run the scanner against repository fixtures and a curated benign corpus before enabling default blocking.

Rollback is straightforward: keep specification validation independent and gate only the security decision integration. Rule changes remain local, versioned, and testable.

## Residual Risk

The scanner will not reliably detect novel obfuscation, payloads hidden in binaries or archives, runtime-only behavior, supply-chain compromise in external dependencies, or attacks outside the selected file budget. `allow` means no configured high-confidence rule matched within reported coverage; it is not a guarantee that the Skill is safe.

## Acceptance Criteria

- Scanning never executes or imports target content.
- Default scan stays within 150 files, 256 KiB per file, and 5 MiB total.
- No target content is sent to a model or external service.
- A high or critical finding produces `block` from a single finding.
- Incomplete coverage produces at least `review`.
- Reports contain only escaped, redacted evidence.
- Existing audit behavior remains available and tests pass.
- The new scanner has deterministic fixtures for clean, review, block, incomplete, and false-positive cases.
