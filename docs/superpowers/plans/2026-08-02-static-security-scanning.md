# Static Security Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a bounded, deterministic, local security scan for an entire Skill directory and integrate its evidence, risk, coverage, and publication recommendation into the CLI and HTML report.

**Architecture:** Create `scripts/security_scan.py` as an isolated scanner with immutable data models, a deterministic file collector, bounded text matching, evidence redaction, and decision aggregation. `scripts/check_skill.py` remains the specification/quality checker and composes the scanner result into `AuditResult`, CLI output, and HTML without executing target content.

**Tech Stack:** Python 3 standard library, `unittest`, existing static HTML renderer.

## Global Constraints

- Never execute, import, install, or evaluate target Skill content.
- Never use network access or model calls.
- Scan at most 150 candidate files, 256 KiB per file, and 5 MiB total.
- Skip symbolic links, binary files, archives, executables, dependencies, caches, and build output.
- Store only relative paths and redacted evidence.
- One `critical` or `high` finding yields `block`; one `medium` yields `review`; two severe findings yield `block`; incomplete coverage yields at least `review`.
- Preserve all current specification, governance, quality, and threshold behavior.
- Preserve the existing uncommitted progressive-disclosure and file-reference warning changes.

---

### Task 1: Scanner Models And Bounded File Collection

**Files:**
- Create: `scripts/security_scan.py`
- Create: `tests/test_security_scan.py`

**Interfaces:**
- Produces: `SecurityFinding`, `ScanCoverage`, `SecurityScanResult`, `collect_candidate_files(root: Path, limits: ScanLimits = DEFAULT_LIMITS) -> tuple[list[Path], ScanCoverage]`.
- `ScanLimits` contains `max_files=150`, `max_file_bytes=262144`, `max_total_bytes=5242880`.

- [ ] **Step 1: Write failing collector tests**

Add tests that build temporary Skill directories and assert:

```python
def test_collector_prioritizes_skill_and_scripts():
    # SKILL.md first, scripts/* second, root configs third, then sorted source files.

def test_collector_skips_dependencies_binary_and_symlink():
    # node_modules, NUL-containing files, unsupported extensions, and symlinks are skipped.

def test_collector_enforces_file_and_byte_budgets():
    # Coverage reports selected/skipped counts, bytes read, and incomplete=True.
```

- [ ] **Step 2: Run collector tests and verify RED**

Run: `python -m unittest tests/test_security_scan.py -v`

Expected: import failure because `scripts.security_scan` does not exist.

- [ ] **Step 3: Implement models, filters, ordering, and budgets**

Implement frozen dataclasses and constants:

```python
@dataclass(frozen=True)
class ScanLimits:
    max_files: int = 150
    max_file_bytes: int = 256 * 1024
    max_total_bytes: int = 5 * 1024 * 1024

@dataclass(frozen=True)
class ScanCoverage:
    selected_files: int
    skipped_files: int
    bytes_read: int
    incomplete: bool
    skip_reasons: dict[str, int]
```

Use explicit supported extensions and excluded directory names from the design. Resolve every candidate and require `candidate.relative_to(root.resolve())` to succeed. Reject `is_symlink()`, non-files, oversized files, and content whose initial bytes contain NUL. Sort with priority `(SKILL.md, scripts, root config, remaining)` and relative path.

- [ ] **Step 4: Run collector tests and verify GREEN**

Run: `python -m unittest tests/test_security_scan.py -v`

Expected: collector tests pass.

### Task 2: Static Detection, Redaction, And Decision Aggregation

**Files:**
- Modify: `scripts/security_scan.py`
- Modify: `tests/test_security_scan.py`

**Interfaces:**
- Produces: `scan_skill_directory(root: Path, limits: ScanLimits = DEFAULT_LIMITS) -> SecurityScanResult`.
- `SecurityFinding` fields: `rule_id`, `category`, `risk_level`, `confidence`, `relative_path`, `line`, `redacted_evidence`, `disposition`, `recommendation`.
- `SecurityScanResult` fields: `decision`, `findings`, `coverage`.

- [ ] **Step 1: Write failing detection tests**

Add independent tests for:

```python
def test_known_secret_is_blocking_and_redacted(): ...
def test_placeholder_secret_is_not_reported(): ...
def test_private_key_is_blocking_without_leaking_body(): ...
def test_prompt_override_with_secret_request_is_high_risk(): ...
def test_security_documentation_is_not_prompt_injection(): ...
def test_download_then_execute_is_high_risk(): ...
def test_isolated_subprocess_or_base64_usage_is_not_blocking(): ...
def test_one_medium_is_review_and_two_medium_are_block(): ...
def test_incomplete_coverage_is_review(): ...
```

- [ ] **Step 2: Run detection tests and verify RED**

Run: `python -m unittest tests/test_security_scan.py -v`

Expected: failures because scanning and rule matching are not implemented.

- [ ] **Step 3: Implement bounded rule matching**

Implement fixed local rules for:

- Secrets: PEM private keys, common credential prefixes, credential assignments with non-placeholder values.
- Prompt injection: directive + protected target + unsafe action combinations; downgrade explicit documentation/examples.
- Malicious code: download+execute, decode+eval/shell, credential access+network, persistence/security-disable, broad destructive commands.
- Policy: incomplete scan coverage and unsupported dangerous files.

Read files with UTF-8 and `errors="strict"`; skip invalid encodings with coverage evidence. Limit evidence to 160 characters, strip terminal control characters, and redact secrets as `<redacted:length=N>` or minimal safe prefix/suffix. Deduplicate on rule/path/line/redacted fingerprint.

- [ ] **Step 4: Implement aggregation**

Use this exact ordering:

```python
if any(risk in {"critical", "high"}): decision = "block"
elif medium_count >= 2: decision = "block"
elif medium_count == 1 or coverage.incomplete: decision = "review"
else: decision = "allow"
```

- [ ] **Step 5: Run detection tests and verify GREEN**

Run: `python -m unittest tests/test_security_scan.py -v`

Expected: all scanner tests pass and no secret literal appears in assertion output or generated evidence.

### Task 3: Audit, CLI, And HTML Integration

**Files:**
- Modify: `scripts/check_skill.py`
- Modify: `tests/test_check_skill.py`

**Interfaces:**
- Consumes: `scan_skill_directory(skill_dir) -> SecurityScanResult`.
- Extends `AuditResult` with `security_decision`, `security_findings`, and `security_coverage`.
- Existing `status`, `severe_count`, `warning_count`, and specification findings remain backward compatible.

- [ ] **Step 1: Write failing integration tests**

Add tests asserting:

```python
def test_clean_fixture_security_decision_is_allow(): ...
def test_high_security_finding_blocks_publication(): ...
def test_html_report_separates_security_findings_and_escapes_evidence(): ...
def test_cli_summary_contains_security_decision_and_coverage(): ...
```

Use temporary Skill directories; do not place live-looking secrets in committed fixtures. Construct split strings in tests and assert the combined value is absent from the report.

- [ ] **Step 2: Run integration tests and verify RED**

Run: `python -m unittest tests/test_check_skill.py -v`

Expected: failures because `AuditResult` and the report do not expose security results.

- [ ] **Step 3: Integrate scanner results**

Run the scanner after resolving and reading `SKILL.md`. On scanner exception, synthesize an incomplete `review` result without changing specification findings. Keep `status` compatible, but make a security `block` force `status="不通过"`.

Add CLI lines for security decision, selected/skipped files, bytes read, and incomplete state.

Add an HTML security panel with:

- Decision badge: `allow`, `review`, or `block`.
- Coverage summary.
- Finding cards grouped separately from specification/quality findings.
- Category, risk, relative path, line, redacted evidence, and recommendation.
- Static-analysis limitation statement.

Pass every value through `html.escape`.

- [ ] **Step 4: Run integration and regression tests and verify GREEN**

Run: `python -m unittest tests/test_check_skill.py tests/test_security_scan.py -v`

Expected: all tests pass; existing threshold tests keep their current behavior.

### Task 4: Release Metadata And Documentation

**Files:**
- Modify: `SKILL.md`
- Modify: `README.md`
- Modify: `references/specification-checklist.md`
- Modify: `docs/superpowers/specs/2026-08-02-static-security-scanning-design.md`

**Interfaces:**
- Documents the default-on scanner behavior and exact limits.

- [ ] **Step 1: Update release metadata**

Set `metadata.version` and README version to `1.1.0`; set `metadata.last-updated` to `2026-08-02`.

- [ ] **Step 2: Document scan behavior**

Document supported file types, exclusions, limits, risk decisions, evidence redaction, no-network/no-execution guarantees, and residual risk. Update the design state to implemented after verification.

- [ ] **Step 3: Verify documentation consistency**

Run searches for stale `1.0.4`, old dates, conflicting limits, and placeholder markers. Expected: fixture versions may differ intentionally; product docs consistently say `1.1.0`, 150 files, 256 KiB, and 5 MiB.

### Task 5: End-To-End Verification

**Files:**
- Verify all changed files.

- [ ] **Step 1: Run complete tests**

Run: `python -m unittest discover -s tests -p "test_*.py" -v`

Expected: all tests pass.

- [ ] **Step 2: Run self-audit**

Run: `python scripts/check_skill.py SKILL.md --out tests/_security-self-audit.html`

Expected: specification result remains valid; security decision is `allow` or documented `review`; no unredacted test secret appears.

- [ ] **Step 3: Check generated report and repository diff**

Verify the HTML contains security decision, coverage, escaped evidence, and the limitation statement. Remove the temporary report. Run `git diff --check` and confirm `.brv/` remains untouched.

- [ ] **Step 4: Final review**

Confirm every acceptance criterion in the design has a passing test or an explicit first-release limitation. Do not claim static scanning guarantees safety.
