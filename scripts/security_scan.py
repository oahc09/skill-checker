from __future__ import annotations

import os
import math
import re
from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import Path


SUPPORTED_EXTENSIONS = {
    ".md",
    ".txt",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".xml",
    ".sql",
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".sh",
    ".bash",
    ".ps1",
    ".bat",
    ".cmd",
    ".rb",
    ".php",
    ".pl",
    ".lua",
    ".java",
    ".kt",
    ".kts",
    ".swift",
    ".go",
    ".rs",
    ".c",
    ".h",
    ".cpp",
    ".hpp",
    ".cs",
}
EXCLUDED_DIRECTORIES = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "out",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    "coverage",
    "reports",
    ".cache",
}
LOCK_FILES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "uv.lock",
    "poetry.lock",
    "cargo.lock",
    "gemfile.lock",
}
ROOT_TEXT_FILES = {"dockerfile", "makefile", "gemfile", "rakefile"}
DANGEROUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".msi",
    ".scr",
    ".com",
    ".jar",
    ".zip",
    ".7z",
    ".rar",
    ".tar",
    ".gz",
}
SECRET_PATTERNS = (
    ("security.aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("security.github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,255}\b")),
    ("security.api-token", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
)
CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*[\"']([^\"']{4,})[\"']"
)
EMAIL_ASSIGNMENT = re.compile(
    r"(?i)\b(?:customer|personal|user)?_?email\b\s*[:=]\s*[\"']"
    r"([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})[\"']"
)
PHONE_ASSIGNMENT = re.compile(
    r"(?i)\b(?:customer|personal|user)?_?(?:phone|mobile)\b\s*[:=]\s*[\"']"
    r"(\+?[0-9][0-9 ()-]{8,}[0-9])[\"']"
)
CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass(frozen=True)
class ScanLimits:
    max_files: int = 150
    max_file_bytes: int = 256 * 1024
    max_total_bytes: int = 5 * 1024 * 1024


DEFAULT_LIMITS = ScanLimits()


@dataclass(frozen=True)
class ScanCoverage:
    selected_files: int
    skipped_files: int
    bytes_read: int
    incomplete: bool
    skip_reasons: dict[str, int] = field(default_factory=dict)
    policy_files: tuple[str, ...] = ()


@dataclass(frozen=True)
class SecurityFinding:
    rule_id: str
    category: str
    risk_level: str
    confidence: str
    relative_path: str
    line: int | None
    redacted_evidence: str
    disposition: str
    recommendation: str


@dataclass(frozen=True)
class SecurityScanResult:
    decision: str
    findings: tuple[SecurityFinding, ...]
    coverage: ScanCoverage


def _is_supported_file(path: Path) -> bool:
    name = path.name.lower()
    if name == ".env" or name.startswith(".env."):
        return True
    if name in ROOT_TEXT_FILES:
        return True
    return path.suffix.lower() in SUPPORTED_EXTENSIONS


def _priority(path: Path, root: Path) -> tuple[int, str]:
    relative = path.relative_to(root)
    parts = relative.parts
    normalized = relative.as_posix().lower()
    if normalized == "skill.md":
        return 0, normalized
    if parts and parts[0].lower() == "scripts":
        return 1, normalized
    if len(parts) == 1:
        return 2, normalized
    return 3, normalized


def _is_probably_binary(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return b"\x00" in handle.read(4096)
    except OSError:
        return False


def collect_candidate_files(
    root: Path,
    limits: ScanLimits = DEFAULT_LIMITS,
) -> tuple[list[Path], ScanCoverage]:
    resolved_root = root.resolve(strict=True)
    reasons: Counter[str] = Counter()
    policy_files: list[str] = []
    candidates: list[tuple[Path, int]] = []

    for directory, dir_names, file_names in os.walk(
        resolved_root,
        topdown=True,
        followlinks=False,
    ):
        current = Path(directory)
        kept_dirs: list[str] = []
        for dir_name in sorted(dir_names):
            child = current / dir_name
            if child.is_symlink():
                reasons["symlink"] += 1
            elif dir_name.lower() in EXCLUDED_DIRECTORIES:
                reasons["excluded_directory"] += 1
            else:
                kept_dirs.append(dir_name)
        dir_names[:] = kept_dirs

        for file_name in sorted(file_names):
            path = current / file_name
            if path.is_symlink():
                reasons["symlink"] += 1
                continue
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(resolved_root)
            except (OSError, ValueError):
                reasons["path_outside_root"] += 1
                continue
            if not resolved.is_file():
                reasons["not_regular_file"] += 1
                continue

            lower_name = resolved.name.lower()
            suffix = resolved.suffix.lower()
            relative = resolved.relative_to(resolved_root).as_posix()
            if suffix in DANGEROUS_EXTENSIONS:
                policy_files.append(relative)
                reasons["dangerous_file_type"] += 1
                continue
            if lower_name in LOCK_FILES or suffix == ".lock":
                reasons["lockfile"] += 1
                continue
            if lower_name.endswith((".min.js", ".min.css", ".map")):
                reasons["generated_file"] += 1
                continue
            if not _is_supported_file(resolved):
                reasons["unsupported_extension"] += 1
                continue
            try:
                size = resolved.stat().st_size
            except OSError:
                reasons["unreadable"] += 1
                continue
            if size > limits.max_file_bytes:
                reasons["file_too_large"] += 1
                continue
            if _is_probably_binary(resolved):
                reasons["binary"] += 1
                continue
            candidates.append((resolved, size))

    candidates.sort(key=lambda item: _priority(item[0], resolved_root))
    selected: list[Path] = []
    bytes_read = 0
    budget_exhausted = False
    for path, size in candidates:
        if len(selected) >= limits.max_files:
            reasons["file_limit"] += 1
            budget_exhausted = True
            continue
        if bytes_read + size > limits.max_total_bytes:
            reasons["total_byte_limit"] += 1
            budget_exhausted = True
            continue
        selected.append(path)
        bytes_read += size

    incomplete = budget_exhausted or reasons["unreadable"] > 0 or reasons["path_outside_root"] > 0
    coverage = ScanCoverage(
        selected_files=len(selected),
        skipped_files=sum(reasons.values()),
        bytes_read=bytes_read,
        incomplete=incomplete,
        skip_reasons=dict(sorted(reasons.items())),
        policy_files=tuple(sorted(policy_files)),
    )
    return selected, coverage


def _is_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    markers = (
        "example",
        "changeme",
        "placeholder",
        "redacted",
        "dummy",
        "your_",
        "your-",
        "xxxxx",
        "test-token",
    )
    return (
        lowered.startswith(("${", "{{", "<", "%"))
        or lowered.endswith("}") and "env" in lowered
        or any(marker in lowered for marker in markers)
    )


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _redact_line(line: str, sensitive: str | None = None) -> str:
    cleaned = CONTROL_CHARACTERS.sub("", line).strip()
    if sensitive:
        cleaned = cleaned.replace(sensitive, f"<redacted:length={len(sensitive)}>")
    if len(cleaned) > 160:
        cleaned = cleaned[:157] + "..."
    return cleaned


def _make_finding(
    rule_id: str,
    category: str,
    risk_level: str,
    relative_path: str,
    line: int | None,
    evidence: str,
    recommendation: str,
    confidence: str = "high",
) -> SecurityFinding:
    disposition = {
        "critical": "block",
        "high": "block",
        "medium": "review",
        "low": "allow_with_warning",
    }[risk_level]
    return SecurityFinding(
        rule_id=rule_id,
        category=category,
        risk_level=risk_level,
        confidence=confidence,
        relative_path=relative_path,
        line=line,
        redacted_evidence=evidence,
        disposition=disposition,
        recommendation=recommendation,
    )


def _looks_like_documentation(context: str) -> bool:
    lowered = context.lower()
    return any(
        marker in lowered
        for marker in (
            "example",
            "documentation",
            "unsafe prompt",
            "detect and report",
            "detect explicit",
            "prompt injection pattern",
            "do not follow",
        )
    )


def _looks_like_rule_definition(context: str) -> bool:
    lowered = context.lower()
    has_regex_literal = "r\"" in context or "r'" in context
    has_regex_api = "re.search(" in lowered or "re.compile(" in lowered
    has_pattern_assignment = bool(re.search(r"\b\w*pattern\w*\s*=", lowered))
    return has_regex_literal and (has_regex_api or has_pattern_assignment)


def _scan_text(relative_path: str, text: str) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    lines = text.splitlines() or [text]
    private_key_open = False

    for index, line in enumerate(lines, start=1):
        context = "\n".join(lines[max(0, index - 5) : index])
        lowered = context.lower()
        current_line = line.lower()

        if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", line):
            private_key_open = True
            findings.append(
                _make_finding(
                    "security.private-key",
                    "secret",
                    "critical",
                    relative_path,
                    index,
                    "<redacted:private-key>",
                    "Remove the private key and load credentials from a protected external secret store.",
                )
            )
        if private_key_open:
            if "-----END " in line and "PRIVATE KEY-----" in line:
                private_key_open = False
            continue

        for rule_id, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(line):
                secret = match.group(0)
                findings.append(
                    _make_finding(
                        rule_id,
                        "secret",
                        "high",
                        relative_path,
                        index,
                        _redact_line(line, secret),
                        "Remove the credential and reference an environment variable or secret store.",
                    )
                )

        assignment = CREDENTIAL_ASSIGNMENT.search(line)
        if assignment and not _is_placeholder(assignment.group(2)):
            value = assignment.group(2)
            risk = "high" if len(value) >= 20 and _entropy(value) >= 3.5 else "medium"
            findings.append(
                _make_finding(
                    "security.credential-assignment",
                    "secret",
                    risk,
                    relative_path,
                    index,
                    _redact_line(line, value),
                    "Remove the hard-coded credential and load it from a protected runtime source.",
                )
            )

        email_match = EMAIL_ASSIGNMENT.search(line)
        if email_match:
            findings.append(
                _make_finding(
                    "security.personal-email",
                    "pii",
                    "medium",
                    relative_path,
                    index,
                    _redact_line(line, email_match.group(1)),
                    "Remove personal data or replace it with a clearly synthetic example.",
                )
            )
        phone_match = PHONE_ASSIGNMENT.search(line)
        if phone_match:
            findings.append(
                _make_finding(
                    "security.personal-phone",
                    "pii",
                    "medium",
                    relative_path,
                    index,
                    _redact_line(line, phone_match.group(1)),
                    "Remove personal data or replace it with a clearly synthetic example.",
                )
            )

        directive = re.search(r"\b(ignore|disregard|override|forget)\b", lowered)
        protected_target = re.search(
            r"\b(previous|system|developer|instruction|rule|safeguard)s?\b",
            lowered,
        )
        unsafe_action = re.search(r"\b(reveal|expose|print|send|leak|read)\b", lowered)
        protected_data = re.search(
            r"\b(credential|api[ _-]?key|password|secret|token)s?\b",
            lowered,
        )
        if (
            directive
            and protected_target
            and unsafe_action
            and protected_data
            and not _looks_like_documentation(context)
        ):
            findings.append(
                _make_finding(
                    "security.prompt-injection",
                    "prompt-injection",
                    "high",
                    relative_path,
                    index,
                    _redact_line(line),
                    "Remove instructions that override trusted policy or request protected data.",
                )
            )

        if (
            re.search(r"\b(curl|wget)\b[^\n|]{0,240}\|\s*(?:ba)?sh\b", lowered)
            or re.search(
                r"\b(?:iwr|invoke-webrequest)\b[^\n|]{0,240}\|\s*(?:iex|invoke-expression)\b",
                lowered,
            )
        ) and not _looks_like_rule_definition(context):
            findings.append(
                _make_finding(
                    "security.download-execute",
                    "malicious-code",
                    "high",
                    relative_path,
                    index,
                    _redact_line(line),
                    "Remove download-and-execute behavior; pin and verify artifacts before any explicit execution step.",
                )
            )

        if (
            re.search(r"(?:b64decode|frombase64string|base64\s+-d)", lowered)
            and re.search(
                r"\b(eval|exec|system|popen|invoke-expression|iex)\b",
                lowered,
            )
            and not _looks_like_rule_definition(context)
        ):
            findings.append(
                _make_finding(
                    "security.decode-execute",
                    "malicious-code",
                    "high",
                    relative_path,
                    index,
                    _redact_line(line),
                    "Remove decoded dynamic execution and use transparent, reviewable code paths.",
                )
            )

        if (
            re.search(r"(?:\.aws/credentials|\.ssh/id_rsa|credential)", lowered)
            and re.search(
                r"\b(curl|requests\.post|invoke-webrequest|fetch)\b",
                lowered,
            )
            and not _looks_like_rule_definition(context)
        ):
            findings.append(
                _make_finding(
                    "security.credential-exfiltration",
                    "malicious-code",
                    "critical",
                    relative_path,
                    index,
                    _redact_line(line),
                    "Remove credential access and outbound transfer behavior.",
                )
            )

        destructive_pattern = (
            r"(?:disable(?:realtime)?monitoring|set-mppreference\s+-disablerealtimemonitoring|"
            r"schtasks\s+/create|crontab\s+-|rm\s+-rf\s+/(?:\s|$))"
        )
        if (
            re.search(destructive_pattern, current_line)
            and not _looks_like_rule_definition(context)
        ):
            findings.append(
                _make_finding(
                    "security.persistence-or-defense-evasion",
                    "malicious-code",
                    "high",
                    relative_path,
                    index,
                    _redact_line(line),
                    "Remove persistence, defense-evasion, or broad destructive behavior.",
                )
            )

    return findings


def _deduplicate_findings(findings: list[SecurityFinding]) -> tuple[SecurityFinding, ...]:
    seen: set[tuple[str, str, int | None, str]] = set()
    unique: list[SecurityFinding] = []
    for finding in findings:
        key = (
            finding.rule_id,
            finding.relative_path,
            finding.line,
            finding.redacted_evidence,
        )
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return tuple(unique)


def _decision(findings: tuple[SecurityFinding, ...], incomplete: bool) -> str:
    if any(item.risk_level in {"critical", "high"} for item in findings):
        return "block"
    medium_count = sum(item.risk_level == "medium" for item in findings)
    if medium_count >= 2:
        return "block"
    if medium_count == 1 or incomplete:
        return "review"
    return "allow"


def scan_skill_directory(
    root: Path,
    limits: ScanLimits = DEFAULT_LIMITS,
) -> SecurityScanResult:
    resolved_root = root.resolve(strict=True)
    selected, coverage = collect_candidate_files(resolved_root, limits)
    findings: list[SecurityFinding] = []
    extra_reasons: Counter[str] = Counter()

    for relative_path in coverage.policy_files:
        findings.append(
            _make_finding(
                "security.dangerous-file-type",
                "policy",
                "medium",
                relative_path,
                None,
                relative_path,
                "Remove executable or archive content from the Skill package and provide reviewable source files.",
            )
        )

    for path in selected:
        relative = path.relative_to(resolved_root).as_posix()
        try:
            before = path.stat()
            text = path.read_text(encoding="utf-8", errors="strict")
            after = path.stat()
        except UnicodeError:
            extra_reasons["unsupported_encoding"] += 1
            continue
        except OSError:
            extra_reasons["unreadable"] += 1
            continue
        if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
            extra_reasons["changed_during_scan"] += 1
            continue
        findings.extend(_scan_text(relative, text))

    if extra_reasons:
        merged_reasons = Counter(coverage.skip_reasons)
        merged_reasons.update(extra_reasons)
        coverage = replace(
            coverage,
            skipped_files=coverage.skipped_files + sum(extra_reasons.values()),
            incomplete=True,
            skip_reasons=dict(sorted(merged_reasons.items())),
        )

    if coverage.incomplete:
        findings.append(
            _make_finding(
                "scan.incomplete",
                "coverage",
                "low",
                ".",
                None,
                f"selected={coverage.selected_files}, skipped={coverage.skipped_files}",
                "Review skipped-file reasons or rerun with an explicitly approved larger scan budget.",
                confidence="high",
            )
        )

    unique = _deduplicate_findings(findings)
    return SecurityScanResult(
        decision=_decision(unique, coverage.incomplete),
        findings=unique,
        coverage=coverage,
    )
