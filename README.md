# Skill Checker

`skill-checker` validates a target `SKILL.md`, performs a bounded static security scan of its Skill directory, and generates an HTML report.

- Author: `oahcfly`
- Version: `1.1.0`
- License: `MIT`

## When to use

Use this skill when the user asks an agent to:

- check a `SKILL.md`
- audit a `SKILL.md`
- review whether a skill file follows the specification
- optimize a `SKILL.md` based on audit findings

## What it checks

Specification checks focus on `SKILL.md`:

- YAML frontmatter presence and parseability
- required fields such as `name` and `description`
- optional specification fields when present
- consistency between `name` and the skill directory name
- whether `description` explains what the skill does and when to use it
- whether the body provides enough actionable guidance

Security checks scan common text and source files across the Skill directory:

- prompt injection and instruction hijacking
- exposed credentials, private keys, and contextual personal information
- composed malicious-code patterns
- executable and archive artifacts requiring review

The local scanner never executes or imports target content, uses no network or model calls, and limits work to 150 files, 256 KiB per file, and 5 MiB total. It skips symlinks, binaries, archives, dependencies, build output, and caches.

The final result is:

- `pass` when severe findings are fewer than `2`
- `fail` when severe findings are `2` or more
- `fail` when the security decision is `block`

Security decisions are `allow`, `review`, or `block`. A `high` or `critical` finding blocks publication, two `medium` findings block publication, and incomplete coverage requires review.

## Usage

Run the checker with either a `SKILL.md` absolute path or a skill directory absolute path.
Use placeholder paths in documentation so the examples stay portable across machines and repositories.
Recommended workflow: auto-locate the `skill-checker` directory, `cd` into it, then run via relative path.

```powershell
# Auto locate this skill directory (works even if you run from another folder)
$SkillDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $SkillDir

# Run
python .\scripts\check_skill.py "C:\path\to\skill\SKILL.md" --out ".\reports\skill-report.html"
```

You can also point it at a skill directory:

```powershell
$SkillDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $SkillDir
python .\scripts\check_skill.py "C:\path\to\skill" --out ".\reports\skill-report.html"
```

For CI or strict pipelines, add:

```powershell
python .\scripts\check_skill.py "C:\path\to\skill\SKILL.md" --out ".\reports\skill-report.html" --fail-on-audit
```

## Output

The script prints:

- final status
- severe finding count
- warning count
- security decision and scan coverage
- generated HTML report path

Exit code behavior:

- Default: exit code `0` when the command itself runs successfully, even if audit result is fail.
- With `--fail-on-audit`: exit code `1` when severe findings are `2` or more or the security decision is `block`.

Generated reports under `reports/` are ignored by Git.

## Project layout

```text
skill-checker/
  SKILL.md
  README.md
  .gitignore
  agents/openai.yaml
  scripts/check_skill.py
  scripts/security_scan.py
  references/specification-checklist.md
  tests/
```

## Tests

```powershell
python -m unittest discover -s .\tests -p "test_*.py"
```

## Notes

- This skill intentionally keeps its current `metadata` rule strict.
- Static scanning is bounded and cannot prove that a Skill is safe.
- HTML reports are meant for review and sharing; they are not committed by default.
