from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "check_skill.py"
SPEC = importlib.util.spec_from_file_location("check_skill", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


FIXTURES = ROOT / "tests" / "fixtures"


class SkillCheckerTests(unittest.TestCase):
    def audit_fixture(self, name: str):
        return MODULE.audit_target(str(FIXTURES / name))

    def test_minimal_pass_fixture_passes(self):
        result = self.audit_fixture("minimal-pass")
        self.assertEqual(result.status, "通过")
        self.assertEqual(result.severe_count, 0)

    def test_strong_pass_fixture_avoids_false_positive(self):
        result = self.audit_fixture("strong-pass")
        self.assertEqual(result.status, "通过")
        self.assertEqual(result.severe_count, 0)

    def test_absolute_skill_file_path_is_supported(self):
        result = MODULE.audit_target(
            str((FIXTURES / "strong-pass" / "SKILL.md").resolve())
        )
        self.assertEqual(result.status, "通过")
        self.assertEqual(result.resolved_from, "file")

    def test_absolute_skill_directory_path_is_supported(self):
        result = MODULE.audit_target(str((FIXTURES / "strong-pass").resolve()))
        self.assertEqual(result.status, "通过")
        self.assertEqual(result.resolved_from, "directory")

    def test_missing_name_is_severe(self):
        result = self.audit_fixture("spec-fail-missing-name")
        self.assertEqual(result.status, "通过")
        self.assertTrue(any(item.rule_id == "spec.required-name" for item in result.findings))

    def test_unknown_field_and_generic_description_fail_threshold(self):
        result = self.audit_fixture("threshold-two-severe")
        self.assertEqual(result.status, "不通过")
        self.assertGreaterEqual(result.severe_count, 2)

    def test_single_severe_issue_can_still_pass(self):
        result = self.audit_fixture("threshold-one-severe")
        self.assertEqual(result.status, "通过")
        self.assertEqual(result.severe_count, 1)

    def test_missing_skill_file_is_blocking_failure(self):
        result = self.audit_fixture("missing-skill-file")
        self.assertEqual(result.status, "不通过")
        self.assertGreaterEqual(result.severe_count, 2)
        self.assertIsNone(result.skill_path)

    def test_invalid_yaml_blocks_audit(self):
        result = self.audit_fixture("spec-fail-invalid-yaml")
        self.assertEqual(result.status, "不通过")
        self.assertTrue(any(item.rule_id == "spec.frontmatter-invalid" for item in result.findings))

    def test_html_report_contains_summary_and_findings(self):
        result = self.audit_fixture("semantic-fail-empty-body")
        report_path = ROOT / "tests" / "_report-test.html"
        try:
            MODULE.write_report(result, str(report_path))
            rendered = report_path.read_text(encoding="utf-8")
        finally:
            if report_path.exists():
                report_path.unlink()
        self.assertIn("Skill Checker 报告", rendered)
        self.assertIn("发现的问题", rendered)
        self.assertIn("semantics.empty-body", rendered)
        self.assertIn("不通过", rendered)


if __name__ == "__main__":
    unittest.main()
