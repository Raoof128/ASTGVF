"""
Unit tests for Remediation Engine

Author: Security Research Team
"""

import pytest
from core.remediation_engine import (
    RemediationEngine,
    RemediationPlan,
    RemediationPriority,
    RemediationStep
)


class TestRemediationEngine:
    """Test RemediationEngine functionality"""

    def test_initialization(self):
        """Test engine initialization"""
        engine = RemediationEngine()
        assert engine is not None

    def test_generate_remediation_plan_sql_injection(self):
        """Test remediation plan generation for SQL injection"""
        engine = RemediationEngine()

        vuln = {
            'name': 'SQL Injection',
            'severity': 'CRITICAL',
            'cvss_score': 9.8,
            'description': 'SQL injection detected'
        }

        plan = engine.generate_remediation_plan(vuln)

        assert plan is not None
        assert isinstance(plan, RemediationPlan)
        assert plan.vulnerability_name == 'SQL Injection'
        assert plan.cwe_id == 'CWE-89'
        assert plan.cvss_score == 9.8
        assert plan.priority == RemediationPriority.IMMEDIATE
        assert len(plan.remediation_steps) > 0
        assert len(plan.secure_code_examples) > 0

    def test_generate_remediation_plan_idor(self):
        """Test remediation plan generation for IDOR"""
        engine = RemediationEngine()

        vuln = {
            'name': 'Insecure Direct Object Reference (IDOR)',
            'severity': 'HIGH',
            'cvss_score': 7.5
        }

        plan = engine.generate_remediation_plan(vuln)

        assert plan is not None
        assert plan.cwe_id == 'CWE-639'
        assert plan.priority in [RemediationPriority.URGENT, RemediationPriority.HIGH]

    def test_generate_remediation_plan_unknown(self):
        """Test remediation plan for unknown vulnerability"""
        engine = RemediationEngine()

        vuln = {
            'name': 'Unknown Vulnerability',
            'severity': 'MEDIUM',
            'cvss_score': 5.0
        }

        plan = engine.generate_remediation_plan(vuln)

        assert plan is None

    def test_calculate_priority_critical(self):
        """Test priority calculation for critical CVSS"""
        engine = RemediationEngine()

        priority = engine._calculate_priority(9.5, 1.0)

        assert priority == RemediationPriority.IMMEDIATE

    def test_calculate_priority_high(self):
        """Test priority calculation for high CVSS"""
        engine = RemediationEngine()

        priority = engine._calculate_priority(7.5, 1.0)

        assert priority == RemediationPriority.URGENT

    def test_calculate_priority_medium(self):
        """Test priority calculation for medium CVSS"""
        engine = RemediationEngine()

        priority = engine._calculate_priority(5.0, 1.0)

        assert priority == RemediationPriority.HIGH

    def test_export_remediation_plan_json(self):
        """Test exporting plan as JSON"""
        engine = RemediationEngine()

        vuln = {
            'name': 'SQL Injection',
            'severity': 'CRITICAL',
            'cvss_score': 9.8
        }

        plan = engine.generate_remediation_plan(vuln)
        json_output = engine.export_remediation_plan(plan, format='json')

        assert isinstance(json_output, str)
        assert 'SQL Injection' in json_output
        assert 'CWE-89' in json_output

    def test_export_remediation_plan_markdown(self):
        """Test exporting plan as Markdown"""
        engine = RemediationEngine()

        vuln = {
            'name': 'SQL Injection',
            'severity': 'CRITICAL',
            'cvss_score': 9.8
        }

        plan = engine.generate_remediation_plan(vuln)
        md_output = engine.export_remediation_plan(plan, format='markdown')

        assert isinstance(md_output, str)
        assert '# Remediation Plan' in md_output
        assert 'SQL Injection' in md_output
        assert '##' in md_output  # Section headers

    def test_remediation_steps_structure(self):
        """Test structure of remediation steps"""
        engine = RemediationEngine()

        vuln = {
            'name': 'SQL Injection',
            'severity': 'CRITICAL',
            'cvss_score': 9.8
        }

        plan = engine.generate_remediation_plan(vuln)

        for step in plan.remediation_steps:
            assert isinstance(step, RemediationStep)
            assert step.step_number > 0
            assert len(step.title) > 0
            assert len(step.description) > 0


class TestRemediationPriority:
    """Test RemediationPriority enum"""

    def test_priority_values(self):
        """Test priority enum values"""
        assert RemediationPriority.IMMEDIATE.value == "Immediate (0-24 hours)"
        assert RemediationPriority.URGENT.value == "Urgent (1-7 days)"
        assert RemediationPriority.HIGH.value == "High (1-2 weeks)"
        assert RemediationPriority.MEDIUM.value == "Medium (2-4 weeks)"
        assert RemediationPriority.LOW.value == "Low (1-3 months)"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
