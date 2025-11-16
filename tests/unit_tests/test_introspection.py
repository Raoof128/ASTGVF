"""
Unit tests for GraphQL Introspection Engine

Author: Security Research Team
"""

import pytest
from core.graphql_introspection import (
    GraphQLIntrospectionEngine,
    Vulnerability,
    VulnerabilitySeverity
)


class TestGraphQLIntrospectionEngine:
    """Test GraphQL Introspection Engine functionality"""

    def test_initialization(self):
        """Test engine initialization"""
        engine = GraphQLIntrospectionEngine(
            graphql_endpoint="https://api.example.com/graphql"
        )

        assert engine.endpoint == "https://api.example.com/graphql"
        assert engine.auth_headers == {}
        assert engine.timeout == 30
        assert engine.verify_ssl == True
        assert engine.schema is None
        assert len(engine.vulnerabilities) == 0

    def test_initialization_with_auth(self):
        """Test engine initialization with authentication"""
        auth_headers = {"Authorization": "Bearer test_token"}

        engine = GraphQLIntrospectionEngine(
            graphql_endpoint="https://api.example.com/graphql",
            auth_headers=auth_headers
        )

        assert engine.auth_headers == auth_headers

    def test_is_sensitive_field(self):
        """Test sensitive field detection"""
        engine = GraphQLIntrospectionEngine(
            graphql_endpoint="https://api.example.com/graphql"
        )

        # Test sensitive field names
        assert engine._is_sensitive_field("password") == True
        assert engine._is_sensitive_field("userPassword") == True
        assert engine._is_sensitive_field("api_key") == True
        assert engine._is_sensitive_field("secret_token") == True
        assert engine._is_sensitive_field("ssn") == True
        assert engine._is_sensitive_field("creditCard") == True

        # Test non-sensitive field names
        assert engine._is_sensitive_field("username") == False
        assert engine._is_sensitive_field("id") == False
        assert engine._is_sensitive_field("name") == False

    def test_extract_type_name(self):
        """Test type name extraction from GraphQL type references"""
        engine = GraphQLIntrospectionEngine(
            graphql_endpoint="https://api.example.com/graphql"
        )

        # Simple type
        type_ref = {"name": "String"}
        assert engine._extract_type_name(type_ref) == "String"

        # Non-null type
        type_ref = {"kind": "NON_NULL", "ofType": {"name": "String"}}
        assert engine._extract_type_name(type_ref) == "String!"

        # List type
        type_ref = {"kind": "LIST", "ofType": {"name": "User"}}
        assert engine._extract_type_name(type_ref) == "[User]"

    def test_calculate_risk_score(self):
        """Test risk score calculation"""
        engine = GraphQLIntrospectionEngine(
            graphql_endpoint="https://api.example.com/graphql"
        )

        # Add vulnerabilities
        engine.vulnerabilities = [
            Vulnerability(
                name="Test Critical",
                severity=VulnerabilitySeverity.CRITICAL,
                cvss_score=9.8,
                description="Test",
                evidence={}
            ),
            Vulnerability(
                name="Test High",
                severity=VulnerabilitySeverity.HIGH,
                cvss_score=7.5,
                description="Test",
                evidence={}
            ),
            Vulnerability(
                name="Test Medium",
                severity=VulnerabilitySeverity.MEDIUM,
                cvss_score=5.3,
                description="Test",
                evidence={}
            )
        ]

        # Simulate schema for risk calculation
        engine.schema = {"types": []}

        risk_score = engine._calculate_risk_score()

        assert isinstance(risk_score, float)
        assert 0.0 <= risk_score <= 10.0
        # With critical and high vulns, score should be significant
        assert risk_score > 3.0


class TestVulnerability:
    """Test Vulnerability dataclass"""

    def test_vulnerability_creation(self):
        """Test creating a vulnerability"""
        vuln = Vulnerability(
            name="SQL Injection",
            severity=VulnerabilitySeverity.CRITICAL,
            cvss_score=9.8,
            description="SQL injection vulnerability detected",
            evidence={"payload": "' OR 1=1--"},
            cwe_id="CWE-89",
            owasp_category="A03:2021 - Injection"
        )

        assert vuln.name == "SQL Injection"
        assert vuln.severity == VulnerabilitySeverity.CRITICAL
        assert vuln.cvss_score == 9.8
        assert vuln.cwe_id == "CWE-89"
        assert len(vuln.affected_fields) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
